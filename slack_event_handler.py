import os
import time
import hmac
import hashlib
import requests
import uuid
import logging
from flask import Flask, request, jsonify, redirect
from slack_bolt import App
from slack_bolt.authorization import AuthorizeResult
from slack_bolt.adapter.flask import SlackRequestHandler
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
from dotenv import load_dotenv
from requests.auth import HTTPBasicAuth
from sqlalchemy import create_engine, Table, Column, String, MetaData, select, update, insert, literal
from sqlalchemy.exc import SQLAlchemyError

# Load environment variables from .env file
load_dotenv()
logging.basicConfig(level=logging.DEBUG)

# Initialize Flask app
app = Flask(__name__)
logger = logging.getLogger(__name__)

# Database configuration
DATABASE_URL = os.getenv("DATABASE_URL")
engine = create_engine(DATABASE_URL)
metadata = MetaData()

tokens_table = Table('tokens', metadata,
    Column('team_id', String, nullable=False),
    Column('user_id', String, primary_key=True, nullable=False),
    Column('access_token', String, nullable=False),
    Column('bot_token', String, nullable=True),  # Add bot_token column if not already present
    Column('created_at', String, nullable=False),
    Column('updated_at', String, nullable=False)
)

metadata.create_all(engine)

store = {}

# Slack client initialization
client = WebClient()  # Initialize without token

def authorize(enterprise_id, team_id, user_id):
    conn = engine.connect()
    logger.debug(f"Authorize called with enterprise_id: {enterprise_id}, team_id: {team_id}, user_id: {user_id}")
    try:
        stmt = select(tokens_table.c.access_token, tokens_table.c.bot_token).where(tokens_table.c.team_id == team_id)
        result = conn.execute(stmt).fetchone()
        if result:
            access_token, bot_token = result
        else:
            access_token = bot_token = None
    except Exception as e:
        logger.error(f"Error querying token in authorize function: {e}")
        conn.close()
        return None

    conn.close()

    if not bot_token:
        logger.error(f"Bot token not found for team_id: {team_id} in authorize function")
        return None

    logger.debug(f"Tokens found for team_id: {team_id} in authorize function: access_token: {access_token}, bot_token: {bot_token}")
    return AuthorizeResult(
        bot_token=bot_token,
        user_token=access_token
    )

# Initialize Bolt app with authorize function
bolt_app = App(
    signing_secret=os.getenv("SLACK_SIGNING_SECRET"),
    authorize=authorize
)
handler = SlackRequestHandler(bolt_app)

# Event handler for app_home_opened
@bolt_app.event("app_home_opened")
def update_home_tab(client, event, logger):
    user_id = event["user"]
    try:
        # Use the bot token for publishing the home tab
        client.views_publish(
            user_id=user_id,
            view={
                "type": "home",
                "blocks": [
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": "Is this working? Can I just ignore the error? \nUse this app to delete messages (+ threaded replies) and generate the user token (`xoxp-1234567890`) for your current user. The user token is used to delete the messages and impersonate users in SBN workflows. Note: This app replaces <https://salesforce.enterprise.slack.com/docs/T01G0063H29/F0741QXLV0D|User Token Generator> (canvas will be transitioned)"
                        }
                    }
                ]
            }
        )
        logger.info(f"Home tab published")

    except Exception as e:
        logger.error(f"Error publishing home tab: {e}")

# Event handler for Slack events and app config
@app.route("/slack/events", methods=["POST"])
def slack_events():
    if "challenge" in request.json:
        return jsonify({"challenge": request.json["challenge"]})
    return handler.handle(request)

# Event handler for reaction_added
@bolt_app.event("reaction_added")
def handle_reaction_added(client, event, context, logger):
    reaction = event["reaction"] 
    logger.debug(f"~*~*~*~ Received a reaction event: {reaction}")

    if reaction == "delete-thread":
        event_item = event.get("item")
        message_channel = event_item.get("channel")
        message_ts = event_item.get("ts")
        user_token = context['user_token']
        logger.info(f"~*~*~*~ Channel: {message_channel} ~*~*~*~ Time stamp: {message_ts}")

        # Fetch replies to the message
        try:
            replies = client.conversations_replies(
                channel=message_channel, 
                ts=message_ts,
                token=user_token
            )
            # Store each message ID in an array
            messages_to_delete = [message["ts"] for message in replies["messages"]]

            # Sort replies from newest to oldest
            messages_to_delete.sort(reverse=True)

            # Delete each message in the replies array
            for ts in messages_to_delete:
                try:
                    result = client.chat_delete(
                        channel=message_channel,
                        ts=ts,
                        token=user_token
                    )
                    logger.info(result)
                except SlackApiError as e:
                    logger.error(f"Error deleting message: {e}")
        except SlackApiError as e:
            logger.error(f"Error fetching replies: {e}")
        
# Verify Slack request
def verify_slack_request(request):
    timestamp = request.headers.get('X-Slack-Request-Timestamp')
    if abs(time.time() - int(timestamp)) > 60 * 5:
        return False

    sig_basestring = f"v0:{timestamp}:{request.get_data(as_text=True)}"
    my_signature = 'v0=' + hmac.new(
        os.getenv("SLACK_SIGNING_SECRET").encode(),
        sig_basestring.encode(),
        hashlib.sha256
    ).hexdigest()

    slack_signature = request.headers.get('X-Slack-Signature')
    return hmac.compare_digest(my_signature, slack_signature)


# INSTALL script-- stage scopes and compile URL
@app.route('/install', methods=['GET'])
def install():
    state = str(uuid.uuid4())
    store[state] = time.time()  # store the state with a timestamp
    scopes = "channels:history,channels:read,chat:write,reactions:read,chat:write.public,emoji:read,users:read,chat:write.customize,im:history,mpim:history,groups:history,im:read,mpim:read,groups:read,users:read.email"
    user_scopes = "admin,channels:history,channels:read,reactions:read,users:read,users:read.email,chat:write,mpim:history,groups:history,im:history"
    oauth_url = f"https://slack.com/oauth/v2/authorize?client_id={os.getenv('SLACK_CLIENT_ID')}&scope={scopes}&user_scope={user_scopes}&state={state}&redirect_uri={os.getenv('REDIRECT_URI')}"
    return redirect(oauth_url)

# OAUTH Callback - check for and update or store tokens
@app.route('/oauth/callback', methods=['GET'])
def oauth_callback():
    state = request.args.get('state')
    code = request.args.get('code')

    if not state or state not in store:
        app.logger.error("State is missing or invalid from the callback URL")
        return "State is missing or invalid from the callback URL", 400

    # Basic authentication for client_id and client_secret
    auth = HTTPBasicAuth(os.getenv("SLACK_CLIENT_ID"), os.getenv("SLACK_CLIENT_SECRET"))

    token_url = "https://slack.com/api/oauth.v2.access"
    data = {
        'code': code,
        'redirect_uri': os.getenv("REDIRECT_URI")
    }

    response = requests.post(token_url, auth=auth, data=data)
    response_data = response.json()

    app.logger.info(f"OAuth response: {response_data}")

    if response_data['ok']:
        team_id = response_data['team']['id']
        user_id = response_data['authed_user']['id']
        access_token = response_data['authed_user'].get('access_token')  # Use user access token if available
        bot_token = response_data.get('access_token')  # Fallback to bot access token

        created_at = str(time.time())
        updated_at = created_at

        app.logger.debug(f"Team ID: {team_id}, User ID: {user_id}, Access Token: {access_token}, Bot Token: {bot_token}")

        if not access_token:
            app.logger.error("Access token not found in OAuth response")
            return "OAuth flow failed", 500

        with engine.connect() as conn:
            app.logger.info(f"Inserting/updating token for team {team_id}, user {user_id}, access_token: {access_token}, bot_token: {bot_token}")
            trans = conn.begin()
            try:
                # Try to insert the new token
                conn.execute(tokens_table.insert().values(
                    team_id=team_id,
                    user_id=user_id,
                    access_token=access_token,
                    bot_token=bot_token,
                    created_at=created_at,
                    updated_at=updated_at
                ))
                trans.commit()
                app.logger.info(f"Successfully inserted token for team {team_id}, user {user_id}")
            except Exception as insert_error:
                app.logger.info(f"Error during insert: {insert_error}")
                if 'duplicate key value violates unique constraint' in str(insert_error):
                    trans.rollback()
                    # If a unique constraint violation occurs, update the existing token
                    app.logger.info(f"Token for user {user_id} already exists, updating instead.")
                    trans = conn.begin()
                    try:
                        conn.execute(tokens_table.update().values(
                            team_id=team_id,
                            access_token=access_token,
                            bot_token=bot_token,
                            updated_at=updated_at
                        ).where(tokens_table.c.user_id == user_id))
                        trans.commit()
                        app.logger.info(f"Successfully updated token for team {team_id}, user {user_id}")
                    except Exception as update_error:
                        trans.rollback()
                        app.logger.error(f"Error updating token: {update_error}")
                        return "OAuth flow failed", 500
                else:
                    trans.rollback()
                    app.logger.error(f"Error inserting token: {insert_error}")
                    return "OAuth flow failed", 500

        # Send a message to the user's personal DM with the user token, user's name, and user ID
        try:
            user_info_response = client.users_info(user=user_id, token=access_token)
            if user_info_response["ok"]:
                user_name = user_info_response["user"]["name"]
                message_text = f"User Token: {access_token}\nUser Name: {user_name}\nUser ID: {user_id}"

                client.chat_postMessage(
                    channel=user_id,
                    text=message_text,
                    token=access_token
                )
                app.logger.info(f"Successfully sent DM to user {user_id}")
            else:
                app.logger.error(f"Error retrieving user info: {user_info_response['error']}")
        except SlackApiError as e:
            app.logger.error(f"Slack API Error: {e.response['error']}")

        return "OAuth flow completed", 200
    else:
        app.logger.error(f"OAuth response error: {response_data}")
        return "OAuth flow failed", 400


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 3000))
    app.run(debug=True, host='0.0.0.0', port=port)