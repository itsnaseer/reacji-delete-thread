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

# Initialize Bolt app

def authorize(enterprise_id, team_id, user_id):
    conn = engine.connect()
    logger.debug(f"Authorize called with enterprise_id: {enterprise_id}, team_id: {team_id}, user_id: {user_id}")
    try:
        stmt = select(tokens_table.c.access_token).where(tokens_table.c.team_id == team_id)
        result = conn.execute(stmt)
        token = result.scalar()
    except Exception as e:
        logger.error(f"Error querying token in authorize function: {e}")
        conn.close()
        return None

    conn.close()

    if not token:
        logger.error(f"Token not found for team_id: {team_id} in authorize function")
        return None

    logger.debug(f"Token found for team_id: {team_id} in authorize function: {token}")
    return AuthorizeResult(
        enterprise_id=enterprise_id,
        team_id=team_id,
        bot_token=token
    )

# Assign the authorize function to Bolt app
bolt_app = App(
    signing_secret=os.getenv("SLACK_SIGNING_SECRET"),
    authorize=authorize
)

# Initialize Flask app
app = Flask(__name__)
handler = SlackRequestHandler(bolt_app)
logger = logging.getLogger(__name__)

# Database configuration
DATABASE_URL = os.getenv("DATABASE_URL")
engine = create_engine(DATABASE_URL)
metadata = MetaData()

tokens_table = Table('tokens', metadata,
    Column('team_id', String, nullable=False),
    Column('user_id', String, primary_key=True, nullable=False),
    Column('access_token', String, nullable=False),
    Column('created_at', String, nullable=False),
    Column('updated_at', String, nullable=False)
)

metadata.create_all(engine)

store = {}

# Slack client initialization
client = WebClient(token=os.getenv("SLACK_CLIENT_ID"))  # Bot token used for OAuth flow

# Event handler for app_home_opened
@bolt_app.event("app_home_opened")
def update_home_tab(client, event, logger):
    
    try:
        # Use the bot token for publishing the home tab
        #bot_token = os.getenv("SLACK_BOT_TOKEN")
        client.views_publish(
        #    token=bot_token,
            user_id=event["user"],
            view={
                "type": "home",
                "blocks": [
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": "Is this working? Cam I just ignore the error? \nUse this app to delete messages (+ threaded replies) and generate the user token (`xoxp-1234567890`) for your current user. The user token is used to delete the messages and impersonate users in SBN workflows. Note: This app replaces <https://salesforce.enterprise.slack.com/docs/T01G0063H29/F0741QXLV0D|User Token Generator> (canvas will be transitioned)"
                        }
                    },
                    {
                        "type": "divider"
                    },
                    {
                        "type": "header",
                        "text": {
                            "type": "plain_text",
                            "text": "Get Started"
                        }
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": "This app uses a combination of bot and user token scopes to get permissions to manage conversations (DM, Channel, MPDM). The app uses the current user’s ID to generate the token. After generating the token it will send a message to the App’s Messages tab. "
                        }
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": "\t1.\t *Set up*. Add `:delete-thread:` as a reaction in your workspace. I like <https://drive.google.com/file/d/1JyOH1AAB1lAa3rHdyDXGrc_kOQuCsems/view?usp=drive_link|this version>, but you can use your own. "
                        }
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": "\t2.\t *Test*.Find a message anywhere in your workspace and apply the `:delete-thread:` reaction. If there are threaded messages, all replies will delete. "
                        }
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": "\t3.\t (optional) *Copy your token*. If you are using Smockbot Next, go to the your DM with yourself <@{user_id}>, copy the token, and follow the instructions for Using with SBN. "
                        }
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": "\t4.\t *Delete the token message*. Find your direct message <@{user_id}> with your token in the DM with yourself and delete the message with the user token.\n_Bonus points_. Use :delete-thread: to delete the DM with the token info.  "
                        }
                    },
                    {
                        "type": "divider"
                    },
                    {
                        "type": "context",
                        "elements": [
                            {
                                "type": "mrkdwn",
                                "text": "Are you looking for more comprehensive guidance? Check out the <https://salesforce.enterprise.slack.com/docs/T01G0063H29/F07BHJ16UAE|App Canvas in Giant Speck>"
                            }
                        ]
                    }
                ]
            }
        )
        logger.info(f"Home tab published")

    except Exception as e:
        logger.error(f"Error publishing home tab: {e}")

#testing events
@bolt_app.message("hello")
def message_hello(message, say):
    # say() sends a message to the channel where the event was triggered
    logger.debug(f"Event received {message}")
    say(f"Hey there <@{message['user']}>!")


# Event handler for Slack events and app config
@app.route("/slack/events", methods=["POST"])
def slack_events():
    if "challenge" in request.json:
        return jsonify({"challenge": request.json["challenge"]})
    return handler.handle(request)

# Event handler for reaction_added
@bolt_app.event("reaction_added")
def handle_reaction_added(client, say, event):
    reaction = event["reaction"] 
    logger.debug("Received a reaction event")
    if reaction == "delete-thread":
        event_item = event.get("item")
        message_channel = event_item.get("channel")
        message_ts = event_item.get("ts")
        logger.info(f"Message details: {event} ~*~*~*~ Item: {event_item} Channel: {message_channel} ~*~*~*~ Time stamp: {message_ts}")
        
        #checking for replies
        try:
            #fetch replies to the message
            replies = client.conversations_replies(
                channel=message_channel, 
                ts=message_ts
            )
            #store each message ID in an array
            messages_to_delete = [message["ts"] for message in replies["messages"]]

            #sort replies from newest to oldest
            messages_to_delete.sort(reverse=True)

            #go through the replies one by one
            for ts in messages_to_delete:
                try:
                    #delete each message in the replies array
                    result = client.chat_delete(
                        channel=message_channel,
                        ts=ts
                    )
                    logger.info(result)
                except SlackApiError as e:
                    logger.error(f"Error eleting message {e}")
        except SlackApiError as e:
            logger.error(f"Error fetching replies {e}")
        
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
        if not access_token:
            access_token = response_data.get('access_token')  # Fallback to bot access token
        created_at = str(time.time())
        updated_at = created_at

        if not access_token:
            app.logger.error("Access token not found in OAuth response")
            return "OAuth flow failed", 500

        with engine.connect() as conn:
            app.logger.info(f"Inserting/updating token for team {team_id}, user {user_id}, access_token: {access_token}")
            trans = conn.begin()
            try:
                # Try to insert the new token
                conn.execute(tokens_table.insert().values(
                    team_id=team_id,
                    user_id=user_id,
                    access_token=access_token,
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