import os
import time
import hmac
import hashlib
import requests
import uuid
from slack_bolt import App
from slack_bolt.adapter.socket_mode import SocketModeHandler
from dotenv import load_dotenv
from sqlalchemy import create_engine, Table, Column, String, MetaData, select, update, insert, literal
from sqlalchemy.exc import SQLAlchemyError
from requests.auth import HTTPBasicAuth

# Load environment variables from .env file
load_dotenv()

# Initialize Bolt app
app = App(token=os.getenv("SLACK_BOT_TOKEN"))

# Signing secret for request verification
signing_secret = os.getenv("SLACK_SIGNING_SECRET")

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

# Function to verify Slack requests
def verify_slack_request(request):
    timestamp = request.headers.get('X-Slack-Request-Timestamp')
    if abs(time.time() - int(timestamp)) > 60 * 5:
        return False

    sig_basestring = f"v0:{timestamp}:{request.get_data(as_text=True)}"
    my_signature = 'v0=' + hmac.new(
        signing_secret.encode(),
        sig_basestring.encode(),
        hashlib.sha256
    ).hexdigest()

    slack_signature = request.headers.get('X-Slack-Signature')
    return hmac.compare_digest(my_signature, slack_signature)

# Function to handle OAuth callback
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

        # Send a message to the user's DM with the access token
        try:
            user_client = WebClient(token=access_token)
            user_info = user_client.users_info(user=user_id)
            user_name = user_info['user']['name']
            user_client.chat_postMessage(
                channel=user_id,
                text=f"OAuth flow completed. Here is your access token: {access_token}\nUser Name: {user_name}\nUser ID: {user_id}"
            )
        except SlackApiError as e:
            app.logger.error(f"Error sending DM: {e.response['error']}")

        return "OAuth flow completed", 200
    else:
        app.logger.error(f"OAuth response error: {response_data}")
        return "OAuth flow failed", 400

# Event handler for Slack events
@app.event("reaction_added")
def handle_reaction_added(event, say):
    app.logger.debug(f"Reaction event: {event}")

<<<<<<< HEAD
    if event["reaction"] == "delete-thread":
        team_id = event["item"]["team"]
        channel_id = event["item"]["channel"]
        message_ts = event["item"]["ts"]
=======
    # Verify that the event is coming from the correct workspace
    if "team_id" not in event_data:
        app.logger.error("team_id missing in event data")
        return jsonify({"error": "team_id missing"}), 400
    
    team_id = event_data["team_id"]
    app.logger.debug(f"Received event from team_id: {team_id}")

    if "event" in event_data and event_data["event"]["type"] == "reaction_added":
        event = event_data["event"]
        app.logger.debug(f"Reaction event: {event}")

        if event["reaction"] == "delete-thread":
            item = event["item"]
            channel_id = item["channel"]
            message_ts = item["ts"]

            # Retrieve the token from the database
            conn = engine.connect()
            app.logger.debug(f"Querying token for team_id: {team_id}")
            try:
                stmt = select(tokens_table.c.access_token).where(tokens_table.c.team_id == team_id)
                result = conn.execute(stmt)
                token = result.scalar()
            except Exception as e:
                app.logger.error(f"Error querying token: {e}")
                conn.close()
                return jsonify({"error": "Error querying token"}), 500
>>>>>>> parent of 05b702d (Update slack_event_handler.py)

        # Retrieve the token from the database
        conn = engine.connect()
        app.logger.debug(f"Querying token for team_id: {team_id}")
        try:
            stmt = select(tokens_table.c.access_token).where(tokens_table.c.team_id == team_id)
            result = conn.execute(stmt)
            token = result.scalar()
        except Exception as e:
            app.logger.error(f"Error querying token: {e}")
            conn.close()
            return

        conn.close()

        if not token:
            app.logger.error(f"Token not found for team_id: {team_id}")
            return

        app.logger.debug(f"Using token: {token} for team_id: {team_id}")

        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

        # Get threaded messages
        replies_url = "https://slack.com/api/conversations.replies"
        replies_payload = {"channel": channel_id, "ts": message_ts}
        replies_response = requests.get(replies_url, headers=headers, params=replies_payload)
        replies_data = replies_response.json()

        if not replies_data["ok"]:
            app.logger.error(f"Error retrieving threaded messages: {replies_data['error']}, channel: {channel_id}, message_id: {message_ts}")
            return

        # Delete threaded messages from newest to oldest
        for reply in sorted(replies_data["messages"], key=lambda x: x["ts"], reverse=True):
            delete_url = "https://slack.com/api/chat.delete"
            delete_payload = {"channel": channel_id, "ts": reply["ts"]}
            delete_response = requests.post(delete_url, headers=headers, json=delete_payload)
            delete_response_data = delete_response.json()

            if not delete_response_data["ok"]:
                app.logger.error(f"Error deleting message: {delete_response_data['error']}, channel: {channel_id}, message_id: {message_ts}")
                return

            app.logger.debug(f"Deleted message: {delete_response_data}")

if __name__ == "__main__":
    handler = SocketModeHandler(app, os.getenv("SLACK_APP_TOKEN"))
    handler.start()