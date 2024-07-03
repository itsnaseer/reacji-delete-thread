import os
import time
import hmac
import hashlib
import requests
import uuid
from flask import Flask, request, jsonify, redirect
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
from dotenv import load_dotenv
from sqlalchemy import create_engine, Table, Column, String, MetaData, select, update, insert, literal
from sqlalchemy.exc import SQLAlchemyError

# Load environment variables from .env file
load_dotenv()

# Initialize Flask app
app = Flask(__name__)

# Slack client initialization
client = WebClient(token=os.getenv("SLACK_CLIENT_ID"))  # Bot token used for OAuth flow
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

@app.route('/install', methods=['GET'])
def install():
    state = str(uuid.uuid4())
    store[state] = time.time()  # store the state with a timestamp
    scopes = "channels:history,channels:read,chat:write,reactions:read,chat:write.public,emoji:read,users:read,chat:write.customize,im:history,mpim:history,groups:history,im:read,mpim:read,groups:read,users:read.email"
    user_scopes = "users:read,users:read.email"
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

    response = client.oauth_v2_access(
        client_id=os.getenv("SLACK_CLIENT_ID"),
        client_secret=os.getenv("SLACK_CLIENT_SECRET"),
        code=code,
        redirect_uri=os.getenv("REDIRECT_URI")
    )

    app.logger.info(f"OAuth response: {response}")

    if response['ok']:
        team_id = response['team']['id']
        user_id = response['authed_user']['id']
        access_token = response['authed_user'].get('access_token')  # Use user access token if available
        if not access_token:
            access_token = response.get('access_token')  # Fallback to bot access token
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

        return "OAuth flow completed", 200
    else:
        app.logger.error(f"OAuth response error: {response}")
        return "OAuth flow failed", 400

# Event handler for Slack events
@app.route("/slack/events", methods=["POST"])
def slack_events():
    event_data = request.json
    app.logger.debug(f"Event Data: {event_data}")

    if "event" in event_data and event_data["event"]["type"] == "reaction_added":
        event = event_data["event"]
        if event["reaction"] == "delete-thread":
            team_id = event_data["team_id"]
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

            conn.close()

            if not token:
                app.logger.error(f"Token not found for team_id: {team_id}")
                return jsonify({"error": "Token not found"}), 400

            app.logger.debug(f"Using token: {token} for team_id: {team_id}")

            # Form the API call to delete the message
            delete_url = "https://slack.com/api/chat.delete"
            headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
            payload = {"channel": channel_id, "ts": message_ts}

            response = requests.post(delete_url, headers=headers, json=payload)
            response_data = response.json()

            if not response_data["ok"]:
                app.logger.error(f"Error deleting message: {response_data['error']}")
                return jsonify({"error": response_data["error"]}), 400

            app.logger.debug(f"Message deleted: {response_data}")

            return jsonify({"status": "Message deleted"}), 200

    return jsonify({"status": "Event received"}), 200

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 3000))
    app.run(debug=True, host='0.0.0.0', port=port)
