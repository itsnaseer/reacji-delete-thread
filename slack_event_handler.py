import os
import time
import hmac
import hashlib
import uuid
from flask import Flask, request, jsonify, redirect
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
from dotenv import load_dotenv
from sqlalchemy import create_engine, Table, Column, String, MetaData, select


# Load environment variables from .env file
load_dotenv()

# Initialize Flask app
app = Flask(__name__)

# Slack client initialization
client = WebClient(token=os.getenv("SLACK_USER_TOKEN"))
signing_secret = os.getenv("SLACK_SIGNING_SECRET")

# Database configuration
DATABASE_URL = os.getenv("DATABASE_URL")
engine = create_engine(DATABASE_URL)
metadata = MetaData()

tokens_table = Table('tokens', metadata,
    Column('team_id', String),
    Column('user_id', String, primary_key=True),
    Column('access_token', String),
    Column('created_at', String),
    Column('updated_at', String)
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
    oauth_url = f"https://slack.com/oauth/v2/authorize?client_id={os.getenv('SLACK_CLIENT_ID')}&scope={os.getenv('SLACK_SCOPES')}&state={state}&redirect_uri={os.getenv('REDIRECT_URI')}"
    return redirect(oauth_url)

@app.route('/oauth/callback', methods=['GET'])
def oauth_callback():
    state = request.args.get('state')
    code = request.args.get('code')

    if not state or state not in store:
        app.logger.error("State is missing or invalid from the callback URL")
        return "State is missing or invalid from the callback URL", 400

    try:
        response = client.oauth_v2_access(
            client_id=os.getenv("SLACK_CLIENT_ID"),
            client_secret=os.getenv("SLACK_CLIENT_SECRET"),
            code=code,
            redirect_uri=os.getenv("REDIRECT_URI")
        )

        if response['ok']:
            team_id = response['team']['id']
            user_id = response['authed_user']['id']
            access_token = response['access_token']
            app.logger.info(f"Received token for team {team_id}, user {user_id}, access_token: {access_token}")

            with engine.connect() as conn:
                # Check if the user_id already exists
                result = conn.execute(select([tokens_table.c.user_id]).where(tokens_table.c.user_id == user_id)).fetchone()
                if result:
                    # Update existing entry
                    conn.execute(tokens_table.update().where(tokens_table.c.user_id == user_id).values(
                        team_id=team_id,
                        access_token=access_token,
                        updated_at=str(time.time())
                    ))
                    app.logger.info(f"Token updated for user {user_id}")
                else:
                    # Insert new entry
                    conn.execute(tokens_table.insert().values(
                        team_id=team_id,
                        user_id=user_id,
                        access_token=access_token,
                        created_at=str(time.time()),
                        updated_at=str(time.time())
                    ))
                    app.logger.info(f"Token stored for user {user_id}")

            app.logger.info("OAuth flow completed successfully")
            return "OAuth flow completed", 200
        else:
            app.logger.error("OAuth flow failed with response: %s", response)
            return "OAuth flow failed", 400

    except Exception as e:
        app.logger.error(f"Error during OAuth callback: {e}")
        return "Failed to complete OAuth flow", 500

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
            result = conn.execute(select(tokens_table.c.access_token).where(tokens_table.c.team_id == team_id))
            token = result.scalar()
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
    app.run(debug=False, host='0.0.0.0', port=port)
