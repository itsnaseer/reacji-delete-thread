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
    Column('team_id', String, primary_key=True),
    Column('user_id', String),
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
        with engine.connect() as conn:
            conn.execute(tokens_table.insert().values(
                team_id=team_id,
                user_id=user_id,
                access_token=access_token,
                created_at=str(time.time()),
                updated_at=str(time.time())
            ))
        return "OAuth flow completed", 200
    else:
        return "OAuth flow failed", 400

@app.route('/slack/events', methods=['POST'])
def slack_events():
    if not verify_slack_request(request):
        return 'Request verification failed', 400

    data = request.json
    if 'event' in data:
        event = data['event']
        if event.get('type') == 'reaction_added' and event.get('reaction') == 'delete-thread':
            channel = event['item']['channel']
            ts = event['item']['ts']
            team_id = data['team_id']

            with engine.connect() as conn:
                result = conn.execute(select([tokens_table.c.access_token]).where(tokens_table.c.team_id == team_id))
                row = result.fetchone()
                if row:
                    token = row['access_token']
                    local_client = WebClient(token=token)
                    try:
                        response = local_client.conversations_replies(channel=channel, ts=ts)
                        for message in response['messages']:
                            if message['ts'] != ts:
                                try:
                                    local_client.chat_delete(channel=channel, ts=message['ts'])
                                except SlackApiError as e:
                                    app.logger.error(f"Error deleting reply: {e.response['error']}")
                        local_client.chat_delete(channel=channel, ts=ts)
                    except SlackApiError as e:
                        app.logger.error(f"Error fetching replies or deleting message: {e.response['error']}")
                    except Exception as e:
                        app.logger.error(f"Unexpected error: {str(e)}")
                else:
                    app.logger.error(f"Token not found for team {team_id}")

    return '', 200

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 3000))
    app.run(debug=False, host='0.0.0.0', port=port)
