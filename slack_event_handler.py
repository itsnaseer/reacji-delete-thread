import os
import time
import hmac
import hashlib
import uuid  # Importing uuid module
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
from flask import Flask, request, jsonify, redirect
from dotenv import load_dotenv
from sqlalchemy import create_engine, Table, Column, String, MetaData, select

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)
signing_secret = os.getenv("SLACK_SIGNING_SECRET")

# Database setup
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

def get_token_for_team(team_id):
    with engine.connect() as connection:
        query = select([tokens_table]).where(tokens_table.c.team_id == team_id)
        result = connection.execute(query).fetchone()
        if result:
            return result['access_token']
        return None

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

@app.route('/slack/events', methods=['POST'])
def slack_events():
    if not verify_slack_request(request):
        return 'Request verification failed', 400

    data = request.json
    if 'event' in data:
        event = data['event']
        if event.get('type') == 'reaction_added' and event.get('reaction') == 'delete-thread':
            team_id = data['team_id']
            token = get_token_for_team(team_id)
            if not token:
                print(f"Token not found for team {team_id}")
                return 'Token not found', 403

            client = WebClient(token=token)
            channel = event['item']['channel']
            ts = event['item']['ts']
            try:
                # Fetch and delete all threaded replies
                response = client.conversations_replies(channel=channel, ts=ts)
                for message in response['messages']:
                    # Only delete replies, not the initial message
                    if message['ts'] != ts:
                        try:
                            client.chat_delete(channel=channel, ts=message['ts'])
                        except SlackApiError as e:
                            print(f"Error deleting reply: {e.response['error']}")

                # Finally, delete the original message
                client.chat_delete(channel=channel, ts=ts)
            except SlackApiError as e:
                print(f"Error fetching replies or deleting message: {e.response['error']}")
            except Exception as e:
                print(f"Unexpected error: {str(e)}")
    return '', 200

@app.route('/install', methods=['GET'])
def install():
    state = str(uuid.uuid4())
    state_store[state] = time.time()
    oauth_url = f"https://slack.com/oauth/v2/authorize?client_id={os.getenv('SLACK_CLIENT_ID')}&scope={os.getenv('SLACK_SCOPES')}&state={state}&redirect_uri={os.getenv('REDIRECT_URI')}"
    return redirect(oauth_url)

@app.route('/oauth/callback', methods=['GET'])
def oauth_callback():
    state = request.args.get('state')
    code = request.args.get('code')
    if not state or not code:
        print("State or code missing from the callback URL")
        return 'State or code missing from the callback URL', 400

    print(f"Received callback with state: {state} and code: {code}")

    if state not in state_store or time.time() - state_store[state] > 60 * 10:
        print(f"Invalid or expired state: {state}")
        return 'Invalid or expired state', 400

    del state_store[state]

    client = WebClient()
    try:
        response = client.oauth_v2_access(
            client_id=os.getenv("SLACK_CLIENT_ID"),
            client_secret=os.getenv("SLACK_CLIENT_SECRET"),
            code=code,
            redirect_uri=os.getenv("REDIRECT_URI")
        )
        if not response['ok']:
            print(f"OAuth failed: {response}")
            return 'OAuth failed', 400

        team_id = response['team']['id']
        user_id = response['authed_user']['id']
        access_token = response['access_token']

        with engine.connect() as connection:
            query = tokens_table.insert().values(
                team_id=team_id,
                user_id=user_id,
                access_token=access_token,
                created_at=time.strftime('%Y-%m-%d %H:%M:%S'),
                updated_at=time.strftime('%Y-%m-%d %H:%M:%S')
            )
            connection.execute(query)

        return 'Installation successful', 200
    except SlackApiError as e:
        print(f"Error during OAuth: {e.response['error']}")
        return f"Error during OAuth: {e.response['error']}", 400
    except Exception as e:
        print(f"Unexpected error: {str(e)}")
        return f"Unexpected error: {str(e)}", 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 3000))
    app.run(debug=True, host='0.0.0.0', port=port)
