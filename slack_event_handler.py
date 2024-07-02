import os
import time
import hmac
import hashlib
import uuid
import json
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
from flask import Flask, request, jsonify, redirect, url_for
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)
client = WebClient(token=os.getenv("SLACK_USER_TOKEN"))
signing_secret = os.getenv("SLACK_SIGNING_SECRET")
state_store = {}

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
    state_store[state] = time.time()
    scopes = os.getenv('SLACK_SCOPES')
    if not scopes:
        scopes = 'channels:history,channels:read,chat:write,reactions:read,im:history,im:read,mpim:read,mpim:history,groups:history,groups:read'
    slack_url = (
        "https://slack.com/oauth/v2/authorize"
        f"?client_id={os.getenv('SLACK_CLIENT_ID')}"
        f"&scope={scopes}"
        f"&state={state}"
        f"&redirect_uri={os.getenv('REDIRECT_URI')}"
    )
    app.logger.debug(f"Issued state: {state}, store: {state_store}")
    app.logger.debug(f"Generated OAuth URL: {slack_url}")
    return redirect(slack_url)

@app.route('/oauth/callback', methods=['GET'])
def oauth_callback():
    state = request.args.get('state')
    if not state:
        app.logger.error('State is missing from the callback URL')
        return 'State is missing from the callback URL', 400
    if state not in state_store:
        app.logger.error(f'Invalid state: {state}')
        return 'Invalid state', 400

    state_store.pop(state)
    code = request.args.get('code')
    if not code:
        app.logger.error('Code is missing from the callback URL')
        return 'Code is missing from the callback URL', 400

    try:
        response = client.oauth_v2_access(
            client_id=os.getenv("SLACK_CLIENT_ID"),
            client_secret=os.getenv("SLACK_CLIENT_SECRET"),
            code=code,
            redirect_uri=os.getenv("REDIRECT_URI")
        )
        team_id = response['team']['id']
        access_token = response['access_token']
        # Store the access token in your database
        app.logger.debug(f'OAuth response: {response}')
        return 'OAuth callback successful', 200
    except SlackApiError as e:
        app.logger.error(f'Error during OAuth: {e.response["error"]}')
        return f'Error during OAuth: {e.response["error"]}', 500

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
            try:
                response = client.conversations_replies(channel=channel, ts=ts)
                for message in response['messages']:
                    if message['ts'] != ts:
                        try:
                            client.chat_delete(channel=channel, ts=message['ts'])
                        except SlackApiError as e:
                            print(f"Error deleting reply: {e.response['error']}")

                client.chat_delete(channel=channel, ts=ts)
            except SlackApiError as e:
                app.logger.error(f'Error fetching replies or deleting message: {e.response["error"]}')
            except Exception as e:
                app.logger.error(f'Unexpected error: {str(e)}')
    return '', 200

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 3000))
    app.run(debug=False, host='0.0.0.0', port=port)
