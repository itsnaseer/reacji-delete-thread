import os
import time
import uuid
import hmac
import hashlib
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
    scopes = os.getenv('SLACK_SCOPES', 'channels:history,channels:read,chat:write,reactions:read,im:history,im:read,mpim:read,mpim:history,groups:history,groups:read')
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
    code = request.args.get('code')

    if not state:
        app.logger.error("State is missing from the callback URL")
        return "State is missing from the callback URL", 400

    if state not in state_store:
        app.logger.error(f"Invalid or expired state: {state}, store: {state_store}")
        return "Invalid or expired state", 400

    app.logger.debug(f"Received state: {state} for validation")
    app.logger.debug(f"State store: {state_store}")
    
    try:
        response = client.oauth_v2_access(
            client_id=os.getenv('SLACK_CLIENT_ID'),
            client_secret=os.getenv('SLACK_CLIENT_SECRET'),
            code=code,
            redirect_uri=os.getenv('REDIRECT_URI')
        )
        access_token = response['access_token']
        team_id = response['team']['id']
        user_id = response['authed_user']['id']
        # Store token logic here...
        app.logger.debug(f"OAuth response: {response}")
        return "Installation successful", 200
    except SlackApiError as e:
        app.logger.error(f"Error during OAuth: {e.response['error']}")
        return f"Error during OAuth: {e.response['error']}", 500
    finally:
        # Clean up the state store
        if state in state_store:
            del state_store[state]

@app.route('/slack/events', methods=['POST'])
def slack_events():
    if not verify_slack_request(request):
        return 'Request verification failed', 400

    data = request.json
    app.logger.debug(f"Received event: {data}")
    if 'event' in data:
        event = data['event']
        if event.get('type') == 'reaction_added' and event.get('reaction') == 'delete-thread':
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
                            app.logger.error(f"Error deleting reply: {e.response['error']}")
                
                # Finally, delete the original message
                client.chat_delete(channel=channel, ts=ts)
            except SlackApiError as e:
                app.logger.error(f"Error fetching replies or deleting message: {e.response['error']}")
            except Exception as e:
                app.logger.error(f"Unexpected error: {str(e)}")
    return '', 200

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 3000))
    app.run(debug=True, host='0.0.0.0', port=port)
