import os
import time
import hmac
import hashlib
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
from flask import Flask, request, jsonify, redirect
from dotenv import load_dotenv
import json
import uuid

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)
client = WebClient(token=os.getenv("SLACK_USER_TOKEN"))
signing_secret = os.getenv("SLACK_SIGNING_SECRET")

# State store for OAuth process
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
    oauth_url = (
        f"https://slack.com/oauth/v2/authorize?"
        f"state={state}&client_id={os.getenv('CLIENT_ID')}&scope=channels:history,channels:read,chat:write,reactions:read,im:history,im:read,mpim:history,mpim:read,groups:history,groups:read"
        f"&redirect_uri={os.getenv('REDIRECT_URI')}"
    )
    return redirect(oauth_url)

@app.route('/oauth/callback', methods=['GET'])
def oauth_callback():
    state = request.args.get('state')
    code = request.args.get('code')

    if state not in state_store or time.time() - state_store[state] > 600:
        return 'Invalid or expired state', 400

    del state_store[state]

    response = client.oauth_v2_access(
        client_id=os.getenv('CLIENT_ID'),
        client_secret=os.getenv('CLIENT_SECRET'),
        redirect_uri=os.getenv('REDIRECT_URI'),
        code=code
    )

    if not response['ok']:
        return f"Error: {response['error']}", 400

    os.environ["SLACK_USER_TOKEN"] = response['access_token']

    return 'Installation successful!', 200

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

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 3000))
    app.run(debug=False, host='0.0.0.0', port=port)
