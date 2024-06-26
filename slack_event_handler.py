import os
import time
import hmac
import hashlib
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
from flask import Flask, request, redirect
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)
client = WebClient(token=os.getenv("SLACK_BOT_TOKEN"))
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

@app.route('/slack/events', methods=['POST'])
def slack_events():
    if not verify_slack_request(request):
        app.logger.error('Request verification failed')
        return 'Request verification failed', 400

    data = request.json
    app.logger.debug(f'Received event: {data}')
    if 'event' in data:
        event = data['event']
        if event.get('type') == 'reaction_added' and event.get('reaction') == 'delete-thread':
            channel = event['item']['channel']
            ts = event['item']['ts']
            try:
                # Fetch and delete all threaded replies
                response = client.conversations_replies(channel=channel, ts=ts)
                app.logger.debug(f'Fetched replies: {response["messages"]}')
                for message in response['messages']:
                    # Only delete replies, not the initial message
                    if message['ts'] != ts:
                        try:
                            client.chat_delete(channel=channel, ts=message['ts'])
                            app.logger.debug(f'Deleted reply: {message["ts"]}')
                        except SlackApiError as e:
                            app.logger.error(f'Error deleting reply: {e.response["error"]}')

                # Finally, delete the original message
                client.chat_delete(channel=channel, ts=ts)
                app.logger.debug(f'Deleted original message: {ts}')
            except SlackApiError as e:
                app.logger.error(f'Error fetching replies or deleting message: {e.response["error"]}')
            except Exception as e:
                app.logger.error(f'Unexpected error: {str(e)}')
    return '', 200

@app.route('/install', methods=['GET'])
def install():
    state = str(uuid.uuid4())
    state_store[state] = time.time()
    oauth_url = f"https://slack.com/oauth/v2/authorize?state={state}&client_id={os.getenv('SLACK_CLIENT_ID')}&scope=channels:history,channels:read,chat:write,reactions:read,im:history,im:read,mpim:history,mpim:read,groups:history,groups:read&user_scope=&redirect_uri={os.getenv('SLACK_REDIRECT_URI')}"
    app.logger.debug(f'Generated OAuth URL: {oauth_url}')
    return redirect(oauth_url)

@app.route('/oauth/callback', methods=['GET'])
def oauth_callback():
    state = request.args.get('state')
    code = request.args.get('code')

    if not state:
        app.logger.error('State is missing from the callback URL')
        return 'Invalid state: missing', 400

    app.logger.debug(f'Received state: {state} for validation')
    if state not in state_store:
        app.logger.error(f'Invalid state: {state}')
        return 'Invalid state', 400

    try:
        response = client.oauth_v2_access(
            client_id=os.getenv("SLACK_CLIENT_ID"),
            client_secret=os.getenv("SLACK_CLIENT_SECRET"),
            code=code,
            redirect_uri=os.getenv("SLACK_REDIRECT_URI")
        )
        app.logger.debug(f'OAuth response: {response}')
    except SlackApiError as e:
        app.logger.error(f'OAuth error: {e.response["error"]}')
        return f'OAuth error: {e.response["error"]}', 400

    access_token = response.get("access_token")
    app.logger.debug('Stored user token in environment variable')

    return 'App successfully installed', 200

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 3000))
    app.run(debug=False, host='0.0.0.0', port=port)
