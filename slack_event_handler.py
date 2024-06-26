import os
import time
import hmac
import hashlib
import uuid
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
from flask import Flask, request, redirect, session, jsonify
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "supersecretkey")
client = WebClient(token=os.getenv("SLACK_USER_TOKEN"))  # Use user token for elevated permissions
signing_secret = os.getenv("SLACK_SIGNING_SECRET")

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
            app.logger.debug(f'Processing reaction in channel: {channel} at timestamp: {ts}')
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
                            app.logger.debug(f'Error details: {e.response}')

                # Finally, delete the original message
                client.chat_delete(channel=channel, ts=ts)
                app.logger.debug(f'Deleted original message: {ts}')
            except SlackApiError as e:
                app.logger.error(f'Error fetching replies or deleting message: {e.response["error"]}')
                app.logger.debug(f'Error details: {e.response}')
            except Exception as e:
                app.logger.error(f'Unexpected error: {str(e)}')
    return '', 200

@app.route('/install', methods=['GET'])
def install():
    state = str(uuid.uuid4())
    session['oauth_state'] = state
    app.logger.debug(f'Storing state in session: {state}')
    oauth_url = f"https://slack.com/oauth/v2/authorize?state={state}&client_id={os.getenv('SLACK_CLIENT_ID')}&scope=channels:history,channels:read,chat:write,reactions:read,im:history,im:read,mpim:history,mpim:read,groups:history,groups:read,admin&user_scope=&redirect_uri={os.getenv('SLACK_REDIRECT_URI')}"
    app.logger.debug(f'Generated OAuth URL: {oauth_url}')
    return redirect(oauth_url)

@app.route('/oauth/callback', methods=['GET'])
def oauth_callback():
    state = request.args.get('state')
    code = request.args.get('code')

    app.logger.debug(f'Received state: {state} and code: {code} for validation')

    if not state:
        app.logger.error(f'State is missing from the callback URL. Code: {code}')
        return 'Invalid state: missing', 400

    saved_state = session.pop('oauth_state', None)
    if saved_state is None:
        app.logger.error(f'State is missing from the session. State received: {state}')
    app.logger.debug(f'Retrieved state from session: {saved_state}')

    if state != saved_state:
        app.logger.error(f'Invalid state: {state}. Expected state: {saved_state}')
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
