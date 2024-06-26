import os
import time
import hmac
import hashlib
import uuid
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
from flask import Flask, request, redirect, session, jsonify, url_for
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

@app.route('/install', methods=['GET'])
def install():
    state = str(uuid.uuid4())
    session['state'] = state
    app.logger.debug(f"Issued state: {state}, session: {session}")

    client_id = os.getenv("SLACK_CLIENT_ID")
    redirect_uri = url_for('oauth_callback', _external=True, _scheme='https')
    app.logger.debug(f"Redirect URI: {redirect_uri}")
    scope = "channels:history,channels:read,chat:write,reactions:read,im:history,im:read,mpim:read,mpim:history,groups:history,groups:read"
    oauth_url = f"https://slack.com/oauth/v2/authorize?state={state}&client_id={client_id}&scope={scope}&redirect_uri={redirect_uri}"

    app.logger.debug(f"Generated OAuth URL: {oauth_url}")
    return redirect(oauth_url)

@app.route('/oauth/callback', methods=['GET'])
def oauth_callback():
    code = request.args.get('code')
    state = request.args.get('state')
    app.logger.debug(f"Received state: {state} for validation")

    if not state:
        app.logger.error("State is missing from the callback URL.")
        return "State is missing from the callback URL", 400

    stored_state = session.pop('state', None)
    app.logger.debug(f"Stored state: {stored_state}")

    if state != stored_state:
        app.logger.error(f"Invalid state: {state} does not match stored state: {stored_state}")
        return "Invalid state", 400

    client_id = os.getenv("SLACK_CLIENT_ID")
    client_secret = os.getenv("SLACK_CLIENT_SECRET")
    redirect_uri = url_for('oauth_callback', _external=True, _scheme='https')
    app.logger.debug(f"OAuth callback redirect URI: {redirect_uri}")

    try:
        response = client.oauth_v2_access(
            client_id=client_id,
            client_secret=client_secret,
            code=code,
            redirect_uri=redirect_uri
        )
        app.logger.debug(f"OAuth response: {response}")
        
        if response.get('ok'):
            access_token = response['access_token']
            # Store access_token securely, if needed
            app.logger.debug("OAuth authentication successful.")
        else:
            app.logger.error(f"OAuth authentication failed: {response}")

    except SlackApiError as e:
        app.logger.error(f"Error during OAuth access: {e.response['error']}")
        return "OAuth access error", 400

    return "Installation successful", 200

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 3000))
    app.run(debug=False, host='0.0.0.0', port=port)
