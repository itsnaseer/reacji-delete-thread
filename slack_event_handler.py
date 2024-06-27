import os
import time
import hmac
import hashlib
import json
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
from flask import Flask, request, jsonify, redirect, url_for, session
from dotenv import load_dotenv
from logging.config import dictConfig

# Configure logging
dictConfig({
    'version': 1,
    'formatters': {'default': {
        'format': '[%(asctime)s] %(levelname)s in %(module)s: %(message)s',
    }},
    'handlers': {'wsgi': {
        'class': 'logging.StreamHandler',
        'stream': 'ext://flask.logging.wsgi_errors_stream',
        'formatter': 'default'
    }},
    'root': {
        'level': 'DEBUG',
        'handlers': ['wsgi']
    }
})

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY")
client = WebClient(token=os.getenv("SLACK_USER_TOKEN"))
signing_secret = os.getenv("SLACK_SIGNING_SECRET")
tokens = {}

def save_tokens(tokens):
    with open('tokens.json', 'w') as file:
        json.dump(tokens, file)

def load_tokens():
    global tokens
    try:
        with open('tokens.json', 'r') as file:
            tokens = json.load(file)
    except FileNotFoundError:
        tokens = {}

load_tokens()

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
            channel = event['item']['channel']
            ts = event['item']['ts']
            team_id = data['team_id']
            token = tokens.get(team_id)

            if not token:
                app.logger.error(f"Token not found for team {team_id}")
                return 'Token not found', 400

            client = WebClient(token=token)
            
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
    state = os.urandom(24).hex()
    session['state'] = state
    app.logger.debug(f"Issued state: {state}")

    client_id = os.getenv("SLACK_CLIENT_ID")
    scope = "reactions:read,channels:history,channels:read,chat:write,im:history,im:read,mpim:read,mpim:history,groups:history,groups:read"
    redirect_uri = url_for('oauth_callback', _external=True, _scheme='https')

    url = f"https://slack.com/oauth/v2/authorize?state={state}&client_id={client_id}&scope={scope}&redirect_uri={redirect_uri}"
    app.logger.debug(f"Generated OAuth URL: {url}")
    return redirect(url)

@app.route('/oauth/callback', methods=['GET'])
def oauth_callback():
    state = request.args.get('state')
    app.logger.debug(f"Received state: {state} for validation")

    if not state:
        app.logger.error("State is missing from the callback URL")
        return "State is missing from the callback URL", 400

    if state != session.get('state'):
        app.logger.error(f"Invalid state: {state}, session state: {session.get('state')}")
        return "Invalid state parameter", 400

    session.pop('state', None)

    code = request.args.get('code')
    
    client_id = os.getenv("SLACK_CLIENT_ID")
    client_secret = os.getenv("SLACK_CLIENT_SECRET")
    redirect_uri = url_for('oauth_callback', _external=True, _scheme='https')
    
    try:
        client = WebClient()  # Initialize the WebClient here
        response = client.oauth_v2_access(
            client_id=client_id,
            client_secret=client_secret,
            redirect_uri=redirect_uri,
            code=code
        )
        app.logger.debug(f"OAuth response: {response}")

        if response.get("ok"):
            team_id = response["team"]["id"]
            tokens[team_id] = response["access_token"]
            save_tokens(tokens)
            app.logger.info(f"OAuth flow completed successfully for team {team_id}")
        else:
            app.logger.error(f"OAuth failed: {response['error']}")
            return f"OAuth failed: {response['error']}", 400
    except SlackApiError as e:
        app.logger.error(f"Slack API error during OAuth: {e.response['error']}")
        return f"Slack API error during OAuth: {e.response['error']}", 400

    return "Installation successful!", 200

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 3000))
    app.run(debug=False, host='0.0.0.0', port=port)
