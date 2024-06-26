import os
import time
import hmac
import hashlib
import uuid
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
from flask import Flask, request, redirect, session, jsonify, url_for
from dotenv import load_dotenv
import json

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "supersecretkey")
signing_secret = os.getenv("SLACK_SIGNING_SECRET")

# Function to load tokens from a JSON file
def load_tokens():
    try:
        with open('tokens.json', 'r') as file:
            return json.load(file)
    except FileNotFoundError:
        return {}

# Function to save tokens to a JSON file
def save_tokens(tokens):
    with open('tokens.json', 'w') as file:
        json.dump(tokens, file)

tokens = load_tokens()

def get_client_for_team(team_id):
    token = tokens.get(team_id)
    if token:
        return WebClient(token=token)
    else:
        app.logger.error(f"No token found for team {team_id}")
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
        app.logger.error('Request verification failed')
        return 'Request verification failed', 400

    data = request.json
    app.logger.debug(f"Received event: {data}")

    team_id = data.get('team_id')
    client = get_client_for_team(team_id)
    if not client:
        return 'Client not found', 400

    if 'event' in data:
        event = data['event']
        app.logger.debug(f"Handling event: {event}")
        if event.get('type') == 'reaction_added' and event.get('reaction') == 'delete-thread':
            channel = event['item']['channel']
            ts = event['item']['ts']
            app.logger.debug(f"Reaction added event in channel: {channel} at timestamp: {ts}")

            try:
                # Fetch and delete all threaded replies
                response = client.conversations_replies(channel=channel, ts=ts)
                app.logger.debug(f"Conversations replies response: {response}")
                for message in response['messages']:
                    # Only delete replies, not the initial message
                    if message['ts'] != ts:
                        try:
                            client.chat_delete(channel=channel, ts=message['ts'])
                            app.logger.debug(f"Deleted reply message with timestamp: {message['ts']}")
                        except SlackApiError as e:
                            app.logger.error(f"Error deleting reply: {e.response['error']}")

                # Finally, delete the original message
                client.chat_delete(channel=channel, ts=ts)
                app.logger.debug(f"Deleted original message with timestamp: {ts}")
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

    auth_url = (
        "https://slack.com/oauth/v2/authorize?"
        f"client_id={client_id}&"
        "scope=channels:history,channels:read,chat:write,reactions:read,im:history,im:read,mpim:read,mpim:history,groups:history,groups:read&"
        f"state={state}&"
        f"redirect_uri={redirect_uri}"
    )
    app.logger.debug(f"Generated OAuth URL: {auth_url}")
    return redirect(auth_url)

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
    try:
        response = client.oauth_v2_access(
            client_id=os.getenv("SLACK_CLIENT_ID"),
            client_secret=os.getenv("SLACK_CLIENT_SECRET"),
            redirect_uri=url_for('oauth_callback', _external=True, _scheme='https'),
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
    app.run(debug=True, host='0.0.0.0', port=port)
