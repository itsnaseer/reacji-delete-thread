import os
import json    # importing json module
import uuid
import logging
from slack_sdk import WebClient
from slack_sdk.oauth import AuthorizeUrlGenerator, OAuthStateStore
from slack_sdk.errors import SlackApiError
from flask import Flask, request, redirect, session, jsonify, url_for, abort
from dotenv import load_dotenv
import hmac
import hashlib
import time

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY")

# Set up logging
logging.basicConfig(level=logging.DEBUG)

# OAuth configuration
client_id = os.getenv("SLACK_CLIENT_ID")
client_secret = os.getenv("SLACK_CLIENT_SECRET")
scopes = ["channels:history", "channels:read", "chat:write", "reactions:read", "im:history", "im:read", "mpim:history", "mpim:read", "groups:history", "groups:read"]
redirect_uri = os.getenv("SLACK_REDIRECT_URI")

# Slack signing secret
signing_secret = os.getenv("SLACK_SIGNING_SECRET")

# File-based state store for OAuth
class FileStateStore(OAuthStateStore):
    def __init__(self, file_path="state_store.json"):
        self.file_path = file_path
        self.expiration_time = 60 * 5  # 5 minutes
        self._load_store()

    def _load_store(self):
        if os.path.exists(self.file_path):
            with open(self.file_path, 'r') as file:
                self.store = json.load(file)
        else:
            self.store = {}

    def _save_store(self):
        with open(self.file_path, 'w') as file:
            json.dump(self.store, file)

    def issue(self):
        state = str(uuid.uuid4())
        self.store[state] = time.time()
        self._save_store()
        logging.debug(f"Issued state: {state}, store: {self.store}")
        return state

    def consume(self, state):
        current_time = time.time()
        state_time = self.store.get(state)
        
        if state_time and (current_time - state_time) <= self.expiration_time:
            del self.store[state]
            self._save_store()
            logging.debug(f"Consumed state: {state}, store: {self.store}")
            return True
        
        logging.debug(f"State not found or expired: {state}, store: {self.store}")
        return False

state_store = FileStateStore()

authorize_url_generator = AuthorizeUrlGenerator(client_id=client_id, scopes=scopes, redirect_uri=redirect_uri)

@app.route('/')
def index():
    return "Slack App is running!", 200

@app.route('/install', methods=['GET'])
def install():
    state = state_store.issue()
    url = authorize_url_generator.generate(state=state)
    logging.debug(f"Generated OAuth URL: {url}")
    return redirect(url)

@app.route('/oauth/callback', methods=['GET'])
def oauth_callback():
    code = request.args.get('code')
    state = request.args.get('state')

    logging.debug(f"Received state: {state} for validation")

    if not state_store.consume(state):
        logging.error(f"Invalid state: {state}")
        return "Invalid state", 400

    try:
        response = WebClient().oauth_v2_access(
            client_id=client_id,
            client_secret=client_secret,
            code=code,
            redirect_uri=redirect_uri
        )
        logging.debug(f"OAuth response: {response}")

        user_token = response['access_token']

        # Store the user token in the environment variable
        os.environ["SLACK_USER_TOKEN"] = user_token
        logging.debug(f"Stored user token in environment variable")

        return "Installation successful!", 200
    except SlackApiError as e:
        logging.error(f"Slack API Error: {e.response['error']}")
        return f"Error: {e.response['error']}", 400
    except Exception as e:
        logging.error(f"Unexpected error: {str(e)}")
        return f"Error: {str(e)}", 400

def verify_slack_request(request):
    timestamp = request.headers.get('X-Slack-Request-Timestamp')
    if abs(time.time() - int(timestamp)) > 60 * 5:
        return False

    sig_basestring = f'v0:{timestamp}:{request.get_data(as_text=True)}'
    my_signature = 'v0=' + hmac.new(
        signing_secret.encode('utf-8'),
        sig_basestring.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()

    slack_signature = request.headers.get('X-Slack-Signature')
    return hmac.compare_digest(my_signature, slack_signature)

@app.route('/slack/events', methods=['POST'])
def slack_events():
    if not verify_slack_request(request):
        logging.error("Request verification failed")
        abort(400)

    data = request.json
    logging.debug(f"Received event: {data}")

    if 'event' in data:
        event = data['event']
        logging.debug(f"Handling event: {event}")

        if event.get('type') == 'reaction_added' and event.get('reaction') == 'delete-thread':
            channel = event['item']['channel']
            ts = event['item']['ts']

            user_token = os.getenv("SLACK_USER_TOKEN")
            logging.debug(f"User token: {user_token}")

            if not user_token:
                logging.error("User token not found")
                return "User token not found", 400

            client = WebClient(token=user_token)

            try:
                # Fetch and delete all threaded replies
                response = client.conversations_replies(channel=channel, ts=ts)
                logging.debug(f"Fetched replies: {response['messages']}")
                for message in response['messages']:
                    if message['ts'] != ts:
                        try:
                            client.chat_delete(channel=channel, ts=message['ts'])
                            logging.debug(f"Deleted reply: {message['ts']}")
                        except SlackApiError as e:
                            logging.error(f"Error deleting reply: {e.response['error']}")
                
                # Finally, delete the original message
                client.chat_delete(channel=channel, ts=ts)
                logging.debug(f"Deleted original message: {ts}")
            except SlackApiError as e:
                logging.error(f"Error fetching replies or deleting message: {e.response['error']}")
            except Exception as e:
                logging.error(f"Unexpected error: {str(e)}")
    return '', 200

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 3000))
    app.run(debug=True, host='0.0.0.0', port=port)
