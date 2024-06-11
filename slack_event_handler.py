import os
import json
import time
import uuid
import logging
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
from slack_sdk.oauth import OAuthStateStore
from flask import Flask, request, jsonify, redirect
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Initialize Flask app
app = Flask(__name__)

# Initialize Slack client
client = WebClient(token=os.getenv("SLACK_USER_TOKEN"))

class FileStateStore(OAuthStateStore):
    def __init__(self, file_path="state_store.json"):
        self.file_path = file_path
        self.expiration_time = 60 * 60  # 60 minutes
        self.store = self._load_store()

    def _load_store(self):
        try:
            if os.path.exists(self.file_path):
                with open(self.file_path, 'r') as file:
                    store = json.load(file)
                logging.debug(f"Loaded state store from {self.file_path}: {store}")
                return store
            else:
                logging.debug(f"State store file {self.file_path} does not exist. Creating new store.")
                return {}
        except Exception as e:
            logging.error(f"Error loading state store from {self.file_path}: {e}")
            return {}

    def _save_store(self):
        try:
            with open(self.file_path, 'w') as file:
                json.dump(self.store, file)
            logging.debug(f"Saved state store to {self.file_path}: {self.store}")
        except Exception as e:
            logging.error(f"Error saving state store to {self.file_path}: {e}")

    def issue(self):
        state = str(uuid.uuid4())
        self.store[state] = time.time()
        self._save_store()
        logging.debug(f"Issued state: {state}, store: {self.store}")
        return state

    def consume(self, state):
        self.store = self._load_store()
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

@app.route('/slack/events', methods=['POST'])
def slack_events():
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
                            logging.error(f"Error deleting reply: {e.response['error']}")
                
                # Finally, delete the original message
                client.chat_delete(channel=channel, ts=ts)
                logging.debug(f"Deleted original message: {ts}")
            except SlackApiError as e:
                logging.error(f"Error fetching replies or deleting message: {e.response['error']}")
            except Exception as e:
                logging.error(f"Unexpected error: {str(e)}")
    return '', 200

@app.route('/install', methods=['GET'])
def install():
    state = state_store.issue()
    client_id = os.getenv("SLACK_CLIENT_ID")
    scope = "channels:history,channels:read,chat:write,reactions:read,im:history,im:read,mpim:history,mpim:read,groups:history,groups:read"
    redirect_uri = os.getenv("SLACK_REDIRECT_URI")
    oauth_url = f"https://slack.com/oauth/v2/authorize?state={state}&client_id={client_id}&scope={scope}&user_scope=&redirect_uri={redirect_uri}"
    logging.debug(f"Generated OAuth URL: {oauth_url}")
    return redirect(oauth_url)

@app.route('/oauth/callback', methods=['GET'])
def oauth_callback():
    state = request.args.get('state')
    code = request.args.get('code')

    logging.debug(f"Received state: {state} for validation")
    if state_store.consume(state):
        client_secret = os.getenv("SLACK_CLIENT_SECRET")
        redirect_uri = os.getenv("SLACK_REDIRECT_URI")
        oauth_response = client.oauth_v2_access(
            client_id=os.getenv("SLACK_CLIENT_ID"),
            client_secret=client_secret,
            code=code,
            redirect_uri=redirect_uri
        )
        logging.debug(f"OAuth response: {oauth_response}")
        
        if oauth_response['ok']:
            token = oauth_response['access_token']
            os.environ["SLACK_USER_TOKEN"] = token
            logging.debug(f"Stored user token in environment variable")
            return "OAuth callback handled, app installed.", 200
        else:
            logging.error(f"OAuth error: {oauth_response['error']}")
            return "OAuth error.", 400
    else:
        logging.error(f"Invalid state: {state}")
        return "Invalid state.", 400

if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    port = int(os.environ.get('PORT', 3000))
    app.run(debug=True, host='0.0.0.0', port=port)
