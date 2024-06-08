import os
import uuid
import logging
from slack_sdk import WebClient
from slack_sdk.oauth import AuthorizeUrlGenerator, OAuthStateStore
from slack_sdk.errors import SlackApiError
from flask import Flask, request, redirect, session, jsonify, url_for
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY")

client = WebClient()

# Set up logging
logging.basicConfig(level=logging.DEBUG)

# OAuth configuration
client_id = os.getenv("SLACK_CLIENT_ID")
client_secret = os.getenv("SLACK_CLIENT_SECRET")
scopes = ["channels:history", "channels:read", "chat:write", "reactions:read", "im:history", "im:read", "mpim:history", "mpim:read", "groups:history", "groups:read"]
redirect_uri = os.getenv("SLACK_REDIRECT_URI")

# In-memory state store for OAuth
class MemoryStateStore(OAuthStateStore):
    def __init__(self):
        self.store = {}

    def issue(self):
        state = str(uuid.uuid4())
        self.store[state] = True
        logging.debug(f"Issued state: {state}")
        return state

    def consume(self, state):
        if state in self.store:
            del self.store[state]
            logging.debug(f"Consumed state: {state}")
            return True
        logging.debug(f"State not found: {state}")
        return False

state_store = MemoryStateStore()

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

    if not state_store.consume(state):
        logging.error(f"Invalid state: {state}")
        return "Invalid state", 400

    try:
        response = client.oauth_v2_access(
            client_id=client_id,
            client_secret=client_secret,
            code=code,
            redirect_uri=redirect_uri
        )
        logging.debug(f"OAuth response: {response}")

        authed_user = response.get('authed_user')
        access_token = authed_user.get('access_token')

        session['slack_user_token'] = access_token

        return "Installation successful!", 200
    except SlackApiError as e:
        logging.error(f"Slack API Error: {e.response['error']}")
        return f"Error: {e.response['error']}", 400
    except Exception as e:
        logging.error(f"Unexpected error: {str(e)}")
        return f"Error: {str(e)}", 400

@app.route('/slack/events', methods=['POST'])
def slack_events():
    data = request.json
    if 'event' in data:
        event = data['event']
        if event.get('type') == 'reaction_added' and event.get('reaction') == 'delete-thread':
            channel = event['item']['channel']
            ts = event['item']['ts']
            user_token = session.get('slack_user_token')

            if not user_token:
                return "User token not found", 400

            user_client = WebClient(token=user_token)

            try:
                # Fetch and delete all threaded replies
                response = user_client.conversations_replies(channel=channel, ts=ts)
                for message in response['messages']:
                    if message['ts'] != ts:
                        try:
                            user_client.chat_delete(channel=channel, ts=message['ts'])
                        except SlackApiError as e:
                            logging.error(f"Error deleting reply: {e.response['error']}")
                
                # Finally, delete the original message
                user_client.chat_delete(channel=channel, ts=ts)
            except SlackApiError as e:
                logging.error(f"Error fetching replies or deleting message: {e.response['error']}")
            except Exception as e:
                logging.error(f"Unexpected error: {str(e)}")
    return '', 200

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 3000))
    app.run(debug=True, host='0.0.0.0', port=port)
