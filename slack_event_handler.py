import os
import requests
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
from flask import Flask, request, jsonify
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
signing_secret = os.getenv("SLACK_SIGNING_SECRET")
database_url = os.getenv("DATABASE_URL")

def get_token(team_id):
    response = requests.get(f"{database_url}/get_token/{team_id}")
    if response.status_code == 200:
        return response.json()['access_token']
    else:
        return None


@app.route('/oauth/callback', methods=['GET'])
def oauth_callback():
    state = request.args.get('state')
    if not state:
        app.logger.error('State is missing from the callback URL')
        return 'State is missing from the callback URL', 400
    if state not in state_store:
        app.logger.error(f'Invalid state: {state}')
        return 'Invalid state', 400
    state_store.pop(state)
    code = request.args.get('code')
    if not code:
        app.logger.error('Code is missing from the callback URL')
        return 'Code is missing from the callback URL', 400
    try:
        response = client.oauth_v2_access(
            client_id=os.getenv("SLACK_CLIENT_ID"),
            client_secret=os.getenv("SLACK_CLIENT_SECRET"),
            code=code,
            redirect_uri=os.getenv("REDIRECT_URI")
        )
        # Store the access token and other details in your database
        app.logger.debug(f'OAuth response: {response}')
        return 'OAuth callback successful', 200
    except SlackApiError as e:
        app.logger.error(f'Error during OAuth: {e.response["error"]}')
        return f'Error during OAuth: {e.response["error"]}', 500


@app.route('/slack/events', methods=['POST'])
def slack_events():
    # verify slack request
    # your existing code here...
    data = request.json
    team_id = data['team_id']
    access_token = get_token(team_id)
    client = WebClient(token=access_token)
    
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
    app.run(debug=True, host='0.0.0.0', port=port)
