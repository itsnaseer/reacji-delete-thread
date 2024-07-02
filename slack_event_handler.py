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

@app.route('/install', methods=['GET'])
def install():
    client_id = os.getenv("SLACK_CLIENT_ID")
    redirect_uri = "https://reacji-delete-thread-c3eb299ca184.herokuapp.com/oauth/callback"
    scope = "reactions:read,channels:history,channels:read,chat:write,im:history,im:read,mpim:read,mpim:history,groups:history,groups:read"
    state = os.urandom(24).hex()
    install_url = f"https://slack.com/oauth/v2/authorize?client_id={client_id}&scope={scope}&state={state}&redirect_uri={redirect_uri}"
    return jsonify({"install_url": install_url})

@app.route('/oauth/callback', methods=['GET'])
def oauth_callback():
    code = request.args.get('code')
    state = request.args.get('state')

    if not state:
        app.logger.error("State is missing from the callback URL")
        return "State is missing from the callback URL", 400

    client = WebClient()
    response = client.oauth_v2_access(
        client_id=os.getenv("SLACK_CLIENT_ID"),
        client_secret=os.getenv("SLACK_CLIENT_SECRET"),
        code=code,
        redirect_uri="https://reacji-delete-thread-c3eb299ca184.herokuapp.com/oauth/callback"
    )

    if response.get('ok'):
        team_id = response['team']['id']
        user_id = response['authed_user']['id']
        access_token = response['access_token']

        # Store token in the database
        requests.post(f"{database_url}/store_token", json={
            "team_id": team_id,
            "user_id": user_id,
            "access_token": access_token
        })

        return "Installation successful", 200
    else:
        app.logger.error("OAuth failed: %s", response.get('error'))
        return f"OAuth failed: {response.get('error')}", 400

@app.route('/slack/events', methods=['POST'])
def slack_events():
    if not verify_slack_request(request):
        return 'Request verification failed', 400

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
                response = client.conversations_replies(channel=channel, ts=ts)
                for message in response['messages']:
                    if message['ts'] != ts:
                        try:
                            client.chat_delete(channel=channel, ts=message['ts'])
                        except SlackApiError as e:
                            app.logger.error(f"Error deleting reply: {e.response['error']}")

                client.chat_delete(channel=channel, ts=ts)
            except SlackApiError as e:
                app.logger.error(f"Error fetching replies or deleting message: {e.response['error']}")
            except Exception as e:
                app.logger.error(f"Unexpected error: {str(e)}")
    return '', 200

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 3000))
    app.run(debug=True, host='0.0.0.0', port=port)
