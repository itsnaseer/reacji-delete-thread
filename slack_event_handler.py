import os
import json
import requests
from flask import Flask, request, jsonify, redirect, url_for
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///tokens.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

SLACK_CLIENT_ID = os.environ.get('SLACK_CLIENT_ID')
SLACK_CLIENT_SECRET = os.environ.get('SLACK_CLIENT_SECRET')
SLACK_SIGNING_SECRET = os.environ.get('SLACK_SIGNING_SECRET')
OAUTH_SCOPE = "channels:history,channels:read,chat:write,reactions:read,users:read"

class UserToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(50), unique=True, nullable=False)
    token = db.Column(db.String(500), nullable=False)

@app.before_first_request
def create_tables():
    db.create_all()

@app.route('/')
def index():
    return "Hello, this is the Slack event handler app."

@app.route('/slack/oauth', methods=['GET'])
def oauth_authorize():
    return redirect(f"https://slack.com/oauth/v2/authorize?client_id={SLACK_CLIENT_ID}&scope={OAUTH_SCOPE}&user_scope={OAUTH_SCOPE}&redirect_uri={url_for('oauth_callback', _external=True)}")

@app.route('/slack/oauth/callback', methods=['GET'])
def oauth_callback():
    code = request.args.get('code')
    response = requests.post("https://slack.com/api/oauth.v2.access", data={
        'client_id': SLACK_CLIENT_ID,
        'client_secret': SLACK_CLIENT_SECRET,
        'code': code,
        'redirect_uri': url_for('oauth_callback', _external=True)
    })
    auth_response = response.json()
    user_id = auth_response['authed_user']['id']
    token = auth_response['authed_user']['access_token']

    user_token = UserToken.query.filter_by(user_id=user_id).first()
    if user_token:
        user_token.token = token
    else:
        user_token = UserToken(user_id=user_id, token=token)
        db.session.add(user_token)
    db.session.commit()

    return "OAuth authorization successful. You can close this window."

@app.route('/slack/events', methods=['POST'])
def slack_events():
    data = request.json
    if 'challenge' in data:
        return jsonify({'challenge': data['challenge']})

    if 'event' in data:
        event = data['event']
        if event['type'] == 'reaction_added' and event['reaction'] == 'delete-thread':
            handle_reaction_added(event)
    
    return jsonify({'status': 'ok'})

def handle_reaction_added(event):
    item = event['item']
    channel = item['channel']
    timestamp = item['ts']
    user_id = event['user']

    user_token = UserToken.query.filter_by(user_id=user_id).first()
    if user_token:
        token = user_token.token
        replies = get_thread_replies(channel, timestamp, token)
        for reply in replies:
            delete_message(channel, reply['ts'], token)
    else:
        print(f"Token for user {user_id} not found.")

def get_thread_replies(channel, timestamp, token):
    url = "https://slack.com/api/conversations.replies"
    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {token}'
    }
    params = {
        'channel': channel,
        'ts': timestamp
    }
    response = requests.get(url, headers=headers, params=params)
    if response.status_code == 200:
        return response.json().get('messages', [])
    return []

def delete_message(channel, timestamp, token):
    url = "https://slack.com/api/chat.delete"
    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {token}'
    }
    data = {
        'channel': channel,
        'ts': timestamp
    }
    response = requests.post(url, headers=headers, data=json.dumps(data))
    print(f"Deleting message {timestamp}, response: {response.text}")

if __name__ == '__main__':
    app.run(port=int(os.environ.get('PORT', 3000)), host='0.0.0.0')
