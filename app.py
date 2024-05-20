import os
import json
import requests
from flask import Flask, request, jsonify

app = Flask(__name__)
SLACK_BOT_TOKEN = os.environ.get('SLACK_BOT_TOKEN')
VERIFICATION_TOKEN = os.environ.get('VERIFICATION_TOKEN')
REACTION_NAME = "delete-thread"  # Replace with the specific reaction name

@app.route('/slack/events', methods=['POST'])
def slack_events():
    data = request.json

    if 'challenge' in data:
        return jsonify({'challenge': data['challenge']})

    if data['token'] != VERIFICATION_TOKEN:
        return jsonify({'error': 'Verification token mismatch'}), 403

    if 'event' in data:
        event = data['event']
        if event['type'] == 'reaction_added' and event['reaction'] == REACTION_NAME:
            handle_reaction_added(event)
    
    return jsonify({'status': 'ok'})

def handle_reaction_added(event):
    channel = event['item']['channel']
    timestamp = event['item']['ts']

    # Get the thread replies
    replies = get_thread_replies(channel, timestamp)
    
    # Delete the parent message and all replies
    for reply in replies:
        delete_message(channel, reply['ts'])

def get_thread_replies(channel, timestamp):
    url = "https://slack.com/api/conversations.replies"
    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {SLACK_BOT_TOKEN}'
    }
    params = {
        'channel': channel,
        'ts': timestamp
    }
    response = requests.get(url, headers=headers, params=params)
    if response.status_code == 200:
        return response.json().get('messages', [])
    return []

def delete_message(channel, timestamp):
    url = "https://slack.com/api/chat.delete"
    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {SLACK_BOT_TOKEN}'
    }
    data = {
        'channel': channel,
        'ts': timestamp
    }
    response = requests.post(url, headers=headers, data=json.dumps(data))
    if response.status_code != 200:
        print(f"Failed to delete message: {response.text}")

if __name__ == '__main__':
    app.run(port=3000)
