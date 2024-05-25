import os
import json
import requests
from flask import Flask, request, jsonify

app = Flask(__name__)
SLACK_BOT_TOKEN = os.environ.get('SLACK_BOT_TOKEN')
VERIFICATION_TOKEN = os.environ.get('VERIFICATION_TOKEN')
REACTION_NAME = "delete-thread"  # Replace with your specific reaction name

@app.route('/slack/events', methods=['POST'])
def slack_events():
    data = request.json
    print("Received event:", data)  # Debugging statement

    # Handle URL verification challenge
    if 'challenge' in data:
        return jsonify({'challenge': data['challenge']})

    if data['token'] != VERIFICATION_TOKEN:
        print("Verification token mismatch")  # Debugging statement
        return jsonify({'error': 'Verification token mismatch'}), 403

    if 'event' in data:
        event = data['event']
        print("Received event type:", event['type'])  # Debugging statement
        if event['type'] == 'reaction_added' and event['reaction'] == REACTION_NAME:
            print("Handling reaction added event")  # Debugging statement
            handle_reaction_added(event)
    
    return jsonify({'status': 'ok'})

@app.route('/')
def index():
    return "Hello, this is the Slack event handler app."

def handle_reaction_added(event):
    item = event['item']
    channel = item['channel']
    timestamp = item['ts']

    print(f"Channel: {channel}, Timestamp: {timestamp}")  # Debugging statement

    # Get the thread replies
    replies = get_thread_replies(channel, timestamp)
    print("Replies:", replies)  # Debugging statement
    
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
    print("Get thread replies response:", response.json())  # Debugging statement
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
    print(f"Deleting message {timestamp}, response: {response.text}")  # Debugging statement
    if response.status_code != 200:
        print(f"Failed to delete message: {response.text}")

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 3000))
    app.run(host='0.0.0.0', port=port)
