import os
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
from flask import Flask, request, jsonify
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
client = WebClient(token=os.getenv("SLACK_USER_TOKEN"))

@app.route('/slack/events', methods=['POST'])
def slack_events():
    data = request.json
    if 'event' in data:
        event = data['event']
        if event.get('type') == 'reaction_added' and event.get('reaction') == 'delete-thread':
            channel = event['item']['channel']
            ts = event['item']['ts']
            try:
                # Delete the original message
                client.chat_delete(channel=channel, ts=ts)
                
                # Fetch and delete all threaded replies
                response = client.conversations_replies(channel=channel, ts=ts)
                for message in response['messages']:
                    client.chat_delete(channel=channel, ts=message['ts'])
            except SlackApiError as e:
                print(f"Error deleting message: {e.response['error']}")
    return '', 200

if __name__ == '__main__':
    app.run(debug=True, port=os.getenv('PORT', 3000))
