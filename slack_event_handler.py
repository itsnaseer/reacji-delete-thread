python
import os
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
from flask import Flask, request, jsonify
from dotenv import load_dotenv
import hmac
import hashlib

# Load environment variables from .env file
load_dotenv()

app = Flask(~name~)
client = WebClient(token=os.getenv("SLACK_USER_TOKEN"))
signing_secret = os.getenv("SLACK_SIGNING_SECRET")

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
return 'Request verification failed', 400

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
print(f"Error deleting reply: {e.response['error']}")

# Finally, delete the original message
client.chat_delete(channel=channel, ts=ts)
except SlackApiError as e:
print(f"Error fetching replies or deleting message: {e.response['error']}")
except Exception as e:
print(f"Unexpected error: {str(e)}")
return '', 200

if ~name~ == '~main~':
port = int(os.environ.get('PORT', 3000))
app.run(debug=False, host='0.0.0.0', port=port)
