import os
import time
import logging
from flask import Flask, request, jsonify
from slack_bolt import App
from slack_bolt.adapter.flask import SlackRequestHandler
from slack_sdk.errors import SlackApiError
from dotenv import load_dotenv
from sqlalchemy import create_engine, Table, Column, String, MetaData

from install import install
from oauth_callback import oauth_callback
from authorize import authorize
from verify_slack_request import verify_slack_request

# Load environment variables from .env file
load_dotenv()
logging.basicConfig(level=logging.DEBUG)

# Initialize Flask app
app = Flask(__name__)
logger = logging.getLogger(__name__)

# Database configuration
DATABASE_URL = os.getenv("DATABASE_URL")
engine = create_engine(DATABASE_URL)
metadata = MetaData()

tokens_table = Table('tokens', metadata,
    Column('team_id', String, nullable=False),
    Column('user_id', String, primary_key=True, nullable=False),
    Column('access_token', String, nullable=False),
    Column('bot_token', String, nullable=True),
    Column('created_at', String, nullable=False),
    Column('updated_at', String, nullable=False)
)

metadata.create_all(engine)

store = {}

# Initialize Bolt app with authorize function
bolt_app = App(
    signing_secret=os.getenv("SLACK_SIGNING_SECRET"),
    authorize=lambda enterprise_id, team_id, user_id: authorize(engine, tokens_table, enterprise_id, team_id, user_id)
)
handler = SlackRequestHandler(bolt_app)

# Event handler for app_home_opened
@bolt_app.event("app_home_opened")
def update_home_tab(client, event, logger):
    user_id = event["user"]
    try:
        # Use the bot token for publishing the home tab
        client.views_publish(
            user_id=user_id,
            view={
                "type": "home",
                "blocks": [
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": "Use this app to delete messages (+ threaded replies) and generate the user token (`xoxp-1234567890`) for your current user. The user token is used to delete the messages and impersonate users in SBN workflows. Note: This app replaces <https://salesforce.enterprise.slack.com/docs/T01G0063H29/F0741QXLV0D|User Token Generator> (canvas will be transitioned)"
                        }
                    },
                    {
                        "type": "divider"
                    },
                    {
                        "type": "header",
                        "text": {
                            "type": "plain_text",
                            "text": "Get Started"
                        }
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": "This app uses a combination of bot and user token scopes to get permissions to manage conversations (DM, Channel, MPDM). The app uses the current user’s ID to generate the token. After generating the token it will send a message to the App’s Messages tab. "
                        }
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": "\t1.\t *Set up*. Add `delete-thread` as a reaction in your workspace. I like <https://drive.google.com/file/d/1JyOH1AAB1lAa3rHdyDXGrc_kOQuCsems/view?usp=drive_link|this version>, but you can use your own. "
                        }
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": "\t2.\t *Test*.Find a message anywhere in your workspace and apply the `:delete-thread:` reaction. If there are threaded messages, all replies will delete. "
                        }
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": "\t3.\t (optional) *Copy your token*. If you are using Smockbot Next, go to the your user’s DM with themself, copy the token, and follow the instructions for Using with SBN. "
                        }
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": "\t4.\t *Delete the token message*. Find the direct message <@{user_id}> with your user’s token in the DM with yourself and delete the message with the user token.\n_Bonus points_. Use :delete-thread: to delete the DM with the token info.  "
                        }
                    },
                    {
                        "type": "divider"
                    },
                    {
                        "type": "context",
                        "elements": [
                            {
                                "type": "mrkdwn",
                                "text": "Are you looking for more comprehensive guidance? Check out the <https://salesforce.enterprise.slack.com/docs/T01G0063H29/F07BHJ16UAE|App Canvas in Giant Speck>"
                            }
                        ]
                    }
                ]
            }
        )
        logger.info(f"Home tab published")

    except Exception as e:
        logger.error(f"Error publishing home tab: {e}")

# Event handler for Slack events and app config
@app.route("/slack/events", methods=["POST"])
def slack_events():
    if "challenge" in request.json:
        return jsonify({"challenge": request.json["challenge"]})
    return handler.handle(request)

# Event handler for reaction_added
@bolt_app.event("reaction_added")
def handle_reaction_added(client, event, context, logger):
    reaction = event["reaction"] 
    logger.debug(f"~*~*~*~ Received a reaction event: {reaction}")

    if reaction == "delete-thread":
        event_item = event.get("item")
        message_channel = event_item.get("channel")
        message_ts = event_item.get("ts")
        user_token = context['user_token']
        logger.debug(f"~*~*~*~ Channel: {message_channel} ~*~*~*~ Time stamp: {message_ts}")

        # Fetch replies to the message
        try:
            replies = client.conversations_replies(
                channel=message_channel, 
                ts=message_ts,
                token=user_token
            )
            # Store each message ID in an array
            messages_to_delete = [message["ts"] for message in replies["messages"]]

            # Sort replies from newest to oldest
            messages_to_delete.sort(reverse=True)

            # Delete each message in the replies array
            for ts in messages_to_delete:
                try:
                    result = client.chat_delete(
                        channel=message_channel,
                        ts=ts,
                        token=user_token
                    )
                    logger.info(result)
                except SlackApiError as e:
                    logger.error(f"Error deleting message: {e}")
        except SlackApiError as e:
            logger.error(f"Error fetching replies: {e}")
        
#route slash command from flask to bolt
@app.route("/slack/clear-channel", methods=["POST"])
def clear_channel_router():
    return handler.handle(request)

# The echo command simply echoes on command
@bolt_app.command("/clear-channel")
def repeat_text(ack, logger, text):
    ack()
    logger.info(f"command received {text}")

# Route for install
@app.route('/install', methods=['GET'])
def install_route():
    return install()

# OAUTH Callback route
@app.route('/oauth/callback', methods=['GET'])
def oauth_callback_route():
    return oauth_callback(engine, tokens_table, app, client)

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 3000))
    app.run(debug=True, host='0.0.0.0', port=port)