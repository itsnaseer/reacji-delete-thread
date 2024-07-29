import os
import time
import hmac
import hashlib
import uuid
import logging
from flask import Flask, request, jsonify
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
from slack_bolt import App
from slack_bolt.authorization import AuthorizeResult
from slack_bolt.adapter.flask import SlackRequestHandler
from sqlalchemy import create_engine, Table, MetaData
from dotenv import load_dotenv

#importing custom functions
from authorize import authorize_function
from oauth_callback import oauth_callback_function
from install import install_function
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

tokens_table = Table('tokens', metadata, autoload_with=engine)

store = {}

# Slack client initialization
client = WebClient()

def custom_authorize(enterprise_id, team_id, user_id, engine, tokens_table):
    auth_data = authorize_function(enterprise_id, team_id, user_id, engine, tokens_table)
    return AuthorizeResult(
        enterprise_id=auth_data["enterprise_id"],
        team_id=auth_data["team_id"],
        bot_token=auth_data["bot_token"],
        user_token=auth_data["user_token"]
    )

# Initialize Bolt app with authorize function
bolt_app = App(
    signing_secret=os.getenv("SLACK_SIGNING_SECRET"),
    authorize=lambda enterprise_id, team_id, user_id: custom_authorize(enterprise_id, team_id, user_id, engine, tokens_table)
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
                            "text": "*Delete Messages*: Use this app to delete messages (+ threaded replies) and generate the user token (`xoxp-1234567890`) for your current user."
                        }
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": "*Clear Channel History*: If you want to clear a channel's entire history, use the `/clear-channel` command.  "
                        }
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": ":warning: Deleting messages cannot be reversed unless you have fine-tuned your retention settings."
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
                                "text": "Are you looking for more comprehensive guidance? Check out the <https://salesforce.enterprise.slack.com/docs/T01G0063H29/F07BHJ16UAE|App Canvas in Giant Speck>\n\nNote: This app replaces <https://salesforce.enterprise.slack.com/docs/T01G0063H29/F0741QXLV0D|User Token Generator> (canvas will be transitioned)"
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
        logger.info(f"~*~*~*~ Channel: {message_channel} ~*~*~*~ Time stamp: {message_ts}")

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

# The clear-channel slash command handler
@bolt_app.command("/clear-channel")
def repeat_text(ack, logger, channel_id, client, context):
    ack()
    user_token = context['user_token']
    logger.info(f"~~~~ channel: {channel_id}")
    
    # Store conversation history
    conversation_history = []
    has_more = True
    next_cursor = None

    try:
        while has_more:
            # Call the conversations.history method using the WebClient
            result = client.conversations_history(
                token=user_token,
                channel=channel_id,
                cursor=next_cursor
            )
            messages = result["messages"]
            conversation_history.extend(messages)
            next_cursor = result.get("response_metadata", {}).get("next_cursor")
            has_more = bool(next_cursor)
        
        # Store each message ID in an array
        messages_to_delete = [message["ts"] for message in conversation_history]
        logger.info(f"messages to delete: {messages_to_delete}")

        # Function to delete a message
        def delete_message(channel_id, ts):
            try:
                result = client.chat_delete(
                    channel=channel_id,
                    ts=ts,
                    token=user_token
                )
                logger.info(f"Deleted message with timestamp {ts}")
            except SlackApiError as e:
                logger.error(f"Error deleting message: {e}")

        for message in conversation_history:
            # Delete the main message
            delete_message(channel_id, message["ts"])

            # If the message has a thread, delete the replies
            if message.get("thread_ts"):
                has_more_replies = True
                next_reply_cursor = None
                while has_more_replies:
                    replies_result = client.conversations_replies(
                        token=user_token,
                        channel=channel_id,
                        ts=message["thread_ts"],
                        cursor=next_reply_cursor
                    )
                    replies = replies_result["messages"]
                    next_reply_cursor = replies_result.get("response_metadata", {}).get("next_cursor")
                    has_more_replies = bool(next_reply_cursor)

                    # Delete each reply
                    for reply in replies:
                        delete_message(channel_id, reply["ts"])

    except SlackApiError as e:
        logger.error("Error fetching conversation history: {}".format(e))

# INSTALL script-- stage scopes and compile URL
@app.route('/install', methods=['GET'])
def install():
    return install_function(store)

# OAUTH Callback - check for and update or store tokens
@app.route('/oauth/callback', methods=['GET'])
def oauth_callback_route():
    return oauth_callback_function(engine, tokens_table, app, store, client)

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 3000))
    app.run(debug=True, host='0.0.0.0', port=port)