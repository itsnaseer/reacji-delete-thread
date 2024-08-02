import os
import logging
from slack_bolt import App
from slack_bolt.oauth.oauth_settings import OAuthSettings
from slack_bolt.adapter.flask import SlackRequestHandler
from slack_sdk.errors import SlackApiError
from sqlalchemy import create_engine, MetaData
from flask import Flask, request

import json
from custom_installation_store import CustomInstallationStore

# Initialize Flask app
flask_app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO)

# Database setup
DATABASE_URL = os.getenv("DATABASE_URL")
engine = create_engine(DATABASE_URL)
metadata = MetaData()

# Installation store
installation_store = CustomInstallationStore(
    client_id=os.getenv("SLACK_CLIENT_ID"),
    engine=engine,
    logger=logging.getLogger(__name__)
)

# Define the scopes required for the app
scopes = [
    "app_mentions:read",
    "channels:history",
    "channels:read",
    "chat:write",
    "commands",
    "groups:history",
    "groups:read",
    "im:history",
    "im:read",
    "mpim:history",
    "mpim:read",
    "reactions:read",
    "users:read",
    "users:read.email",
    "chat:write.public",
    "chat:write.customize",
    "reactions:write",
    "team:read",
    "users.profile:read",
    "conversations.history",
    "conversations.replies",
    "conversations:read"
]

# Initialize Slack Bolt app with OAuth settings
bolt_app = App(
    signing_secret=os.getenv("SLACK_SIGNING_SECRET"),
    oauth_settings=OAuthSettings(
        client_id=os.getenv("SLACK_CLIENT_ID"),
        client_secret=os.getenv("SLACK_CLIENT_SECRET"),
        scopes=scopes,
        installation_store=installation_store
    )
)

# Initialize Slack request handler for Flask
handler = SlackRequestHandler(bolt_app)

# Route for Slack events
@flask_app.route("/slack/events", methods=["POST"])
def slack_events():
    try:
        return handler.handle(request)
    except Exception as e:
        logging.error(f"Error handling Slack event: {e}")
        return "Internal Server Error", 500

# Route for clear-channel slash command
@flask_app.route("/slack/clear-channel", methods=["POST"])
def clear_channel_router():
    try:
        return handler.handle(request)
    except Exception as e:
        logging.error(f"Error handling clear-channel command: {e}")
        return "Internal Server Error", 500

# The clear-channel slash command handler
@bolt_app.command("/clear-channel")
def repeat_text(ack, logger, body, client, context):
    ack()
    channel_id = body['channel_id']
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

# Reaction added event listener to handle delete-thread functionality
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

# Event handler for app_home_opened
@bolt_app.event("app_home_opened")
def update_home_tab(client, event, logger):
    user_id = event["user"]
    try:
        client.views_publish(
            user_id=user_id,
            view=open('app_home.json')
        )
        logger.info(f"Home tab published")

    except Exception as e:
        logger.error(f"Error publishing home tab: {e}")

if __name__ == "__main__":
    port = int(os.getenv("PORT", 3000))
    logging.info(f"Starting app on port {port}")
    flask_app.run(host="0.0.0.0", port=port)