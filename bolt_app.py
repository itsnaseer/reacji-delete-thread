import os
import logging
from slack_bolt import App
from slack_bolt.oauth.oauth_settings import OAuthSettings
from slack_bolt.adapter.flask import SlackRequestHandler
from slack_sdk.oauth.installation_store.sqlalchemy import SQLAlchemyInstallationStore
from slack_sdk.oauth.state_store.sqlalchemy import SQLAlchemyOAuthStateStore
from sqlalchemy import create_engine, MetaData
from flask import Flask, request
from slack_sdk.errors import SlackApiError

# Initialize Flask app
flask_app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.DEBUG)

# Database setup
DATABASE_URL = os.getenv("DATABASE_URL")
engine = create_engine(DATABASE_URL)
metadata = MetaData()

# Installation store and OAuth state store
installation_store = SQLAlchemyInstallationStore(
    client_id=os.getenv("SLACK_CLIENT_ID"),
    engine=engine,
    metadata=metadata,
    logger=logging.getLogger(__name__)
)

oauth_state_store = SQLAlchemyOAuthStateStore(
    expiration_seconds=600,
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
        installation_store=installation_store,
        state_store=oauth_state_store,
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
def clear_channel(ack, body, logger, client, context):
    ack()
    channel_id = body['channel_id']
    user_token = context.get('user_token')  # Fetch user token if available

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
                client.chat_delete(
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
        logger.error(f"Error fetching conversation history: {e}")

# Reaction added event listener to handle delete-thread functionality
@bolt_app.event("reaction_added")
def handle_reaction_added(event, client, logger, context):
    try:
        if event["reaction"] == "your_specific_reaction":
            channel_id = event["item"]["channel"]
            message_ts = event["item"]["ts"]
            user_token = context['user_token']

            # Fetch replies to the message
            replies = client.conversations_replies(
                channel=channel_id,
                ts=message_ts,
                token=user_token
            )

            # Collect the timestamps of all messages in the thread
            messages_to_delete = [reply["ts"] for reply in replies["messages"]]

            # Delete all messages in the thread
            for ts in messages_to_delete:
                client.chat_delete(
                    channel=channel_id,
                    ts=ts,
                    token=user_token
                )
                logger.info(f"Deleted message with timestamp {ts}")

    except SlackApiError as e:
        logger.error(f"Error handling reaction: {e}")

if __name__ == "__main__":
    port = int(os.getenv("PORT", 3000))
    logging.info(f"Starting app on port {port}")
    flask_app.run(host="0.0.0.0", port=port)