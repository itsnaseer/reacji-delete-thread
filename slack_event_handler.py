import requests
from flask import Flask, request, jsonify
from sqlalchemy import create_engine, Table, Column, String, MetaData, select

app = Flask(__name__)
DATABASE_URL = os.getenv('DATABASE_URL')

# Initialize database connection
engine = create_engine(DATABASE_URL)
metadata = MetaData()

# Define tokens table
tokens_table = Table('tokens', metadata,
    Column('team_id', String, nullable=False),
    Column('user_id', String, primary_key=True, nullable=False),
    Column('access_token', String, nullable=False),
    Column('created_at', String, nullable=False),
    Column('updated_at', String, nullable=False)
)

@app.route("/slack/events", methods=["POST"])
def slack_events():
    event_data = request.json
    app.logger.debug(f"Event Data: {event_data}")

    if "event" in event_data and event_data["event"]["type"] == "reaction_added":
        event = event_data["event"]
        if event["reaction"] == "delete-thread":
            team_id = event_data["team_id"]
            item = event["item"]
            channel_id = item["channel"]
            message_ts = item["ts"]

            # Retrieve the token from the database
            try:
                with engine.connect() as conn:
                    app.logger.debug(f"Querying token for team_id: {team_id}")
                    result = conn.execute(select([tokens_table.c.access_token]).where(tokens_table.c.team_id == team_id))
                    token = result.scalar()
            except Exception as e:
                app.logger.error(f"Error querying token: {e}")
                return jsonify({"error": "Error querying token"}), 500

            if not token:
                app.logger.error(f"Token not found for team_id: {team_id}")
                return jsonify({"error": "Token not found"}), 400

            app.logger.debug(f"Using token: {token} for team_id: {team_id}")

            # Form the API call to delete the message
            delete_url = "https://slack.com/api/chat.delete"
            headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
            payload = {"channel": channel_id, "ts": message_ts}

            response = requests.post(delete_url, headers=headers, json=payload)
            response_data = response.json()

            if not response_data["ok"]:
                app.logger.error(f"Error deleting message: {response_data['error']}")
                return jsonify({"error": response_data["error"]}), 400

            app.logger.debug(f"Message deleted: {response_data}")

            return jsonify({"status": "Message deleted"}), 200

    return jsonify({"status": "Event received"}), 200

if __name__ == "__main__":
    app.run(debug=True)
