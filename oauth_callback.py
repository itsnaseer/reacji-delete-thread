import time
import requests
from sqlalchemy import insert, update
from slack_sdk.errors import SlackApiError

def oauth_callback(engine, tokens_table, app, client):
    from flask import request
    from requests.auth import HTTPBasicAuth

    state = request.args.get('state')
    code = request.args.get('code')

    if not state or state not in store:
        app.logger.error("State is missing or invalid from the callback URL")
        return "State is missing or invalid from the callback URL", 400

    # Basic authentication for client_id and client_secret
    auth = HTTPBasicAuth(os.getenv("SLACK_CLIENT_ID"), os.getenv("SLACK_CLIENT_SECRET"))

    token_url = "https://slack.com/api/oauth.v2.access"
    data = {
        'code': code,
        'redirect_uri': os.getenv("REDIRECT_URI")
    }

    response = requests.post(token_url, auth=auth, data=data)
    response_data = response.json()

    app.logger.info(f"OAuth response: {response_data}")

    if response_data['ok']:
        team_id = response_data['team']['id']
        user_id = response_data['authed_user']['id']
        access_token = response_data['authed_user'].get('access_token')  # Use user access token if available
        bot_token = response_data.get('access_token')  # Fallback to bot access token

        created_at = str(time.time())
        updated_at = created_at

        app.logger.debug(f"Team ID: {team_id}, User ID: {user_id}, Access Token: {access_token}, Bot Token: {bot_token}")

        if not access_token:
            app.logger.error("Access token not found in OAuth response")
            return "OAuth flow failed", 500

        with engine.connect() as conn:
            app.logger.info(f"Inserting/updating token for team {team_id}, user {user_id}, access_token: {access_token}, bot_token: {bot_token}")
            trans = conn.begin()
            try:
                # Try to insert the new token
                conn.execute(tokens_table.insert().values(
                    team_id=team_id,
                    user_id=user_id,
                    access_token=access_token,
                    bot_token=bot_token,
                    created_at=created_at,
                    updated_at=updated_at
                ))
                trans.commit()
                app.logger.info(f"Successfully inserted token for team {team_id}, user {user_id}")
            except Exception as insert_error:
                app.logger.info(f"Error during insert: {insert_error}")
                if 'duplicate key value violates unique constraint' in str(insert_error):
                    trans.rollback()
                    # If a unique constraint violation occurs, update the existing token
                    app.logger.info(f"Token for user {user_id} already exists, updating instead.")
                    trans = conn.begin()
                    try:
                        conn.execute(tokens_table.update().values(
                            team_id=team_id,
                            access_token=access_token,
                            bot_token=bot_token,
                            updated_at=updated_at
                        ).where(tokens_table.c.user_id == user_id))
                        trans.commit()
                        app.logger.info(f"Successfully updated token for team {team_id}, user {user_id}")
                    except Exception as update_error:
                        trans.rollback()
                        app.logger.error(f"Error updating token: {update_error}")
                        return "OAuth flow failed", 500
                else:
                    trans.rollback()
                    app.logger.error(f"Error inserting token: {insert_error}")
                    return "OAuth flow failed", 500

        # Send a message to the user's personal DM with the user token, user's name, and user ID
        try:
            user_info_response = client.users_info(user=user_id, token=access_token)
            if user_info_response["ok"]:
                user_name = user_info_response["user"]["name"]
                message_text = f"User Token: {access_token}\nUser Name: {user_name}\nUser ID: {user_id}"

                client.chat_postMessage(
                    channel=user_id,
                    text=message_text,
                    token=access_token
                )
                app.logger.info(f"Successfully sent DM to user {user_id}")
            else:
                app.logger.error(f"Error retrieving user info: {user_info_response['error']}")
        except SlackApiError as e:
            app.logger.error(f"Slack API Error: {e.response['error']}")

        return "OAuth flow completed", 200
    else:
        app.logger.error(f"OAuth response error: {response_data}")
        return "OAuth flow failed", 400