import os
import time
import logging
from flask import request
from requests.auth import HTTPBasicAuth
import requests

def oauth_callback(engine, tokens_table, app, client, store):
    state = request.args.get('state')
    code = request.args.get('code')
    
    app.logger.debug(f"State received: {state}")
    app.logger.debug(f"Store content: {store}")

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
                        app.logger.info(f"Successfully updated