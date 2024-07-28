import logging
from sqlalchemy import select
from slack_bolt.authorization import AuthorizeResult

def authorize(enterprise_id, team_id, user_id, engine, tokens_table):
    logger = logging.getLogger(__name__)
    conn = engine.connect()
    logger.debug(f"Authorize called with enterprise_id: {enterprise_id}, team_id: {team_id}, user_id: {user_id}")
    try:
        stmt = select(tokens_table.c.access_token, tokens_table.c.bot_token).where(tokens_table.c.team_id == team_id)
        result = conn.execute(stmt).fetchone()
        if result:
            access_token, bot_token = result
        else:
            access_token = bot_token = None
    except Exception as e:
        logger.error(f"Error querying token in authorize function: {e}")
        conn.close()
        return None

    conn.close()

    if not bot_token:
        logger.error(f"Bot token not found for team_id: {team_id} in authorize function")
        return None

    logger.debug(f"Tokens found for team_id: {team_id} in authorize function: access_token: {access_token}, bot_token: {bot_token}")
    return AuthorizeResult(
        enterprise_id=enterprise_id,
        team_id=team_id,
        bot_token=bot_token,
        user_token=access_token
    )