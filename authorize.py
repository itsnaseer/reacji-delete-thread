from sqlalchemy import select
import logging

logger = logging.getLogger(__name__)

def authorize_function(enterprise_id, team_id, user_id, engine, tokens_table):
    logger.debug(f"authorize_function called with enterprise_id: {enterprise_id}, team_id: {team_id}, user_id: {user_id}")
    if not team_id and not enterprise_id:
        raise Exception("Both team_id and enterprise_id are None in authorize_function")

    conn = engine.connect()
    try:
        # Select based on both team_id and enterprise_id
        stmt = select(tokens_table.c.access_token, tokens_table.c.bot_token).where(
            (tokens_table.c.team_id == team_id) | (tokens_table.c.enterprise_id == enterprise_id)
        )
        result = conn.execute(stmt).fetchone()
        if result:
            access_token, bot_token = result
        else:
            access_token = bot_token = None
    except Exception as e:
        conn.close()
        raise e

    conn.close()

    if not bot_token:
        raise Exception(f"Bot token not found for team_id: {team_id} and enterprise_id: {enterprise_id}")

    return {
        "enterprise_id": enterprise_id,
        "team_id": team_id,
        "bot_token": bot_token,
        "user_token": access_token
    }