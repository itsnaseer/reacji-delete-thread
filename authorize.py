from sqlalchemy import select

def authorize_function(enterprise_id, team_id, user_id, engine, tokens_table):
    conn = engine.connect()
    try:
        stmt = select(tokens_table.c.access_token, tokens_table.c.bot_token).where(tokens_table.c.team_id == team_id)
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
        raise Exception(f"Bot token not found for team_id: {team_id}")

    return {
        "enterprise_id": enterprise_id,
        "team_id": team_id,
        "bot_token": bot_token,
        "user_token": access_token
    }