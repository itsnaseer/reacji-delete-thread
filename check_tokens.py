import os
from sqlalchemy import create_engine, Table, Column, String, MetaData, select
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")
engine = create_engine(DATABASE_URL)
metadata = MetaData()

tokens_table = Table('tokens', metadata,
    Column('team_id', String, primary_key=True),
    Column('user_id', String),
    Column('access_token', String),
    Column('bot_token', String, nullable=False),  
    Column('created_at', String),
    Column('updated_at', String)
)

metadata.create_all(engine)

def get_all_tokens():
    with engine.connect() as connection:
        query = select([tokens_table])
        result = connection.execute(query).fetchall()
        return result

if __name__ == "__main__":
    tokens = get_all_tokens()
    for token in tokens:
        print(f"Team ID: {token['team_id']}, User ID: {token['user_id']}, Access Token: {token['access_token']}, Created At: {token['created_at']}, Updated At: {token['updated_at']}")
