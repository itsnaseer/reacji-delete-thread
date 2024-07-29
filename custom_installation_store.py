from slack_sdk.oauth.installation_store.sqlalchemy import SQLAlchemyInstallationStore
from sqlalchemy import Table, MetaData, Column, String, select
import time

class CustomInstallationStore(SQLAlchemyInstallationStore):
    def __init__(self, client_id, engine, logger):
        self.client_id = client_id
        self.engine = engine
        self._logger = logger
        self.metadata = MetaData()
        self.tokens_table = Table(
            'tokens',
            self.metadata,
            Column('enterprise_id', String, nullable=True),
            Column('team_id', String, nullable=False),
            Column('user_id', String, primary_key=True, nullable=False),
            Column('access_token', String, nullable=False),
            Column('bot_token', String, nullable=False),
            Column('created_at', String, nullable=False),
            Column('updated_at', String, nullable=False)
        )

    @property
    def logger(self):
        return self._logger

    def save(self, installation):
        with self.engine.connect() as conn:
            stmt = self.tokens_table.insert().values(
                enterprise_id=installation.enterprise_id,
                team_id=installation.team_id,
                user_id=installation.user_id,
                access_token=installation.user_token,
                bot_token=installation.bot_token,
                created_at=str(time.time()),
                updated_at=str(time.time())
            )
            conn.execute(stmt)
        return installation

    def find_installation(self, enterprise_id, team_id, is_enterprise_install):
        with self.engine.connect() as conn:
            stmt = select(
                self.tokens_table.c.enterprise_id,
                self.tokens_table.c.team_id,
                self.tokens_table.c.user_id,
                self.tokens_table.c.access_token,
                self.tokens_table.c.bot_token
            ).where(
                (self.tokens_table.c.enterprise_id == enterprise_id) &
                (self.tokens_table.c.team_id == team_id)
            )
            result = conn.execute(stmt).fetchone()
        if result:
            return {
                "enterprise_id": result.enterprise_id,
                "team_id": result.team_id,
                "user_id": result.user_id,
                "access_token": result.access_token,
                "bot_token": result.bot_token
            }
        return None

class Installation:
    def __init__(self, enterprise_id, team_id, user_id, access_token, bot_token):
        self.enterprise_id = enterprise_id
        self.team_id = team_id
        self.user_id = user_id
        self.access_token = access_token
        self.bot_token = bot_token