import logging
from sqlalchemy import Table, Column, String, MetaData, select
from sqlalchemy.orm import sessionmaker
from slack_sdk.oauth.installation_store import InstallationStore, Bot, Installation

class CustomInstallationStore(InstallationStore):
    def __init__(self, client_id, engine, logger=None):
        self.client_id = client_id
        self.engine = engine
        self.metadata = MetaData()
        self.installations = Table(
            'tokens', self.metadata,
            Column('enterprise_id', String),
            Column('team_id', String, nullable=False),
            Column('user_id', String, primary_key=True, nullable=False),
            Column('access_token', String, nullable=False),
            Column('bot_token', String, nullable=False),
        )
        self.sessionmaker = sessionmaker(bind=engine)
        self.logger = logger or logging.getLogger(__name__)

    def save(self, installation: Installation):
        with self.engine.connect() as connection:
            stmt = self.installations.insert().values(
                enterprise_id=installation.enterprise_id,
                team_id=installation.team_id,
                user_id=installation.user_id,
                access_token=installation.user_token,
                bot_token=installation.bot_token,
            )
            connection.execute(stmt)

    def find_installation(self, *, enterprise_id, team_id, user_id, is_enterprise_install, user_token, bot_token):
        with self.engine.connect() as connection:
            stmt = select([
                self.installations.c.enterprise_id,
                self.installations.c.team_id,
                self.installations.c.user_id,
                self.installations.c.access_token,
                self.installations.c.bot_token
            ]).where(
                self.installations.c.enterprise_id == enterprise_id,
                self.installations.c.team_id == team_id
            )
            result = connection.execute(stmt).fetchone()
            if result:
                return Installation(
                    enterprise_id=result.enterprise_id,
                    team_id=result.team_id,
                    user_id=result.user_id,
                    user_token=result.access_token,
                    bot_token=result.bot_token
                )
            return None

    def find_bot(self, *, enterprise_id, team_id):
        with self.engine.connect() as connection:
            stmt = select([
                self.installations.c.enterprise_id,
                self.installations.c.team_id,
                self.installations.c.bot_token
            ]).where(
                self.installations.c.enterprise_id == enterprise_id,
                self.installations.c.team_id == team_id
            )
            result = connection.execute(stmt).fetchone()
            if result:
                return Bot(
                    enterprise_id=result.enterprise_id,
                    team_id=result.team_id,
                    bot_token=result.bot_token
                )
            return None