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
            Column('team_id', String),
            Column('access_token', String, nullable=False),
            Column('user_id', String, primary_key=True, nullable=False),
            Column('created_at', String),
            Column('updated_at', String),
            Column('bot_token', String),
            Column('enterprise_id', String),
            Column('id_type', String, nullable=False)  # New column
        )
        self.sessionmaker = sessionmaker(bind=engine)
        self._logger = logger or logging.getLogger(__name__)

    @property
    def logger(self):
        return self._logger

    def save(self, installation: Installation):
        id_value = installation.enterprise_id if installation.enterprise_id else installation.team_id
        id_type = 'enterprise_id' if installation.enterprise_id else 'team_id'
        with self.engine.connect() as connection:
            stmt = self.installations.insert().values(
                team_id=installation.team_id,
                access_token=installation.user_token,
                user_id=installation.user_id,
                created_at=installation.created_at,
                updated_at=installation.updated_at,
                bot_token=installation.bot_token,
                enterprise_id=installation.enterprise_id,
                id_type=id_type
            )
            connection.execute(stmt)

    def find_installation(self, *, enterprise_id=None, team_id=None, user_id=None, is_enterprise_install=None):
        id_value = enterprise_id if enterprise_id else team_id
        id_type = 'enterprise_id' if enterprise_id else 'team_id'
        with self.engine.connect() as connection:
            query = select(
                self.installations.c.team_id,
                self.installations.c.user_id,
                self.installations.c.access_token,
                self.installations.c.bot_token
            ).where(
                (self.installations.c.enterprise_id == id_value if id_type == 'enterprise_id' else self.installations.c.team_id == id_value)
            )
            if user_id:
                query = query.where(self.installations.c.user_id == user_id)

            result = connection.execute(query).fetchone()
            if result:
                return Installation(
                    enterprise_id=result.enterprise_id if id_type == 'enterprise_id' else None,
                    team_id=result.team_id,
                    user_id=result.user_id,
                    user_token=result.access_token,
                    bot_token=result.bot_token
                )
            return None

    def find_bot(self, *, enterprise_id=None, team_id=None, is_enterprise_install=None):
        id_value = enterprise_id if enterprise_id else team_id
        id_type = 'enterprise_id' if enterprise_id else 'team_id'
        with self.engine.connect() as connection:
            query = select(
                self.installations.c.team_id,
                self.installations.c.bot_token
            ).where(
                (self.installations.c.enterprise_id == id_value if id_type == 'enterprise_id' else self.installations.c.team_id == id_value)
            )
            result = connection.execute(query).fetchone()
            if result:
                return Bot(
                    enterprise_id=result.enterprise_id if id_type == 'enterprise_id' else None,
                    team_id=result.team_id,
                    bot_token=result.bot_token
                )
            return None