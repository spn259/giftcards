from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, scoped_session
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()

class PostgresDB:
    def __init__(self, username, password, host, port, database, sslmode='require', sslrootcert=None, sslcert=None, sslkey=None):
        # Construct the database URL
        self.database_url = f"postgresql://{username}:{password}@{host}:{port}/{database}?sslmode={sslmode}"

        # Append SSL parameters if provided
        if sslrootcert:
            self.database_url += f"&sslrootcert={sslrootcert}"
        if sslcert:
            self.database_url += f"&sslcert={sslcert}"
        if sslkey:
            self.database_url += f"&sslkey={sslkey}"

        # Create the engine
        self.engine = create_engine(self.database_url, echo=True)  # Echo logs SQL queries to the console
        self.Session = scoped_session(sessionmaker(bind=self.engine))
        self.session = self.Session()

    def create_tables(self):
        """Creates database tables based on the models defined."""
        Base.metadata.create_all(self.engine)

    def commit_session(self):
        """Commits the current transaction."""
        try:
            self.session.commit()
        except Exception as e:
            self.session.rollback()  # Rollback in case of error
            raise e

    def close_session(self):
        """Closes the session."""
        self.session.close()

# # Example usage
# if __name__ == '__main__':
#     db = PostgresDB(
#         username="your_user",
#         password="your_pass",
#         host="localhost",
#         port=5432,
#         database="your_db",
#         sslmode="require",
#         sslrootcert="/path/to/root.crt",  # optional
#         sslcert="/path/to/client.crt",    # optional, required if client-side certificates are needed
#         sslkey="/path/to/client.key"      # optional, required if client-side certificates are needed
#     )
