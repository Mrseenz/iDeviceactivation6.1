import sqlite3
import logging # For better error logging
from flask import g # For managing DB connection per request if needed, though simpler for now

# Get configuration
# Assuming config.py is in the same directory or src.config can be imported
from .config import Config

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def get_db_connection() -> sqlite3.Connection:
    """
    Establishes a new database connection.
    The connection object does not manage transactions automatically by default (unless isolation_level=None).
    sqlite3.PARSE_DECLTYPES allows parsing of declared types from table schema.
    sqlite3.PARSE_COLNAMES allows access to columns by name.
    """
    try:
        conn = sqlite3.connect(Config.DATABASE_FILE, detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES)
        conn.row_factory = sqlite3.Row # Access columns by name
        logger.info(f"Database connection established to {Config.DATABASE_FILE}")
        return conn
    except sqlite3.Error as e:
        logger.error(f"Database connection error to {Config.DATABASE_FILE}: {e}", exc_info=True)
        raise # Re-raise the exception to be handled by the caller or Flask error handler

def close_db_connection(conn: sqlite3.Connection = None, e=None):
    """Closes the database connection."""
    # This function might be registered with Flask's app.teardown_appcontext
    # For now, we'll manage connections explicitly in routes or rely on 'with' statements.
    if conn is not None:
        conn.close()
        logger.info("Database connection closed.")

def init_db_schema():
    """Initializes the database schema if the tables do not exist."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                udid TEXT UNIQUE NOT NULL,
                serial_number TEXT,
                imei TEXT,
                product_type TEXT,
                is_simulated_locked INTEGER NOT NULL DEFAULT 0,
                simulated_lock_message TEXT,
                activation_record_xml TEXT,
                notes TEXT,
                first_seen_timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                last_activation_attempt_timestamp DATETIME
            )
        """)

        cursor.execute("CREATE INDEX IF NOT EXISTS idx_devices_udid ON devices (udid)")

        conn.commit()
        logger.info("Database schema initialized successfully.")
    except sqlite3.Error as e:
        logger.error(f"Error initializing database schema: {e}", exc_info=True)
        # In a real app, you might want to handle this more gracefully,
        # e.g., by exiting if the DB can't be initialized.
        if conn: # Rollback if error occurred during transaction
            conn.rollback()
    finally:
        if conn:
            close_db_connection(conn)

def query_db(query: str, args=(), one=False):
    """Helper function to query the database and return results."""
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.execute(query, args)
        rv = [dict(row) for row in cur.fetchall()] # Convert sqlite3.Row to dict
        cur.close()
        conn.commit() # Commit any changes if the query was an INSERT/UPDATE/DELETE
        return (rv[0] if rv else None) if one else rv
    except sqlite3.Error as e:
        logger.error(f"Database query error: {e}\nQuery: {query}\nArgs: {args}", exc_info=True)
        if conn:
            conn.rollback() # Rollback on error
        # Depending on app structure, might re-raise or return None/empty
        return None
    finally:
        if conn:
            close_db_connection(conn)

# Example of how to use in Flask app (to be done in server.py):
# from flask import current_app, g
# def get_db_for_flask():
#     if 'db' not in g:
#         g.db = sqlite3.connect(
#             current_app.config['DATABASE_FILE'],
#             detect_types=sqlite3.PARSE_DECLTYPES
#         )
#         g.db.row_factory = sqlite3.Row
#     return g.db

# def close_db_for_flask(e=None):
#     db = g.pop('db', None)
#     if db is not None:
#         db.close()

# def init_app(app):
#     app.teardown_appcontext(close_db_for_flask)
#     # Add a command to init DB from CLI: flask init-db
#     # app.cli.add_command(init_db_command)

if __name__ == '__main__':
    # This allows running `python src/database.py` to initialize the DB.
    print("Initializing database schema...")
    init_db_schema()
    print("Database schema initialization attempt complete. Check logs for details.")

    # Example test query (optional)
    # print("\nAttempting to query devices (should be empty or show existing):")
    # devices = query_db("SELECT * FROM devices")
    # if devices is not None:
    #     if not devices:
    #         print("No devices found (as expected for a new DB).")
    #     else:
    #         print(f"Found {len(devices)} devices:")
    #         for device in devices:
    #             print(device)
    # else:
    #     print("Failed to query devices.")
