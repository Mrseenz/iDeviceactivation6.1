import os

class Config:
    # Determine the absolute path for the database file
    # Assuming this script is in py_idevice_activation/src, data/ is one level up then down.
    BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
    DATABASE_FILE = os.path.join(BASE_DIR, 'data', 'activation_simulator.sqlite')
    DEBUG = True # Set to False in production
    SECRET_KEY = os.urandom(24) # For Flask session management, if needed later
    TEMPLATES_FOLDER = os.path.join(BASE_DIR, 'templates')
    STATIC_FOLDER = os.path.join(BASE_DIR, 'static')

# Example: print(Config.DATABASE_FILE) would show the absolute path
# Ensure the 'data' directory exists at the root of the 'py_idevice_activation' project.
