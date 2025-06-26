# Python iDevice Activation Server Simulator

This project is a Python-based simulator for an iDevice activation server, ported from an original PHP implementation. It aims to replicate the process of generating activation records for iDevices and includes a simulated device management interface.

**This server CANNOT and DOES NOT bypass real Apple Activation Lock.** It is for educational and testing purposes only, to understand the activation handshake and simulate server-side device state management.

## Features

*   Generates cryptographically valid (simulated) iDevice activation records.
*   Handles device activation requests (raw plist or multipart form).
*   Simulates a server-side device lock via a local SQLite database.
*   Provides a web interface to manage simulated device lock status.
*   Built with Python and Flask.

## Project Structure

```
py_idevice_activation/
├── data/
│   └── activation_simulator.sqlite   # SQLite database for device info and lock status
├── src/
│   ├── __init__.py
│   ├── activation_generator.py       # Core logic for generating activation records
│   ├── config.py                     # Configuration settings (e.g., database path)
│   ├── database.py                   # Database connection and schema initialization
│   └── server.py                     # Flask web server application (handles requests)
├── templates/
│   └── manage_devices.html           # HTML template for the device management page
├── requirements.txt                  # Python dependencies
└── README.md                         # This file
```

## Setup and Installation

1.  **Clone the repository (if applicable) or ensure you have the files.**

2.  **Create a Python virtual environment (recommended):**
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows: venv\Scripts\activate
    ```

3.  **Install dependencies:**
    Navigate to the `py_idevice_activation` directory (if not already there) and run:
    ```bash
    pip install -r requirements.txt
    ```
    This will install Flask and Cryptography.

4.  **Initialize the database:**
    From the `py_idevice_activation` directory, run:
    ```bash
    python -m src.database
    ```
    This will create the `data/activation_simulator.sqlite` file and set up the necessary tables. You should see log messages indicating success.

## Running the Server

1.  **Navigate to the `py_idevice_activation` directory.**

2.  **Set the `FLASK_APP` environment variable:**
    ```bash
    export FLASK_APP=src.server  # On Linux/macOS
    # set FLASK_APP=src.server    # On Windows CMD
    # $env:FLASK_APP="src.server" # On Windows PowerShell
    ```

3.  **Run the Flask development server:**
    ```bash
    flask run --host=0.0.0.0 --port=5000
    ```
    The server will start, typically on `http://0.0.0.0:5000/`. You should see log output from Flask. The database will also be initialized on startup if it hasn't been already.

## Usage

*   **Activation Endpoint (`/`):**
    *   `GET /`: Displays a simple status message.
    *   `POST /`: Expects iDevice activation data.
        *   Can be a raw POST body containing the device's activation request plist (XML).
        *   Can also be `multipart/form-data` with a field named `activation-info`. This field should contain an XML Plist, which itself has a key `ActivationInfoXML` whose value is a base64-encoded string of the actual device activation request plist.
    *   If successful (and device is not simulated as locked), it returns an HTML page with the activation record in an `text/x-apple-plist` script tag, similar to how iTunes expects it.
    *   If the device is marked as "simulated locked" in the database, it returns an HTML page indicating this.

*   **Device Management Endpoint (`/manage`):**
    *   `GET /manage`: Displays a web page listing all devices that have contacted the server. From here, you can see their simulated lock status and toggle it.
    *   `POST /manage`: Used by the forms on the management page to toggle the lock status of a device.