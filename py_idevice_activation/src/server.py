import os
import logging
import datetime
import base64 # For parsing activation-info from multipart
import plistlib # For parsing activation-info from multipart

from flask import Flask, request, Response, jsonify, make_response, render_template_string
from werkzeug.exceptions import BadRequest, InternalServerError, MethodNotAllowed

from .config import Config
from .database import init_db_schema, get_db_connection, close_db_connection, query_db
from .activation_generator import ActivationGenerator, ActivationGeneratorException

# --- Flask App Setup ---
app = Flask(__name__, template_folder=Config.TEMPLATES_FOLDER, static_folder=Config.STATIC_FOLDER)
app.config.from_object(Config)

# --- Logging Setup ---
logging.basicConfig(level=logging.INFO if Config.DEBUG else logging.WARNING)
logger = logging.getLogger(__name__)

# --- Initialize Database Schema ---
# This should ideally be a CLI command like 'flask init-db'
# For simplicity in this environment, we'll call it once on startup.
# A better approach in production would be to ensure this is run as part of deployment.
with app.app_context(): # Ensure we are in app context for config loading etc.
    try:
        # Check if DB file exists, if not, then init. Or check if table exists.
        # A simple way: try to init anyway, it's idempotent.
        logger.info("Attempting to initialize database schema on startup...")
        init_db_schema()
    except Exception as e:
        logger.error(f"Failed to initialize database on startup: {e}", exc_info=True)
        # Depending on the severity, you might want to exit the app
        # For now, we'll let it continue and it might fail on DB operations.

# --- Helper Functions ---
def send_json_error(http_code: int, message: str, log_message: str = None):
    """Sends a JSON error response and logs the error."""
    actual_log_message = log_message if log_message else message
    logger.error(f"HTTP {http_code}: {actual_log_message}")
    response = jsonify(error=message)
    response.status_code = http_code
    return response

# --- Routes ---
@app.route('/', methods=['GET', 'POST'])
def handle_activation_request():
    if request.method == 'POST':
        try:
            raw_body = request.get_data() # Get raw body bytes
            if not raw_body:
                return send_json_error(400, 'Request body is empty.')

            final_request_plist_bytes = raw_body
            content_type = request.content_type if request.content_type else ''

            # Handle multipart form data (like from some desktop tools)
            if 'multipart/form-data' in content_type:
                if 'activation-info' not in request.form:
                    return send_json_error(400, 'Multipart request missing "activation-info" part.')

                # The 'activation-info' part in PHP's example is an XML Plist containing
                # a base64 encoded string which is the *actual* device activation plist.
                activation_info_xml_str = request.form['activation-info']
                try:
                    # Parse the outer XML plist
                    outer_plist = plistlib.loads(activation_info_xml_str.encode('utf-8'))
                    if 'ActivationInfoXML' not in outer_plist:
                        return send_json_error(400, 'Could not find ActivationInfoXML data in activation-info part.')

                    # Decode the inner base64'd plist
                    encoded_inner_plist = outer_plist['ActivationInfoXML']
                    # Ensure it's bytes for b64decode, then decode again if it was bytes->str
                    if isinstance(encoded_inner_plist, str):
                        encoded_inner_plist = encoded_inner_plist.encode('ascii') # Base64 is ASCII

                    final_request_plist_bytes = base64.b64decode(encoded_inner_plist)
                    if not final_request_plist_bytes: # Should not happen if b64decode succeeds
                         return send_json_error(400, 'Failed to Base64-decode the ActivationInfoXML content (empty result).')
                except (plistlib.InvalidFileException, ValueError, TypeError, base64.binascii.Error) as e:
                    return send_json_error(400, f'Could not parse or decode XML/Base64 from activation-info part: {e}')

            # At this point, final_request_plist_bytes contains the actual device request plist

            # Initialize ActivationGenerator
            try:
                generator = ActivationGenerator(final_request_plist_bytes)
                device_info = generator.get_device_info()
            except ActivationGeneratorException as e:
                logger.error(f"ActivationGeneratorException: {e}", exc_info=True)
                # Provide a less detailed error to the client for security
                return send_json_error(400, f'Error processing activation request: Invalid device data.')
            except Exception as e: # Catch any other unexpected errors from generator
                logger.error(f"Unexpected error in ActivationGenerator: {e}", exc_info=True)
                return send_json_error(500, 'Internal server error during activation data generation.')


            udid = device_info.get('UniqueDeviceID')
            if not udid: # Should be caught by ActivationGenerator, but double check
                return send_json_error(400, 'UniqueDeviceID not found in processed device info.')

            conn = get_db_connection()
            try:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM devices WHERE udid = ?", (udid,))
                device_record = cursor.fetchone()

                current_time_str = datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S')

                if not device_record:
                    logger.info(f"New device seen: UDID {udid}")
                    cursor.execute("""
                        INSERT INTO devices (udid, serial_number, imei, product_type, last_activation_attempt_timestamp)
                        VALUES (?, ?, ?, ?, ?)
                    """, (
                        udid,
                        device_info.get('SerialNumber'),
                        device_info.get('InternationalMobileEquipmentIdentity'),
                        device_info.get('ProductType'),
                        current_time_str
                    ))
                    conn.commit()
                    # Re-fetch to get the full record including ID and defaults
                    cursor.execute("SELECT * FROM devices WHERE udid = ?", (udid,))
                    device_record = cursor.fetchone()
                else:
                    logger.info(f"Existing device seen: UDID {udid}")
                    cursor.execute("UPDATE devices SET last_activation_attempt_timestamp = ? WHERE udid = ?", (current_time_str, udid))
                    conn.commit()

                if not device_record: # Should not happen if insert/select logic is correct
                    logger.error(f"Failed to fetch/create device record for UDID {udid}")
                    return send_json_error(500, "Database error: Could not retrieve device record.")

                # Check Simulated Lock Status
                if device_record['is_simulated_locked'] == 1:
                    lock_message = device_record['simulated_lock_message'] if device_record['simulated_lock_message'] else 'This device is SIMULATED as locked.'
                    # Using f-string for simplicity, consider Jinja2 for more complex HTML
                    sim_lock_html = f"""<!DOCTYPE html><html><head><title>Simulated Activation Lock</title><style>body{{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;text-align:center;padding:50px 20px;color:#1d1d1f;background-color:#f5f5f7;}}.container{{max-width:400px;margin:0 auto;}}.lock-icon{{font-size:48px;}}.message{{margin-top:20px;font-size:22px;font-weight:600;}}.sub-message{{font-size:14px;color:#6e6e73;margin-top:12px;}}</style></head>
                    <body><div class="container"><div class="lock-icon">🔒</div><h1 class="message">Activation Lock Simulation</h1><p class="sub-message">{lock_message}</p><p class="sub-message"><small>This is a local simulation and does not reflect real Apple Activation Lock status.</small></p></div></body></html>"""
                    return Response(sim_lock_html, mimetype='text/html; charset=utf-8')

                # Generate Activation Record
                try:
                    activation_record_xml_bytes = generator.generate_activation_record()
                except Exception as e: # Catch errors during final record generation
                    logger.error(f"Error during generate_activation_record: {e}", exc_info=True)
                    # This might be the FairPlayKeyData issue if it persists
                    return send_json_error(500, f'Internal server error generating activation record. Possible data issue: {str(e)[:100]}')


                # Store the generated record for auditing
                cursor.execute("UPDATE devices SET activation_record_xml = ? WHERE udid = ?", (activation_record_xml_bytes.decode('utf-8'), udid))
                conn.commit()

                # Output the standard iTunes response HTML
                # The plist content must be exactly as generated, not HTML escaped.
                # The PHP script puts the raw XML into the script tag.
                itunes_response_html = f"""<!DOCTYPE html>
                <html><head><meta http-equiv="Content-Type" content="text/html; charset=utf-8" /><title>iPhone Activation</title>
                <script id="protocol" type="text/x-apple-plist">{activation_record_xml_bytes.decode('utf-8')}</script>
                <script>
                    document.addEventListener('DOMContentLoaded', function() {{
                        try {{
                            var protocolElement = document.getElementById("protocol");
                            var protocolContent = protocolElement.textContent || protocolElement.innerText;
                            if (window.iTunes && typeof window.iTunes.addProtocol === 'function') {{
                                window.iTunes.addProtocol(protocolContent);
                            }} else {{ console.warn("iTunes protocol handler not found."); }}
                        }} catch (e) {{ console.error("Error with iTunes protocol handler:", e); }}
                    }});
                </script></head><body></body></html>"""
                return Response(itunes_response_html, mimetype='text/html; charset=utf-8')

            except sqlite3.Error as db_err:
                logger.error(f"Database operation failed: {db_err}", exc_info=True)
                if conn: conn.rollback()
                return send_json_error(500, "A database error occurred.")
            finally:
                if conn: close_db_connection(conn)

        except BadRequest as e: # Explicitly catch Werkzeug's BadRequest
            return send_json_error(e.code, e.description)
        except Exception as e: # Catch-all for unexpected errors in the POST block
            logger.error(f"Unhandled error in POST request: {e}", exc_info=True)
            return send_json_error(500, "An unexpected error occurred during POST processing.")

    elif request.method == 'GET':
        # Simple GET response as in PHP
        get_response_html = """<h1>Activation Server 2.0 (Python/Flask Simulated)</h1>
        <p>This script expects a POST request with iDevice activation data.</p>
        <p>For educational purposes only. This system uses a local database to <strong>simulate</strong> a server-side device lock.</p>
        <p>See <code>/manage</code> endpoint for device management (if implemented).</p>"""
        return Response(get_response_html, mimetype='text/html; charset=utf-8')
    else:
        # Should not be reached if methods=['GET', 'POST'] is respected by Flask
        # However, Flask maps HEAD to GET by default, so this might not be strictly necessary
        # if only GET/POST are defined. For clarity, keeping it.
        logger.warning(f"Received unhandled method: {request.method} on /")
        # Let Flask's default 405 handler trigger via raising MethodNotAllowed
        # or ensure the app.route decorator correctly limits methods.
        # If methods=['GET', 'POST'] is set, Flask handles this.
        # This line is more of a safeguard if method list was broader.
        return send_json_error(405, "Method Not Allowed on this endpoint.")


@app.route('/manage', methods=['GET', 'POST'])
def manage_devices():
    message = None
    error_message = None
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        if request.method == 'POST':
            action = request.form.get('action')
            device_id = request.form.get('id', type=int)

            if action == 'toggle_lock' and device_id is not None:
                cursor.execute("SELECT is_simulated_locked FROM devices WHERE id = ?", (device_id,))
                current_device = cursor.fetchone()

                if current_device:
                    new_status = 0 if current_device['is_simulated_locked'] == 1 else 1
                    lock_msg_text = "This device was locked by the administrator." if new_status == 1 else None

                    cursor.execute("UPDATE devices SET is_simulated_locked = ?, simulated_lock_message = ? WHERE id = ?",
                                   (new_status, lock_msg_text, device_id))
                    conn.commit()
                    logger.info(f"Toggled lock status for device ID {device_id} to {'LOCKED' if new_status == 1 else 'UNLOCKED'}.")
                    message = f"Device ID {device_id} lock status updated." # Using a general message variable
                else:
                    logger.warning(f"Attempted to toggle lock for non-existent device ID {device_id}.")
                    error_message = f"Device ID {device_id} not found."
            else:
                logger.warning(f"Invalid POST action ('{action}') or missing device ID ('{device_id}') for /manage.")
                error_message = "Invalid action or missing device ID."

        # Fetch all devices for GET request or after POST action
        cursor.execute("SELECT * FROM devices ORDER BY last_activation_attempt_timestamp DESC")
        devices = cursor.fetchall() # Will be list of sqlite3.Row objects

        # Convert sqlite3.Row objects to dictionaries for easier template access if needed,
        # though Flask/Jinja2 can often handle Row objects directly.
        # For consistency with query_db or if complex manipulation is needed:
        devices_list = [dict(row) for row in devices]

        return render_template_string(
            app.jinja_env.get_template('manage_devices.html').render(
                devices=devices_list,
                message=message,
                error_message=error_message
            )
        )
    except sqlite3.Error as db_err:
        logger.error(f"Database error in /manage: {db_err}", exc_info=True)
        if conn: conn.rollback()
        # Render the page with an error if possible, or a generic error page
        return render_template_string(
             app.jinja_env.get_template('manage_devices.html').render(
                devices=[],
                error_message="A database error occurred while managing devices."
            )
        ) # Fallback rendering
    except Exception as e:
        logger.error(f"Error in /manage: {e}", exc_info=True)
        return render_template_string(
             app.jinja_env.get_template('manage_devices.html').render(
                devices=[],
                error_message="An unexpected error occurred."
            )
        ) # Fallback rendering
    finally:
        if conn: close_db_connection(conn)


# --- Error Handlers for Flask ---
@app.errorhandler(400) # BadRequest
@app.errorhandler(404) # NotFound
@app.errorhandler(405) # MethodNotAllowed
@app.errorhandler(500) # InternalServerError
def handle_werkzeug_errors(e):
    """Handle common HTTP errors by sending a JSON response if API-like, or HTML error page."""
    log_message = f"Werkzeug HTTP Error: {e.name} ({e.code}). Path: {request.path}. Description: {e.description}"

    # For 500 errors, log the original exception if available
    original_exc_info = None
    if hasattr(e, 'original_exception') and e.original_exception:
        original_exc_info = e.original_exception

    # Check if the request path suggests an API endpoint or a user-facing page
    if request.path.startswith('/api/') or "application/json" in request.accept_mimetypes: # crude check
        logger.error(log_message, exc_info=original_exc_info if original_exc_info else e)
        response = jsonify(error=e.description, code=e.code if hasattr(e, 'code') else 500)
        response.status_code = e.code if hasattr(e, 'code') else 500
        return response
    else:
        # For non-API routes, render a user-friendly HTML error page
        # You would create a generic error.html template for this
        logger.error(log_message, exc_info=original_exc_info if original_exc_info else e)
        # Simple HTML error response for now
        error_page_html = f"<html><head><title>{e.name}</title></head><body><h1>Error {e.code if hasattr(e, 'code') else 'Unknown'}: {e.name}</h1><p>{e.description}</p></body></html>"
        return Response(error_page_html, status=e.code if hasattr(e, 'code') else 500, mimetype='text/html')


@app.errorhandler(Exception)
def handle_generic_exception(e):
    """Handle any other unhandled exceptions."""
    # Log with full traceback
    logger.error(f"Unhandled Server Exception: {str(e)} on path {request.path}", exc_info=e)

    if request.path.startswith('/api/') or "application/json" in request.accept_mimetypes: # crude check
        response = jsonify(error="An unexpected internal server error occurred.", code=500)
        response.status_code = 500
        return response
    else:
        error_page_html = f"<html><head><title>Internal Server Error</title></head><body><h1>Error 500: Internal Server Error</h1><p>An unexpected error occurred. Please try again later.</p></body></html>"
        return Response(error_page_html, status=500, mimetype='text/html')


# --- Main Execution ---
if __name__ == '__main__':
    # Note: For development, Flask's built-in server is fine.
    # For production, use a proper WSGI server like Gunicorn or uWSGI.
    # The host '0.0.0.0' makes it accessible from network, useful for testing with actual devices or VMs.
    # Flask's default port is 5000.
    logger.info(f"Starting Flask app on http://0.0.0.0:5000 (Debug: {app.config.get('DEBUG', False)})")
    # Use app.config for debug for consistency
    app.run(host='0.0.0.0', port=5000, debug=app.config.get('DEBUG', False))
