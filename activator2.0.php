<?php
declare(strict_types=1);

// This script simulates a stateful activation server with a local database
// to demonstrate how a server-side lock could function.
// It DOES NOT and CANNOT bypass real Apple Activation Lock.

require_once __DIR__ . '/ActivationGenerator.php';

// --- Database Configuration and Functions ---
// For better security, place the database file outside the web-accessible directory if possible.
// Example: define('DB_FILE', dirname(__DIR__) . '/database/activation_simulator.sqlite');
define('DB_FILE', __DIR__ . '/activation_simulator.sqlite');

function get_db_connection(): PDO
{
    static $pdo = null;
    if ($pdo === null) {
        try {
            // Use a persistent connection if the server environment supports it well
            $pdo = new PDO('sqlite:' . DB_FILE, null, null, [PDO::ATTR_PERSISTENT => true]);
            $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            $pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
        } catch (PDOException $e) {
            send_json_error(500, 'Database service is unavailable.', "DB Connection Error: " . $e->getMessage());
        }
    }
    return $pdo;
}

function init_db(): void
{
    $pdo = get_db_connection();
    $pdo->exec("
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
    ");
    $pdo->exec("CREATE INDEX IF NOT EXISTS idx_devices_udid ON devices (udid)");
}

/**
 * Sends a JSON error response and terminates the script.
 */
function send_json_error(int $httpCode, string $message, ?string $logMessage = null): void {
    http_response_code($httpCode);
    header('Content-Type: application/json; charset=utf-8');
    error_log($logMessage ?? $message);
    echo json_encode(['error' => $message]);
    exit;
}

// --- Main Script Execution ---

$requestMethod = $_SERVER['REQUEST_METHOD'] ?? 'GET';

if ($requestMethod === 'POST') {
    try {
        init_db();
        $pdo = get_db_connection();

        // 1. Get and Parse the Request Plist
        $contentType = $_SERVER['CONTENT_TYPE'] ?? '';
        $rawBody = file_get_contents('php://input');
        if (empty($rawBody)) {
            send_json_error(400, 'Request body is empty.');
        }

        $finalRequestPlist = $rawBody;
        if (stripos($contentType, 'multipart/form-data') !== false) {
            if (!isset($_POST['activation-info'])) {
                send_json_error(400, 'Multipart request missing "activation-info" part.');
            }
            libxml_use_internal_errors(true);
            $xml = simplexml_load_string($_POST['activation-info']);
            if (!$xml || !isset($xml->dict->key)) {
                 send_json_error(400, 'Could not parse XML from activation-info part.');
            }
            $keyIndex = array_search('ActivationInfoXML', (array)$xml->dict->key);
            if ($keyIndex === false || !isset($xml->dict->data[$keyIndex])) {
                 send_json_error(400, 'Could not find ActivationInfoXML data in activation-info part.');
            }
            $decodedPlist = base64_decode((string)$xml->dict->data[$keyIndex], true);
            if (!$decodedPlist) {
                send_json_error(400, 'Failed to Base64-decode the ActivationInfoXML content.');
            }
            $finalRequestPlist = $decodedPlist;
        }

        // 2. Get Device Identifiers and Check Database
        $generator = new ActivationGenerator($finalRequestPlist);
        $deviceInfo = $generator->getDeviceInfo();
        $udid = $deviceInfo['UniqueDeviceID'];
        
        $stmt = $pdo->prepare("SELECT * FROM devices WHERE udid = :udid");
        $stmt->execute(['udid' => $udid]);
        $deviceRecord = $stmt->fetch();

        $currentTime = date('Y-m-d H:i:s');

        if (!$deviceRecord) {
            $stmt = $pdo->prepare("INSERT INTO devices (udid, serial_number, imei, product_type, last_activation_attempt_timestamp) VALUES (:udid, :serial_number, :imei, :product_type, :now)");
            $stmt->execute([
                'udid' => $udid,
                'serial_number' => $deviceInfo['SerialNumber'],
                'imei' => $deviceInfo['InternationalMobileEquipmentIdentity'] ?? null,
                'product_type' => $deviceInfo['ProductType'],
                'now' => $currentTime
            ]);
            $stmt->execute(['udid' => $udid]); // Re-fetch after insert
            $deviceRecord = $stmt->fetch();
        } else {
            $stmt = $pdo->prepare("UPDATE devices SET last_activation_attempt_timestamp = :now WHERE udid = :udid");
            $stmt->execute(['now' => $currentTime, 'udid' => $udid]);
        }

        // 3. Check Simulated Lock Status
        if ($deviceRecord && $deviceRecord['is_simulated_locked'] == 1) {
            header('Content-Type: text/html; charset=utf-8');
            $lockMessage = htmlspecialchars($deviceRecord['simulated_lock_message'] ?? 'This device is SIMULATED as locked.');
            echo <<<HTML
            <!DOCTYPE html><html><head><title>Simulated Activation Lock</title><style>body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;text-align:center;padding:50px 20px;color:#1d1d1f;background-color:#f5f5f7;}.container{max-width:400px;margin:0 auto;}.lock-icon{font-size:48px;}.message{margin-top:20px;font-size:22px;font-weight:600;}.sub-message{font-size:14px;color:#6e6e73;margin-top:12px;}</style></head>
            <body><div class="container"><div class="lock-icon">🔒</div><h1 class="message">Activation Lock Simulation</h1><p class="sub-message">{$lockMessage}</p><p class="sub-message"><small>This is a local simulation via activator2.0.php and does not reflect real Apple Activation Lock status.</small></p></div></body></html>
            HTML;
            exit;
        }

        // 4. Generate and Send Activation Record
        $activationRecordPlist = $generator->generate();

        // Store the generated record for auditing purposes
        $stmt = $pdo->prepare("UPDATE devices SET activation_record_xml = :xml WHERE udid = :udid");
        $stmt->execute(['xml' => $activationRecordPlist, 'udid' => $udid]);

        // Output the standard iTunes response
        $htmlOutput = <<<HTML
        <!DOCTYPE html>
        <html>
           <head>
              <meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
              <title>iPhone Activation</title>
              <script id="protocol" type="text/x-apple-plist">{$activationRecordPlist}</script>
              <script>
                    document.addEventListener('DOMContentLoaded', function() {
                        try {
                            var protocolElement = document.getElementById("protocol");
                            var protocolContent = protocolElement.textContent || protocolElement.innerText;
                            if (window.iTunes && typeof window.iTunes.addProtocol === 'function') {
                                window.iTunes.addProtocol(protocolContent);
                            } else {
                                console.warn("iTunes protocol handler not found. This is expected in a normal browser.");
                            }
                        } catch (e) {
                             console.error("Error communicating with iTunes protocol handler:", e);
                        }
                    });
              </script>
           </head>
           <body></body>
        </html>
        HTML;
        
        header('Content-Type: text/html; charset=utf-8');
        echo $htmlOutput;

    } catch (\Throwable $e) {
        send_json_error(
            500,
            'An error occurred during the activation process. Check server logs for details.',
            'Activation Process Error: ' . $e->getMessage() . "\n" . $e->getTraceAsString()
        );
    }

} elseif ($requestMethod === 'GET') {
    header('Content-Type: text/html; charset=utf-8');
    echo "<h1>Activation Server 2.0 (Simulated)</h1>";
    echo "<p>This script expects a POST request with iDevice activation data.</p>";
    echo "<p>For educational purposes only. This system uses a local database to <strong>simulate</strong> a server-side device lock.</p>";
    // You would create an admin panel (e.g., manage_devices.php) to interact with the database
    // and set the is_simulated_locked flag for devices.
    echo "<p><em>An admin panel for managing simulated locks is not included but would be the next step.</em></p>";
} else {
    http_response_code(405);
    header('Allow: POST, GET');
    echo 'Method Not Allowed';
}
