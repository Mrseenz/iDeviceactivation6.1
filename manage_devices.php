<?php
declare(strict_types=1);

// This script acts as a simple admin panel to manage the simulated device locks.
// It interacts with the same database as activator2.0.php.

define('DB_FILE', __DIR__ . '/activation_simulator.sqlite');

function get_db_connection(): PDO {
    try {
        $pdo = new PDO('sqlite:' . DB_FILE);
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
        return $pdo;
    } catch (PDOException $e) {
        die("Database Error: " . $e->getMessage());
    }
}

// Ensure the table exists, in case this is run first
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

// Handle form submissions for locking/unlocking
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action'])) {
    if ($_POST['action'] === 'toggle_lock' && isset($_POST['id'])) {
        $id = filter_var($_POST['id'], FILTER_VALIDATE_INT);
        
        // First, get the current status
        $stmt = $pdo->prepare("SELECT is_simulated_locked FROM devices WHERE id = ?");
        $stmt->execute([$id]);
        $currentStatus = $stmt->fetchColumn();

        // Toggle it
        $newStatus = ($currentStatus == 1) ? 0 : 1;
        $lockMessage = ($newStatus == 1) ? "This device was locked by the administrator." : null;
        
        $stmt = $pdo->prepare("UPDATE devices SET is_simulated_locked = ?, simulated_lock_message = ? WHERE id = ?");
        $stmt->execute([$newStatus, $lockMessage, $id]);
    }
    // Redirect to the same page to prevent form re-submission on refresh
    header("Location: " . $_SERVER['PHP_SELF']);
    exit;
}

// Fetch all devices to display on the page
$devices = $pdo->query("SELECT * FROM devices ORDER BY last_activation_attempt_timestamp DESC")->fetchAll();

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Simulated Activation Lock Manager</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; margin: 0; background-color: #f5f5f7; color: #1d1d1f; }
        .container { max-width: 1200px; margin: 20px auto; padding: 20px; background-color: #fff; border-radius: 12px; box-shadow: 0 4px 12px rgba(0,0,0,0.1); }
        h1 { text-align: center; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th, td { padding: 12px 15px; text-align: left; border-bottom: 1px solid #e5e5e5; }
        th { background-color: #f8f8f8; font-weight: 600; }
        tr:hover { background-color: #f9f9f9; }
        .status { padding: 5px 10px; border-radius: 15px; color: #fff; font-size: 0.8em; font-weight: bold; }
        .status.unlocked { background-color: #34c759; }
        .status.locked { background-color: #ff3b30; }
        button { cursor: pointer; padding: 8px 16px; border-radius: 8px; border: none; font-weight: 600; color: #fff; transition: background-color 0.2s; }
        .btn-lock { background-color: #ff3b30; }
        .btn-lock:hover { background-color: #d93228; }
        .btn-unlock { background-color: #34c759; }
        .btn-unlock:hover { background-color: #2da44a; }
        .info { font-family: "SF Mono", "Menlo", monospace; font-size: 0.85em; color: #6e6e73; word-break: break-all; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Simulated Activation Lock Manager</h1>
        <p>This panel controls the <strong>local simulation</strong> of Activation Lock. It modifies the `is_simulated_locked` flag in the `activation_simulator.sqlite` database, which `activator2.0.php` reads.</p>
        <table>
            <thead>
                <tr>
                    <th>Device</th>
                    <th>Identifiers</th>
                    <th>Last Seen</th>
                    <th>Status</th>
                    <th>Action</th>
                </tr>
            </thead>
            <tbody>
                <?php if (empty($devices)): ?>
                    <tr>
                        <td colspan="5" style="text-align: center; padding: 20px;">No devices have contacted the activation server yet.</td>
                    </tr>
                <?php else: ?>
                    <?php foreach ($devices as $device): ?>
                        <tr>
                            <td>
                                <strong><?= htmlspecialchars($device['product_type'] ?? 'Unknown') ?></strong>
                            </td>
                            <td>
                                <div class="info">
                                    <strong>UDID:</strong> <?= htmlspecialchars($device['udid']) ?><br>
                                    <strong>S/N:</strong> <?= htmlspecialchars($device['serial_number'] ?? 'N/A') ?><br>
                                    <strong>IMEI:</strong> <?= htmlspecialchars($device['imei'] ?? 'N/A') ?>
                                </div>
                            </td>
                            <td><?= htmlspecialchars($device['last_activation_attempt_timestamp'] ?? 'N/A') ?></td>
                            <td>
                                <?php if ($device['is_simulated_locked']): ?>
                                    <span class="status locked">LOCKED</span>
                                <?php else: ?>
                                    <span class="status unlocked">UNLOCKED</span>
                                <?php endif; ?>
                            </td>
                            <td>
                                <form method="POST" action="">
                                    <input type="hidden" name="action" value="toggle_lock">
                                    <input type="hidden" name="id" value="<?= $device['id'] ?>">
                                    <?php if ($device['is_simulated_locked']): ?>
                                        <button type="submit" class="btn-unlock">Unlock</button>
                                    <?php else: ?>
                                        <button type="submit" class="btn-lock">Lock</button>
                                    <?php endif; ?>
                                </form>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                <?php endif; ?>
            </tbody>
        </table>
    </div>
</body>
</html>
