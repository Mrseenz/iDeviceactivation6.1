using System;
using System.Collections.Generic;
using System.Data.SQLite; // NuGet: System.Data.SQLite.Core
using System.IO;
using System.Reflection; // For logging, not strictly needed for DB

namespace ActivationLogicLib
{
    // Simple DTO for device records to avoid using DataTables or anonymous types everywhere
    public class DeviceRecord
    {
        public long Id { get; set; }
        public string Udid { get; set; }
        public string SerialNumber { get; set; }
        public string Imei { get; set; }
        public string ProductType { get; set; }
        public bool IsSimulatedLocked { get; set; }
        public string SimulatedLockMessage { get; set; }
        public string ActivationRecordXml { get; set; }
        public string Notes { get; set; }
        public DateTime FirstSeenTimestamp { get; set; }
        public DateTime? LastActivationAttemptTimestamp { get; set; } // Nullable
    }

    public class DatabaseManager : IDisposable
    {
        private SQLiteConnection _connection;
        private static readonly string DbPath = AppSettings.GetDatabasePath(); // Uses the logic from AppSettings

        public DatabaseManager()
        {
            // Connection will be opened on first use or explicitly
        }

        private SQLiteConnection GetOpenConnection()
        {
            if (_connection == null || _connection.State != System.Data.ConnectionState.Open)
            {
                string dbDirectory = Path.GetDirectoryName(DbPath);
                if (!string.IsNullOrEmpty(dbDirectory) && !Directory.Exists(dbDirectory))
                {
                    try
                    {
                        Directory.CreateDirectory(dbDirectory);
                        Console.WriteLine($"[DatabaseManager] Created database directory: {dbDirectory}");
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"[DatabaseManager] Error creating database directory {dbDirectory}: {ex.Message}");
                        // Optionally rethrow or handle more gracefully
                    }
                }
                _connection = new SQLiteConnection($"Data Source={DbPath};Version=3;");
                try
                {
                    _connection.Open();
                    Console.WriteLine($"[DatabaseManager] Database connection opened to: {DbPath}");
                }
                catch (SQLiteException ex)
                {
                    Console.WriteLine($"[DatabaseManager] Error opening database connection to {DbPath}: {ex.Message}");
                    // Rethrow or handle (e.g. if DB file is corrupt or permissions are wrong)
                    throw;
                }
            }
            return _connection;
        }

        public void InitializeSchema()
        {
            try
            {
                using (var cmd = GetOpenConnection().CreateCommand())
                {
                    cmd.CommandText = @"
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
                        );";
                    cmd.ExecuteNonQuery();

                    cmd.CommandText = "CREATE INDEX IF NOT EXISTS idx_devices_udid ON devices (udid);";
                    cmd.ExecuteNonQuery();
                    Console.WriteLine("[DatabaseManager] Database schema initialized/verified.");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[DatabaseManager] Error initializing schema: {ex.Message}");
                // Optionally rethrow
            }
        }

        public DeviceRecord GetDeviceByUdid(string udid)
        {
            DeviceRecord record = null;
            try
            {
                using (var cmd = GetOpenConnection().CreateCommand())
                {
                    cmd.CommandText = "SELECT * FROM devices WHERE udid = @udid;";
                    cmd.Parameters.AddWithValue("@udid", udid);
                    using (var reader = cmd.ExecuteReader())
                    {
                        if (reader.Read())
                        {
                            record = MapReaderToDeviceRecord(reader);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[DatabaseManager] Error in GetDeviceByUdid for {udid}: {ex.Message}");
            }
            return record;
        }

        public List<DeviceRecord> GetAllDevices()
        {
            var records = new List<DeviceRecord>();
            try
            {
                using (var cmd = GetOpenConnection().CreateCommand())
                {
                    cmd.CommandText = "SELECT * FROM devices ORDER BY last_activation_attempt_timestamp DESC;";
                    using (var reader = cmd.ExecuteReader())
                    {
                        while (reader.Read())
                        {
                            records.Add(MapReaderToDeviceRecord(reader));
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[DatabaseManager] Error in GetAllDevices: {ex.Message}");
            }
            return records;
        }

        public void InsertDevice(DeviceRecord device)
        {
            try
            {
                using (var cmd = GetOpenConnection().CreateCommand())
                {
                    cmd.CommandText = @"
                        INSERT INTO devices (udid, serial_number, imei, product_type, last_activation_attempt_timestamp, first_seen_timestamp)
                        VALUES (@udid, @serial_number, @imei, @product_type, @last_activation_attempt_timestamp, @first_seen_timestamp);";
                    cmd.Parameters.AddWithValue("@udid", device.Udid);
                    cmd.Parameters.AddWithValue("@serial_number", device.SerialNumber ?? (object)DBNull.Value);
                    cmd.Parameters.AddWithValue("@imei", device.Imei ?? (object)DBNull.Value);
                    cmd.Parameters.AddWithValue("@product_type", device.ProductType ?? (object)DBNull.Value);
                    cmd.Parameters.AddWithValue("@last_activation_attempt_timestamp", device.LastActivationAttemptTimestamp ?? (object)DBNull.Value);
                    cmd.Parameters.AddWithValue("@first_seen_timestamp", device.FirstSeenTimestamp == DateTime.MinValue ? DateTime.UtcNow : device.FirstSeenTimestamp);
                    cmd.ExecuteNonQuery();
                }
            }
            catch (Exception ex)
            {
                 Console.WriteLine($"[DatabaseManager] Error in InsertDevice for {device.Udid}: {ex.Message}");
            }
        }

        public void UpdateDeviceTimestamp(string udid, DateTime timestamp)
        {
            try
            {
                using (var cmd = GetOpenConnection().CreateCommand())
                {
                    cmd.CommandText = "UPDATE devices SET last_activation_attempt_timestamp = @timestamp WHERE udid = @udid;";
                    cmd.Parameters.AddWithValue("@timestamp", timestamp);
                    cmd.Parameters.AddWithValue("@udid", udid);
                    cmd.ExecuteNonQuery();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[DatabaseManager] Error in UpdateDeviceTimestamp for {udid}: {ex.Message}");
            }
        }

        public void UpdateDeviceActivationRecord(string udid, string activationRecordXml)
        {
            try
            {
                using (var cmd = GetOpenConnection().CreateCommand())
                {
                    cmd.CommandText = "UPDATE devices SET activation_record_xml = @xml WHERE udid = @udid;";
                    cmd.Parameters.AddWithValue("@xml", activationRecordXml ?? (object)DBNull.Value);
                    cmd.Parameters.AddWithValue("@udid", udid);
                    cmd.ExecuteNonQuery();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[DatabaseManager] Error in UpdateDeviceActivationRecord for {udid}: {ex.Message}");
            }
        }

        public void ToggleDeviceLockStatus(long deviceId, bool newLockStatus, string lockMessage)
        {
            try
            {
                using (var cmd = GetOpenConnection().CreateCommand())
                {
                    cmd.CommandText = "UPDATE devices SET is_simulated_locked = @status, simulated_lock_message = @message WHERE id = @id;";
                    cmd.Parameters.AddWithValue("@status", newLockStatus ? 1 : 0);
                    cmd.Parameters.AddWithValue("@message", lockMessage ?? (object)DBNull.Value);
                    cmd.Parameters.AddWithValue("@id", deviceId);
                    cmd.ExecuteNonQuery();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[DatabaseManager] Error in ToggleDeviceLockStatus for ID {deviceId}: {ex.Message}");
            }
        }

        public DeviceRecord GetDeviceById(long deviceId)
        {
            DeviceRecord record = null;
            try
            {
                using (var cmd = GetOpenConnection().CreateCommand())
                {
                    cmd.CommandText = "SELECT * FROM devices WHERE id = @id;";
                    cmd.Parameters.AddWithValue("@id", deviceId);
                    using (var reader = cmd.ExecuteReader())
                    {
                        if (reader.Read())
                        {
                            record = MapReaderToDeviceRecord(reader);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                 Console.WriteLine($"[DatabaseManager] Error in GetDeviceById for {deviceId}: {ex.Message}");
            }
            return record;
        }

        private DeviceRecord MapReaderToDeviceRecord(SQLiteDataReader reader)
        {
            return new DeviceRecord
            {
                Id = Convert.ToInt64(reader["id"]),
                Udid = reader["udid"] as string, // Safe cast
                SerialNumber = reader["serial_number"] == DBNull.Value ? null : (string)reader["serial_number"],
                Imei = reader["imei"] == DBNull.Value ? null : (string)reader["imei"],
                ProductType = reader["product_type"] == DBNull.Value ? null : (string)reader["product_type"],
                IsSimulatedLocked = Convert.ToInt32(reader["is_simulated_locked"]) == 1,
                SimulatedLockMessage = reader["simulated_lock_message"] == DBNull.Value ? null : (string)reader["simulated_lock_message"],
                ActivationRecordXml = reader["activation_record_xml"] == DBNull.Value ? null : (string)reader["activation_record_xml"],
                Notes = reader["notes"] == DBNull.Value ? null : (string)reader["notes"],
                FirstSeenTimestamp = Convert.ToDateTime(reader["first_seen_timestamp"]),
                LastActivationAttemptTimestamp = reader["last_activation_attempt_timestamp"] == DBNull.Value ? (DateTime?)null : Convert.ToDateTime(reader["last_activation_attempt_timestamp"])
            };
        }

        public void Dispose()
        {
            if (_connection != null)
            {
                if (_connection.State != System.Data.ConnectionState.Closed)
                {
                    try
                    {
                        _connection.Close();
                    }
                    catch (Exception ex)
                    {
                         Console.WriteLine($"[DatabaseManager] Error closing connection: {ex.Message}");
                    }
                }
                _connection.Dispose();
                _connection = null;
                Console.WriteLine("[DatabaseManager] Database connection disposed.");
            }
        }
    }
}
