using System;
using System.Drawing;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.IO; // For MemoryStream
using ActivationLogicLib; // Assumes ActivationLogicLib is referenced
using System.Xml.Linq; // For Plist parsing if needed here, though mostly in ActivationGenerator
using Newtonsoft.Json; // If errors are returned as JSON. NuGet: Newtonsoft.Json
using System.Collections.Generic; // For IDictionary
using System.Linq; // For OfType<T>()

namespace WindowsFormsApp
{
    public partial class MainForm : Form
    {
        private Button btnStartServer;
        private Button btnStopServer;
        private TextBox txtLog;
        private Label lblStatus;
        private Button btnManageDevices; // Button to open device management

        private ActivationHttpServer _httpServer;
        private CancellationTokenSource _cancellationTokenSource;

        public MainForm()
        {
            InitializeComponent();
            // Initialize DatabaseManager and schema (once)
            try
            {
                // Ensure AppSettings can find the DB path correctly.
                // This might involve copying the DB to the output dir or configuring AppSettings.
                LogMessage($"Database path configured to: {AppSettings.GetDatabasePath()}");
                using (var dbManager = new DatabaseManager()) { // DatabaseManager will use AppSettings.GetDatabasePath()
                    dbManager.InitializeSchema();
                }
                LogMessage("Database schema initialized successfully.");
            }
            catch (Exception ex)
            {
                LogMessage($"Error initializing database: {ex.GetType().Name} - {ex.Message}{Environment.NewLine}Trace: {ex.StackTrace}");
                MessageBox.Show($"Error initializing database: {ex.Message}{Environment.NewLine}Please ensure System.Data.SQLite.Core and its dependencies are correctly installed and accessible, and that the database path is valid.", "Database Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void InitializeComponent()
        {
            this.btnStartServer = new System.Windows.Forms.Button();
            this.btnStopServer = new System.Windows.Forms.Button();
            this.txtLog = new System.Windows.Forms.TextBox();
            this.lblStatus = new System.Windows.Forms.Label();
            this.btnManageDevices = new System.Windows.Forms.Button();
            this.SuspendLayout();

            // btnStartServer
            this.btnStartServer.Location = new System.Drawing.Point(12, 12);
            this.btnStartServer.Name = "btnStartServer";
            this.btnStartServer.Size = new System.Drawing.Size(100, 23);
            this.btnStartServer.TabIndex = 0;
            this.btnStartServer.Text = "Start Server";
            this.btnStartServer.UseVisualStyleBackColor = true;
            this.btnStartServer.Click += new System.EventHandler(this.BtnStartServer_Click);

            // btnStopServer
            this.btnStopServer.Location = new System.Drawing.Point(118, 12);
            this.btnStopServer.Name = "btnStopServer";
            this.btnStopServer.Size = new System.Drawing.Size(100, 23);
            this.btnStopServer.TabIndex = 1;
            this.btnStopServer.Text = "Stop Server";
            this.btnStopServer.UseVisualStyleBackColor = true;
            this.btnStopServer.Enabled = false;
            this.btnStopServer.Click += new System.EventHandler(this.BtnStopServer_Click);

            // btnManageDevices
            this.btnManageDevices.Location = new System.Drawing.Point(224, 12);
            this.btnManageDevices.Name = "btnManageDevices";
            this.btnManageDevices.Size = new System.Drawing.Size(120, 23);
            this.btnManageDevices.TabIndex = 2;
            this.btnManageDevices.Text = "Manage Devices";
            this.btnManageDevices.UseVisualStyleBackColor = true;
            this.btnManageDevices.Click += new System.EventHandler(this.BtnManageDevices_Click);

            // lblStatus
            this.lblStatus.Location = new System.Drawing.Point(350, 12); // Adjusted position
            this.lblStatus.Name = "lblStatus";
            this.lblStatus.Size = new System.Drawing.Size(222, 23); // Adjusted size
            this.lblStatus.TabIndex = 3;
            this.lblStatus.Text = "Server Status: Stopped";
            this.lblStatus.TextAlign = System.Drawing.ContentAlignment.MiddleLeft;

            // txtLog
            this.txtLog.Anchor = ((System.Windows.Forms.AnchorStyles)((((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Bottom)
            | System.Windows.Forms.AnchorStyles.Left)
            | System.Windows.Forms.AnchorStyles.Right)));
            this.txtLog.Location = new System.Drawing.Point(12, 41);
            this.txtLog.Multiline = true;
            this.txtLog.Name = "txtLog";
            this.txtLog.ReadOnly = true;
            this.txtLog.ScrollBars = System.Windows.Forms.ScrollBars.Vertical;
            this.txtLog.Size = new System.Drawing.Size(560, 308);
            this.txtLog.TabIndex = 4; // Adjusted TabIndex

            // MainForm
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(584, 361);
            this.Controls.Add(this.btnManageDevices);
            this.Controls.Add(this.lblStatus);
            this.Controls.Add(this.txtLog);
            this.Controls.Add(this.btnStopServer);
            this.Controls.Add(this.btnStartServer);
            this.MinimumSize = new System.Drawing.Size(500, 250);
            this.Name = "MainForm";
            this.Text = "iDevice Activation Server GUI (C#)";
            this.FormClosing += new System.Windows.Forms.FormClosingEventHandler(this.MainForm_FormClosing);
            this.ResumeLayout(false);
            this.PerformLayout();
        }

        private void BtnStartServer_Click(object sender, EventArgs e)
        {
            if (_httpServer != null && _httpServer.IsListening)
            {
                LogMessage("Server is already running.");
                return;
            }

            _cancellationTokenSource = new CancellationTokenSource();
            // TODO: Make port configurable via UI / AppSettings
            string listenerPrefix = "http://localhost:5000/";
            _httpServer = new ActivationHttpServer(listenerPrefix, this.LogMessage);

            try
            {
                // Start HttpListener on a separate thread so it doesn't block UI thread
                Task.Run(() => _httpServer.Start(_cancellationTokenSource.Token), _cancellationTokenSource.Token);
                LogMessage($"HTTP server starting. Listening on {listenerPrefix}");
                btnStartServer.Enabled = false;
                btnStopServer.Enabled = true;
                lblStatus.Text = "Server Status: Running";
            }
            catch (Exception ex)
            {
                LogMessage($"Error starting server: {ex.Message}");
                MessageBox.Show($"Error starting server: {ex.Message}", "Server Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                btnStartServer.Enabled = true;
                btnStopServer.Enabled = false;
                lblStatus.Text = "Server Status: Error";
            }
        }

        private void BtnStopServer_Click(object sender, EventArgs e)
        {
            if (_httpServer == null || !_httpServer.IsListening)
            {
                LogMessage("Server is not running or already stopping.");
                // Ensure UI state is correct if somehow stop is clicked when not running
                btnStartServer.Enabled = true;
                btnStopServer.Enabled = false;
                lblStatus.Text = "Server Status: Stopped";
                return;
            }

            try
            {
                LogMessage("Stopping HTTP server...");
                _cancellationTokenSource?.Cancel();
                // Allow some time for the listener task to acknowledge cancellation and stop gracefully
                // _httpServer.Stop() should be called by the task itself upon cancellation.
                // Or, if Start is not fully async cancellable, call Stop directly.
                // For HttpListener, Stop() is synchronous and can be called.
                _httpServer.Stop();

                // Wait a bit for the task to complete if it's running
                // Task.Delay(100).Wait(); // This would block UI, not ideal.
                // Better: The _httpServer.Start task should handle cancellation and exit.
            }
            catch (Exception ex)
            {
                LogMessage($"Error stopping server: {ex.Message}");
            }
            finally
            {
                _httpServer = null; // Allow it to be GC'd
                _cancellationTokenSource?.Dispose();
                _cancellationTokenSource = null;
                LogMessage("HTTP server stopped.");
                btnStartServer.Enabled = true;
                btnStopServer.Enabled = false;
                lblStatus.Text = "Server Status: Stopped";
            }
        }

        private void BtnManageDevices_Click(object sender, EventArgs e)
        {
            // This is where you would open a new Form/Dialog for device management.
            // For now, let's log a message.
            LogMessage("Manage Devices button clicked. (Functionality to be implemented in a separate form/dialog)");
            // Example:
            // ManageDevicesForm manageForm = new ManageDevicesForm(this.LogMessage); // Pass logger
            // manageForm.ShowDialog(this);
            MessageBox.Show("Device management UI is not yet implemented in this version.", "Manage Devices", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }


        public void LogMessage(string message)
        {
            if (txtLog.InvokeRequired)
            {
                // Safely update UI from a different thread
                txtLog.Invoke(new Action<string>(LogMessageInternal), message);
            }
            else
            {
                LogMessageInternal(message);
            }
        }

        private void LogMessageInternal(string message)
        {
            string formattedMessage = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] {message}{Environment.NewLine}";
            if (txtLog.TextLength + formattedMessage.Length >= txtLog.MaxLength)
            {
                // Basic log rotation: clear half if it gets too long
                txtLog.Text = txtLog.Text.Substring(txtLog.TextLength / 2);
            }
            txtLog.AppendText(formattedMessage);
            txtLog.ScrollToCaret(); // Scroll to the end
        }

        private void MainForm_FormClosing(object sender, FormClosingEventArgs e)
        {
            if (_httpServer != null && _httpServer.IsListening)
            {
                LogMessage("Stopping server due to form closing...");
                _cancellationTokenSource?.Cancel();
                _httpServer.Stop();
                _httpServer = null;
                _cancellationTokenSource?.Dispose();
            }
        }
    }

    public class ActivationHttpServer
    {
        private readonly HttpListener _listener;
        private readonly string _prefix;
        private readonly Action<string> _logMessageCallback; // Delegate for logging to UI

        public bool IsListening => _listener?.IsListening ?? false;

        public ActivationHttpServer(string prefix, Action<string> logMessageCallback)
        {
            _prefix = prefix ?? throw new ArgumentNullException(nameof(prefix));
            _listener = new HttpListener();
            if (!HttpListener.IsSupported) {
                throw new NotSupportedException("HttpListener is not supported on this platform.");
            }
            _listener.Prefixes.Add(_prefix);
            _logMessageCallback = logMessageCallback;
        }

        public async Task Start(CancellationToken cancellationToken)
        {
            try
            {
                _listener.Start();
                _logMessageCallback?.Invoke($"ActivationHttpServer: Listening for requests on {_prefix}");
            }
            catch (HttpListenerException hlex)
            {
                 _logMessageCallback?.Invoke($"ActivationHttpServer: Failed to start listener. Port may be in use or prefix invalid. Error: {hlex.Message} (Code: {hlex.ErrorCode})");
                 return; // Cannot start
            }
            catch (Exception ex)
            {
                 _logMessageCallback?.Invoke($"ActivationHttpServer: Unexpected error on start: {ex.Message}");
                 return;
            }


            try
            {
                while (!cancellationToken.IsCancellationRequested && _listener.IsListening)
                {
                    HttpListenerContext context = await _listener.GetContextAsync().ConfigureAwait(false);
                    // Using Task.Run to process each request on a thread pool thread
                    // This prevents blocking the listener loop for long-running requests.
                    _ = Task.Run(async () => await ProcessRequestContextAsync(context), cancellationToken);
                }
            }
            catch (HttpListenerException ex) when (ex.ErrorCode == 995 || ex.NativeErrorCode == 995) // ERROR_OPERATION_ABORTED
            {
                _logMessageCallback?.Invoke("ActivationHttpServer: Listener loop aborted (server stopping).");
            }
            catch (ObjectDisposedException)
            {
                 _logMessageCallback?.Invoke("ActivationHttpServer: Listener loop aborted (listener disposed).");
            }
            catch (Exception ex)
            {
                _logMessageCallback?.Invoke($"ActivationHttpServer: Critical listener error: {ex.Message}");
            }
            finally
            {
                if (_listener.IsListening) // Should be false if Stop() was called or error occurred
                {
                    _listener.Stop();
                }
                _logMessageCallback?.Invoke("ActivationHttpServer: Listener has fully stopped.");
            }
        }

        private async Task ProcessRequestContextAsync(HttpListenerContext context)
        {
            HttpListenerRequest request = context.Request;
            HttpListenerResponse response = context.Response;
            string responseString = "";
            string contentType = "text/html; charset=utf-8";
            int statusCode = 200;

            try
            {
                _logMessageCallback?.Invoke($"ActivationHttpServer: Received {request.HttpMethod} request for {request.Url.AbsolutePath}");

                if (request.HttpMethod == "POST" && request.Url.AbsolutePath == "/")
                {
                    byte[] requestBodyBytes;
                    using (var ms = new MemoryStream())
                    {
                        await request.InputStream.CopyToAsync(ms).ConfigureAwait(false);
                        requestBodyBytes = ms.ToArray();
                    }

                    if (requestBodyBytes.Length == 0)
                    {
                        statusCode = 400;
                        responseString = GenerateJsonErrorResponse("Request body is empty.");
                        contentType = "application/json; charset=utf-8";
                    }
                    else
                    {
                        _logMessageCallback?.Invoke($"ActivationHttpServer: POST request body length: {requestBodyBytes.Length}, Content-Type: {request.ContentType}");

                        // TODO: Add multipart parsing if request.ContentType indicates multipart/form-data
                        // For now, assumes raw plist body

                        ActivationGenerator generator = null;
                        try
                        {
                            generator = new ActivationGenerator(requestBodyBytes);
                            var deviceInfo = generator.GetDeviceInfo();
                            string udid = deviceInfo["UniqueDeviceID"]; // Should exist due to constructor check
                            _logMessageCallback?.Invoke($"ActivationHttpServer: Processing for UDID {udid}");

                            using (var dbManager = new DatabaseManager()) // Ensure DB is disposed
                            {
                                var deviceRecord = dbManager.GetDeviceByUdid(udid);
                                var now = DateTime.UtcNow;
                                if (deviceRecord == null)
                                {
                                    dbManager.InsertDevice(new DeviceRecord {
                                        Udid = udid,
                                        SerialNumber = deviceInfo.GetValueOrDefault("SerialNumber"),
                                        Imei = deviceInfo.GetValueOrDefault("InternationalMobileEquipmentIdentity"),
                                        ProductType = deviceInfo.GetValueOrDefault("ProductType"),
                                        FirstSeenTimestamp = now,
                                        LastActivationAttemptTimestamp = now
                                    });
                                    _logMessageCallback?.Invoke($"ActivationHttpServer: New device {udid} added to DB.");
                                    deviceRecord = dbManager.GetDeviceByUdid(udid); // Re-fetch
                                }
                                else
                                {
                                    dbManager.UpdateDeviceTimestamp(udid, now);
                                     _logMessageCallback?.Invoke($"ActivationHttpServer: Existing device {udid} timestamp updated.");
                                }

                                if (deviceRecord != null && deviceRecord.IsSimulatedLocked)
                                {
                                    string lockMsg = string.IsNullOrEmpty(deviceRecord.SimulatedLockMessage) ? "This device is SIMULATED as locked." : deviceRecord.SimulatedLockMessage;
                                    // HTML structure copied from Python version
                                    responseString = $"<!DOCTYPE html><html><head><title>Simulated Activation Lock</title><style>body{{font-family:-apple-system,BlinkMacSystemFont,\"Segoe UI\",Roboto,Helvetica,Arial,sans-serif;text-align:center;padding:50px 20px;color:#1d1d1f;background-color:#f5f5f7;}}.container{{max-width:400px;margin:0 auto;}}.lock-icon{{font-size:48px;}}.message{{margin-top:20px;font-size:22px;font-weight:600;}}.sub-message{{font-size:14px;color:#6e6e73;margin-top:12px;}}</style></head><body><div class=\"container\"><div class=\"lock-icon\">🔒</div><h1 class=\"message\">Activation Lock Simulation</h1><p class=\"sub-message\">{System.Security.SecurityElement.Escape(lockMsg)}</p><p class=\"sub-message\"><small>This is a local simulation and does not reflect real Apple Activation Lock status.</small></p></div></body></html>";
                                }
                                else
                                {
                                    byte[] activationRecordBytes = generator.GenerateActivationRecord();
                                    string activationRecordXml = Encoding.UTF8.GetString(activationRecordBytes);
                                    if (deviceRecord != null) { // deviceRecord could be null if first insert failed and re-fetch was null
                                         dbManager.UpdateDeviceActivationRecord(udid, activationRecordXml);
                                    }

                                    responseString = $"<!DOCTYPE html><html><head><meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\" /><title>iPhone Activation</title><script id=\"protocol\" type=\"text/x-apple-plist\">{System.Security.SecurityElement.Escape(activationRecordXml)}</script><script>document.addEventListener('DOMContentLoaded', function() {{ try {{ var p = document.getElementById(\"protocol\").textContent; if (window.iTunes && typeof window.iTunes.addProtocol === 'function') window.iTunes.addProtocol(p); else console.warn(\"iTunes protocol handler not found.\"); }} catch (e) {{ console.error(\"Error with iTunes protocol handler:\", e); }} }});</script></head><body></body></html>";
                                }
                            }
                        }
                        catch (ActivationGeneratorException age)
                        {
                            _logMessageCallback?.Invoke($"ActivationHttpServer: ActivationGeneratorException: {age.Message}");
                            statusCode = 400;
                            responseString = GenerateJsonErrorResponse($"Error processing activation request: {age.Message}");
                            contentType = "application/json; charset=utf-8";
                        }
                        catch (Exception ex)
                        {
                            _logMessageCallback?.Invoke($"ActivationHttpServer: Error during activation processing: {ex.GetType().Name} - {ex.Message}{Environment.NewLine}Trace: {ex.StackTrace}");
                            statusCode = 500;
                            responseString = GenerateJsonErrorResponse("Internal server error during activation processing.");
                            contentType = "application/json; charset=utf-8";
                        }
                    }
                }
                else if (request.HttpMethod == "GET" && request.Url.AbsolutePath == "/")
                {
                    responseString = "<h1>C# Activation Server (Simulated)</h1><p>POST activation data to this endpoint.</p><p><a href=\"/manage\">Manage Devices</a></p>";
                }
                else // No /manage endpoint on HttpListener, that's GUI only
                {
                    statusCode = 404;
                    responseString = "<h1>404 Not Found</h1><p>The requested URL was not found on this server.</p>";
                }
            }
            catch (Exception ex) // Catch-all for ProcessRequestContextAsync
            {
                _logMessageCallback?.Invoke($"ActivationHttpServer: Unhandled error processing request {request.Url}: {ex.Message}");
                statusCode = 500;
                try {
                    responseString = GenerateJsonErrorResponse("An unexpected error occurred processing your request.");
                    contentType = "application/json; charset=utf-8";
                } catch {} // Avoid error in error handling
            }
            finally
            {
                try
                {
                    response.StatusCode = statusCode;
                    response.ContentType = contentType;
                    byte[] buffer = Encoding.UTF8.GetBytes(responseString);
                    response.ContentLength64 = buffer.Length;
                    await response.OutputStream.WriteAsync(buffer, 0, buffer.Length).ConfigureAwait(false);
                }
                catch(Exception exResp) { // Error sending the response itself
                    _logMessageCallback?.Invoke($"ActivationHttpServer: Fatal error sending response for {request.Url}: {exResp.Message}");
                }
                finally {
                    response.OutputStream.Close(); // Always close output stream
                }
            }
        }

        private string GenerateJsonErrorResponse(string message, string detail = null)
        {
            var errorObj = new { error = message, detail = detail };
            try { return JsonConvert.SerializeObject(errorObj); } // Requires Newtonsoft.Json
            catch { return $"{{\"error\":\"{message.Replace("\"", "\\\"")}\",\"detail\":\"Serialization error\"}}"; } // Fallback if JSON fails
        }

        public void Stop()
        {
            _logMessageCallback?.Invoke("ActivationHttpServer: Stop requested.");
            if (_listener != null && _listener.IsListening)
            {
                // HttpListener.Stop() is synchronous and may block if there are active requests.
                // HttpListener.Close() aborts current requests and releases resources.
                // HttpListener.Abort() also exists.
                // For graceful shutdown, cancellation token should be primary, then Close/Abort.
                _listener.Close(); // Using Close for more immediate resource release.
            }
        }
    }

    public static class DictionaryExtensions // Helper, move to utility class if project grows
    {
        public static TValue GetValueOrDefault<TKey, TValue>(this IDictionary<TKey, TValue> dictionary, TKey key, TValue defaultValue = default(TValue))
        {
            return dictionary.TryGetValue(key, out TValue value) ? value : defaultValue;
        }
    }
}
