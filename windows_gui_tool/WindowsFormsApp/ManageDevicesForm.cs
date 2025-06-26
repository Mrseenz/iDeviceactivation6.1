using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using ActivationLogicLib; // For DatabaseManager and DeviceRecord

namespace WindowsFormsApp
{
    public partial class ManageDevicesForm : Form
    {
        private DataGridView dgvDevices;
        private Button btnRefresh;
        private Button btnToggleLock;
        private Label lblSelectedDevice;

        private readonly Action<string> _logMessageCallback; // To log actions to MainForm's log

        public ManageDevicesForm(Action<string> logMessageCallback)
        {
            _logMessageCallback = logMessageCallback;
            InitializeComponent();
            LoadDevices();
        }

        private void InitializeComponent()
        {
            this.dgvDevices = new System.Windows.Forms.DataGridView();
            this.btnRefresh = new System.Windows.Forms.Button();
            this.btnToggleLock = new System.Windows.Forms.Button();
            this.lblSelectedDevice = new System.Windows.Forms.Label();
            ((System.ComponentModel.ISupportInitialize)(this.dgvDevices)).BeginInit();
            this.SuspendLayout();

            // dgvDevices
            this.dgvDevices.AllowUserToAddRows = false;
            this.dgvDevices.AllowUserToDeleteRows = false;
            this.dgvDevices.Anchor = ((System.Windows.Forms.AnchorStyles)((((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Bottom)
            | System.Windows.Forms.AnchorStyles.Left)
            | System.Windows.Forms.AnchorStyles.Right)));
            this.dgvDevices.ColumnHeadersHeightSizeMode = System.Windows.Forms.DataGridViewColumnHeadersHeightSizeMode.AutoSize;
            this.dgvDevices.Location = new System.Drawing.Point(12, 41);
            this.dgvDevices.MultiSelect = false;
            this.dgvDevices.Name = "dgvDevices";
            this.dgvDevices.ReadOnly = true;
            this.dgvDevices.SelectionMode = System.Windows.Forms.DataGridViewSelectionMode.FullRowSelect;
            this.dgvDevices.Size = new System.Drawing.Size(760, 300);
            this.dgvDevices.TabIndex = 0;
            this.dgvDevices.SelectionChanged += new System.EventHandler(this.DgvDevices_SelectionChanged);


            // btnRefresh
            this.btnRefresh.Location = new System.Drawing.Point(12, 12);
            this.btnRefresh.Name = "btnRefresh";
            this.btnRefresh.Size = new System.Drawing.Size(75, 23);
            this.btnRefresh.TabIndex = 1;
            this.btnRefresh.Text = "Refresh";
            this.btnRefresh.UseVisualStyleBackColor = true;
            this.btnRefresh.Click += new System.EventHandler(this.BtnRefresh_Click);

            // btnToggleLock
            this.btnToggleLock.Location = new System.Drawing.Point(93, 12);
            this.btnToggleLock.Name = "btnToggleLock";
            this.btnToggleLock.Size = new System.Drawing.Size(100, 23);
            this.btnToggleLock.TabIndex = 2;
            this.btnToggleLock.Text = "Toggle Lock";
            this.btnToggleLock.UseVisualStyleBackColor = true;
            this.btnToggleLock.Enabled = false; // Enabled when a device is selected
            this.btnToggleLock.Click += new System.EventHandler(this.BtnToggleLock_Click);

            // lblSelectedDevice
            this.lblSelectedDevice.AutoSize = true;
            this.lblSelectedDevice.Location = new System.Drawing.Point(200, 17);
            this.lblSelectedDevice.Name = "lblSelectedDevice";
            this.lblSelectedDevice.Size = new System.Drawing.Size(0, 13); // Text set dynamically
            this.lblSelectedDevice.TabIndex = 3;

            // ManageDevicesForm
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(784, 353);
            this.Controls.Add(this.lblSelectedDevice);
            this.Controls.Add(this.btnToggleLock);
            this.Controls.Add(this.btnRefresh);
            this.Controls.Add(this.dgvDevices);
            this.Name = "ManageDevicesForm";
            this.Text = "Manage Simulated Devices";
            this.MinimumSize = new System.Drawing.Size(600, 300);
            ((System.ComponentModel.ISupportInitialize)(this.dgvDevices)).EndInit();
            this.ResumeLayout(false);
            this.PerformLayout();
        }

        private void Log(string message)
        {
            _logMessageCallback?.Invoke($"[ManageDevices] {message}");
        }

        private void LoadDevices()
        {
            try
            {
                using (var dbManager = new DatabaseManager())
                {
                    List<DeviceRecord> devices = dbManager.GetAllDevices();
                    // Configure DataGridView columns - this could be more dynamic or use attributes
                    dgvDevices.DataSource = null; // Clear previous data
                    dgvDevices.AutoGenerateColumns = false;
                    dgvDevices.Columns.Clear();

                    dgvDevices.Columns.Add(new DataGridViewTextBoxColumn { Name = "Id", HeaderText = "ID", DataPropertyName = "Id", Visible = false }); // Hide internal ID
                    dgvDevices.Columns.Add(new DataGridViewTextBoxColumn { Name = "ProductType", HeaderText = "Product Type", DataPropertyName = "ProductType", AutoSizeMode = DataGridViewAutoSizeColumnMode.AllCells });
                    dgvDevices.Columns.Add(new DataGridViewTextBoxColumn { Name = "SerialNumber", HeaderText = "Serial Number", DataPropertyName = "SerialNumber", AutoSizeMode = DataGridViewAutoSizeColumnMode.AllCells });
                    dgvDevices.Columns.Add(new DataGridViewTextBoxColumn { Name = "Udid", HeaderText = "UDID", DataPropertyName = "Udid", AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill });
                    dgvDevices.Columns.Add(new DataGridViewTextBoxColumn { Name = "Imei", HeaderText = "IMEI", DataPropertyName = "Imei", AutoSizeMode = DataGridViewAutoSizeColumnMode.AllCells });
                    dgvDevices.Columns.Add(new DataGridViewCheckBoxColumn { Name = "IsSimulatedLocked", HeaderText = "Locked?", DataPropertyName = "IsSimulatedLocked", AutoSizeMode = DataGridViewAutoSizeColumnMode.ColumnHeader });
                    dgvDevices.Columns.Add(new DataGridViewTextBoxColumn { Name = "SimulatedLockMessage", HeaderText = "Lock Message", DataPropertyName = "SimulatedLockMessage", AutoSizeMode = DataGridViewAutoSizeColumnMode.AllCells });
                    dgvDevices.Columns.Add(new DataGridViewTextBoxColumn { Name = "LastActivationAttemptTimestamp", HeaderText = "Last Seen", DataPropertyName = "LastActivationAttemptTimestamp", DefaultCellStyle = new DataGridViewCellStyle { Format = "yyyy-MM-dd HH:mm:ss" }, AutoSizeMode = DataGridViewAutoSizeColumnMode.AllCells });
                    dgvDevices.Columns.Add(new DataGridViewTextBoxColumn { Name = "FirstSeenTimestamp", HeaderText = "First Seen", DataPropertyName = "FirstSeenTimestamp", DefaultCellStyle = new DataGridViewCellStyle { Format = "yyyy-MM-dd HH:mm:ss" }, AutoSizeMode = DataGridViewAutoSizeColumnMode.AllCells });

                    dgvDevices.DataSource = devices;
                    Log($"Loaded {devices.Count} devices.");
                }
            }
            catch (Exception ex)
            {
                Log($"Error loading devices: {ex.Message}");
                MessageBox.Show($"Error loading devices: {ex.Message}", "Database Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            UpdateSelectedDeviceStatus();
        }

        private void BtnRefresh_Click(object sender, EventArgs e)
        {
            LoadDevices();
        }

        private void DgvDevices_SelectionChanged(object sender, EventArgs e)
        {
            UpdateSelectedDeviceStatus();
        }

        private void UpdateSelectedDeviceStatus()
        {
            if (dgvDevices.SelectedRows.Count > 0)
            {
                btnToggleLock.Enabled = true;
                DeviceRecord selectedDevice = dgvDevices.SelectedRows[0].DataBoundItem as DeviceRecord;
                if (selectedDevice != null)
                {
                    lblSelectedDevice.Text = $"Selected: {selectedDevice.ProductType} (S/N: {selectedDevice.SerialNumber}) - UDID: {selectedDevice.Udid.Substring(0, Math.Min(10, selectedDevice.Udid.Length))}...";
                    btnToggleLock.Text = selectedDevice.IsSimulatedLocked ? "Unlock Device" : "Lock Device";
                }
            }
            else
            {
                btnToggleLock.Enabled = false;
                lblSelectedDevice.Text = "";
            }
        }

        private void BtnToggleLock_Click(object sender, EventArgs e)
        {
            if (dgvDevices.SelectedRows.Count == 0)
            {
                MessageBox.Show("Please select a device from the list.", "No Device Selected", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            DeviceRecord selectedDevice = dgvDevices.SelectedRows[0].DataBoundItem as DeviceRecord;
            if (selectedDevice == null) return;

            try
            {
                using (var dbManager = new DatabaseManager())
                {
                    bool newLockStatus = !selectedDevice.IsSimulatedLocked;
                    string lockMessage = newLockStatus ? "This device was locked by the administrator via GUI." : null;

                    dbManager.ToggleDeviceLockStatus(selectedDevice.Id, newLockStatus, lockMessage);
                    Log($"Toggled lock for device ID {selectedDevice.Id} (UDID: {selectedDevice.Udid}) to {(newLockStatus ? "LOCKED" : "UNLOCKED")}.");
                }
                LoadDevices(); // Refresh the list to show updated status
            }
            catch (Exception ex)
            {
                Log($"Error toggling lock status for device ID {selectedDevice.Id}: {ex.Message}");
                MessageBox.Show($"Error toggling lock status: {ex.Message}", "Database Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }
    }
}
