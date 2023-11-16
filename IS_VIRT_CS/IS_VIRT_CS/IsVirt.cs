//
// C#
// IS_VIRT_CS
// v 0.2, 16.11.2023
// https://github.com/dkxce/Detect-Virtual-Machine
// en,ru,1251,utf-8
//

using System;
using System.IO;
using System.Management;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using System.Security;
using Microsoft.Win32;

public class Virtualization
{
    [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    private static extern IntPtr CreateFile(
            [MarshalAs(UnmanagedType.LPTStr)] string filename,
            [MarshalAs(UnmanagedType.U4)] FileAccess access,
            [MarshalAs(UnmanagedType.U4)] FileShare share,
            IntPtr securityAttributes, // optional SECURITY_ATTRIBUTES struct or IntPtr.Zero
            [MarshalAs(UnmanagedType.U4)] FileMode creationDisposition,
            [MarshalAs(UnmanagedType.U4)] FileAttributes flagsAndAttributes,
            IntPtr templateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
    [SuppressUnmanagedCodeSecurity]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr hObject);

    public static bool IsVirtualMachine(ConnectionOptions options = null, ManagementScope scope = null)
    {
        bool isVirt = false;
        try
        {
            if (true) // Try Registry
            {
                try
                {
                    IntPtr handle = CreateFile("\\\\.\\VBoxMiniRdrDN", FileAccess.Read, FileShare.Read, IntPtr.Zero, FileMode.Open, FileAttributes.Normal, IntPtr.Zero);
                    if (handle != new IntPtr(-1)) { CloseHandle(handle); isVirt = true; };
                }
                catch { };
                if (isVirt) return isVirt;

                try
                {
                    RegistryKey regKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Default);
                    RegistryKey subKey = regKey.OpenSubKey("SOFTWARE\\VMware, Inc.\\VMware Tools", RegistryKeyPermissionCheck.ReadSubTree);
                    if (subKey != null) { subKey.Close(); isVirt = true; };
                    regKey.Close();
                }
                catch { };
                if (isVirt) return isVirt;
            };

            if (true) // Try WMI
            {
                const string root = "root\\CIMV2";
                if (options == null) options = new ConnectionOptions() { EnablePrivileges = true };
                if (scope == null) { scope = new ManagementScope(ManagementPath.DefaultPath, options); scope.Connect(); };
                ManagementObjectSearcher mos = null;

                if (!isVirt)
                    using (mos = new ManagementObjectSearcher(root, "SELECT * FROM Win32_ComputerSystem"))
                    {
                        foreach (ManagementObject mo in mos.Get())
                        {
                            string manufacturer = ""; string model = "";
                            try { manufacturer = mo["Manufacturer"]?.ToString().ToUpper(); } catch { };
                            try { model = mo["Model"]?.ToString().ToUpper(); } catch { };
                            if (string.IsNullOrEmpty(manufacturer)) manufacturer = "";
                            if (string.IsNullOrEmpty(model)) model = "";

                            // Hyper-V
                            if (manufacturer.Contains("MICROSOFT") && model.Contains("VIRTUAL")) isVirt = true;
                            // VMWare
                            if (manufacturer.Contains("VMWARE")) isVirt = true;
                            // VirtualBox
                            if (model == "VIRTUALBOX") isVirt = true;
                            if (model == "VIRTUAL MACHINE") isVirt = true;
                            // WMWare
                            if (model.StartsWith("VMWARE")) isVirt = true;
                        };
                    };
                if (!isVirt)
                    using (mos = new ManagementObjectSearcher(root, "SELECT * FROM Win32_processor"))
                    {
                        foreach (ManagementObject mo in mos.Get())
                        {
                            string processor = "";
                            try { processor = mo["Manufacturer"]?.ToString().ToUpper(); } catch { continue; };
                            if (string.IsNullOrEmpty(processor)) processor = "";

                            // VBox
                            if (processor.Contains("VBOXVBOXVBOX")) isVirt = true;
                            // VMWare
                            if (processor.Contains("VMWAREVMWARE")) isVirt = true;
                            // Hyper-V
                            if (processor.Contains("PRL HYPERV")) isVirt = true;
                        };
                    };
                if (!isVirt)
                    using (mos = new ManagementObjectSearcher(root, "SELECT * FROM Win32_BaseBoard"))
                    {
                        foreach (ManagementObject mo in mos.Get())
                        {
                            string baseboard = "";
                            try { baseboard = mo["Manufacturer"]?.ToString().ToUpper(); } catch { continue; };
                            if (string.IsNullOrEmpty(baseboard)) baseboard = "";

                            // Hyper-V
                            if (baseboard == "MICROSOFT CORPORATION") isVirt = true;
                        };
                    };
                if (!isVirt)
                    using (mos = new ManagementObjectSearcher(root, "SELECT * FROM Win32_BIOS"))
                    {
                        foreach (ManagementObject mo in mos.Get())
                        {
                            string bios_sn = "";
                            try { bios_sn = mo["SerialNumber"]?.ToString().ToUpper(); } catch { continue; };
                            if (string.IsNullOrEmpty(bios_sn)) bios_sn = "";

                            // Hyper-V
                            if (bios_sn.Contains("VMWARE")) isVirt = true;
                        };
                    };
                if (!isVirt)
                    using (mos = new ManagementObjectSearcher(root, "SELECT * FROM Win32_DiskDrive"))
                    {
                        foreach (ManagementObject mo in mos.Get())
                        {
                            string disk_model = ""; string disk_device = "";
                            try { disk_model = mo["Model"]?.ToString().ToUpper(); } catch { };
                            try { disk_device = mo["PNPDeviceID"]?.ToString().ToUpper(); } catch { };
                            if (string.IsNullOrEmpty(disk_model)) disk_model = "";
                            if (string.IsNullOrEmpty(disk_device)) disk_device = "";

                            // Hyper-V
                            if (disk_model.Contains("VIRTUAL")) isVirt = true;
                            // VMWARE / VEN_VMWARE
                            if (disk_model.Contains("VMWARE")) isVirt = true;
                            // VMWARE / VEN_VMWARE
                            if (disk_device.Contains("VEN_VMWARE")) isVirt = true;
                            // QEmu
                            if (disk_model.Contains("QEMU")) isVirt = true;
                            // VBox / VBOX_HARDDISK
                            if (disk_model.Contains("VBOX")) isVirt = true;
                            // VBox / VBOX_HARDDISK
                            if (disk_device.Contains("VBOX_HARDDISK")) isVirt = true;
                        };
                    };
                if (!isVirt)
                    using (mos = new ManagementObjectSearcher(root, "SELECT * FROM Win32_PnPEntity"))
                    {
                        foreach (ManagementObject mo in mos.Get())
                        {
                            string pnp_device = "";
                            try { pnp_device = mo["Name"]?.ToString().ToUpper(); } catch { continue; };
                            if (string.IsNullOrEmpty(pnp_device)) pnp_device = "";

                            // VMWare
                            if (pnp_device == "VMWARE POINTING DEVICE") isVirt = true;
                            if (pnp_device == "VMWARE USB POINTING DEVICE") isVirt = true;
                            if (pnp_device == "VMWARE VMCU BUS DEVICE") isVirt = true;
                            if (pnp_device == "VMWARE VIRTUAL S SCSI DISK DEVICE") isVirt = true;
                            if (pnp_device.Contains("VMWARE SATA")) isVirt = true;
                            if (pnp_device.StartsWith("VMWARE SVGA")) isVirt = true;
                            // Virtual Box
                            if (pnp_device.Contains("VBOX")) isVirt = true;
                        };
                    };
                if (!isVirt)
                    using (mos = new ManagementObjectSearcher(root, "SELECT * FROM Win32_Service"))
                    {
                        foreach (ManagementObject mo in mos.Get())
                        {
                            string service = "";
                            try { service = mo["Name"]?.ToString().ToUpper(); } catch { continue; };
                            if (string.IsNullOrEmpty(service)) service = "";

                            // VMWare
                            if (service == "WMTOOLS") isVirt = true;
                            if (service == "TPVCGATEWAY") isVirt = true;
                            if (service == "TPAUTOCONNSVC") isVirt = true;
                            // Virtual PC
                            if (service.Contains("VPCMAP")) isVirt = true;
                            if (service.Contains("WMSRVC")) isVirt = true;
                            if (service.Contains("VMUSRVC")) isVirt = true;
                            // VBox
                            if (service.Contains("VBOXSERVICE")) isVirt = true;
                        };
                    };
            };
        }
        catch { };
        return isVirt;
    }
}