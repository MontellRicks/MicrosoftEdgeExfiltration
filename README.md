# Threat Event (Unauthorized Keylogger Installation)  
**Unauthorized Revealer Keylogger Installation via Microsoft Edge by User `nealthreatvm`**

## Reason for the Hunt:
**Unusual System Behavior + Management Directive**  
On April 11, 2025, IT detected suspicious outbound connections from a VM registered under the user `nealthreatvm`. Management issued a directive to investigate possible data exfiltration or policy violations. A threat hunt was initiated to determine whether any unauthorized software, such as keyloggers, had been installed and executed using Microsoft Edge.

---

## Timeline of Events (April 11, 2025)

| **Time (UTC)** | **Event** |
|----------------|-----------|
| 10:02:13 AM | Microsoft Edge launched by user `nealthreatvm` |
| 10:04:27 AM | Visited `https://www.logixoft.com/en/rkfree` |
| 10:05:10 AM | Downloaded file `rkfree.exe` to `C:\Users\nealthreatvm\Downloads\` |
| 10:06:31 AM | Executed `rkfree.exe`, triggering silent installation of Revealer Keylogger |
| 10:07:45 AM | Created `revealer.exe` in `C:\Users\nealthreatvm\AppData\Roaming\RKL\` |
| 10:08:55 AM | Keylogger began capturing input and writing logs to disk |
| 10:14:21 AM | Outbound connection initiated to `logixoft.com` (C2 callback suspected) |
| 10:29:03 AM | Deleted `rkfree.exe` installer from Downloads folder |
| 10:30:40 AM | Deleted `RKL` folder and associated log files manually |

---

## Tables Used to Detect IoCs:

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceFileEvents |
| **Info**| [Microsoft Docs - DeviceFileEvents](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefileevents-table) |
| **Purpose**| Detects keylogger installer download, log file creation, and manual deletion of evidence. |

| **Name**| DeviceProcessEvents |
| **Info**| [Microsoft Docs - DeviceProcessEvents](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table) |
| **Purpose**| Captures execution of suspicious binaries and parent-child process relationships initiated by Microsoft Edge. |

| **Name**| DeviceNetworkEvents |
| **Info**| [Microsoft Docs - DeviceNetworkEvents](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table) |
| **Purpose**| Detects suspicious outbound communication attempts by unauthorized tools. |

---

## Related Queries:
```kql
// Detect download of Revealer Keylogger installer by nealthreatvm on device nealthreatvm
DeviceFileEvents
| where DeviceName == "nealthreatvm"
| where FileName =~ "rkfree.exe"
| where InitiatingProcessFileName == "msedge.exe"
| where InitiatingProcessAccountName == "nealthreatvm"
| project Timestamp, DeviceName, FileName, FolderPath, ActionType, InitiatingProcessCommandLine

// Detect rkfree.exe execution or Revealer Keylogger launched by nealthreatvm on device nealthreatvm
DeviceProcessEvents
| where DeviceName == "nealthreatvm"
| where AccountName == "nealthreatvm"
| where FileName in~ ("rkfree.exe", "revealer.exe")
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine

// Detect log file creation or folder deletion related to Revealer Keylogger
DeviceFileEvents
| where DeviceName == "nealthreatvm"
| where AccountName == "nealthreatvm"
| where FolderPath has "AppData\\Roaming\\RKL" or FileName contains "log"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath

// Detect outbound connections made by Revealer Keylogger from device nealthreatvm
DeviceNetworkEvents
| where DeviceName == "nealthreatvm"
| where InitiatingProcessAccountName == "nealthreatvm"
| where InitiatingProcessFileName in~ ("rkfree.exe", "revealer.exe")
| where RemoteUrl contains "logixoft" or RemoteIP != ""
| project Timestamp, DeviceName, InitiatingProcessAccountName, RemoteUrl, RemoteIP, RemotePort
