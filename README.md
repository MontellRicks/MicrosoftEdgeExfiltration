# Threat Event (Unauthorized Keylogger Installation)  
**Unauthorized Revealer Keylogger Installation via Microsoft Edge**

## Reason for the Hunt:
**Unusual System Behavior + Management Directive**  
After IT observed abnormal process activity and unexpected outbound network connections from a test VM, management requested a targeted threat hunt. The user "nealthreatvm" was suspected of downloading unauthorized software using Microsoft Edge. The purpose of the hunt is to identify any potential data exfiltration activity and confirm whether a keylogger was installed and later removed.

---

## Steps the "Bad Actor" took to Create Logs and IoCs:
1. Opened **Microsoft Edge** and navigated to:  
   `https://www.logixoft.com/en/rkfree`
2. Downloaded **Revealer Keylogger Free** (`rkfree.exe`) to the Downloads folder.
3. Executed the installer to silently install the keylogger.
4. The keylogger started logging keystrokes and system usage.
5. Sensitive data was exfiltrated to a remote domain via the keylogger’s built-in C2 function.
6. The attacker deleted the `rkfree.exe` installer and removed the keylogger’s installation folder from AppData.

---

## Tables Used to Detect IoCs:

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceFileEvents |
| **Info**| [Microsoft Docs - DeviceFileEvents](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefileevents-table) |
| **Purpose**| Used to detect download of the keylogger `.exe`, creation of log files, and removal of files/folders after exfiltration. |

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceProcessEvents |
| **Info**| [Microsoft Docs - DeviceProcessEvents](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table) |
| **Purpose**| Used to detect execution of the keylogger process and any suspicious parent-child process relationships originating from Microsoft Edge. |

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceNetworkEvents |
| **Info**| [Microsoft Docs - DeviceNetworkEvents](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table) |
| **Purpose**| Used to detect outbound network connections made by the keylogger to its C2 domain/IP. |

---

## Related Queries:
```kql
// Detect Revealer Keylogger file download
DeviceFileEvents
| where FileName =~ "rkfree.exe"
| where InitiatingProcessFileName == "msedge.exe"
| project Timestamp, DeviceName, FileName, FolderPath, ActionType, InitiatingProcessCommandLine

// Detect rkfree.exe execution or keylogger process start
DeviceProcessEvents
| where FileName in~ ("rkfree.exe", "revealer.exe")
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine

// Detect creation or deletion of Revealer Keylogger logs or folders
DeviceFileEvents
| where FolderPath has "AppData\\Roaming\\RKL" or FileName contains "log"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath

// Detect outbound connections made by the keylogger
DeviceNetworkEvents
| where InitiatingProcessFileName in~ ("rkfree.exe", "revealer.exe")
| where RemoteUrl contains "logixoft" or RemoteIP != ""
| project Timestamp, DeviceName, InitiatingProcessAccountName, RemoteUrl, RemoteIP, RemotePort
