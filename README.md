# Threat Event (Unauthorized Chrome Extension Abuse)  
**Malicious Google Chrome Extension Installation and Use**

## Reason for the Hunt:
**Management Directive following Cybersecurity News Alert**  
After multiple cybersecurity outlets reported on malicious Chrome extensions capable of stealing data and monitoring user behavior, management requested a threat hunt across all endpoints to detect unauthorized or suspicious Chrome extensions—especially those not approved by IT or installed outside the Chrome Web Store.

---

## Steps the "Bad Actor" took to Create Logs and IoCs:
1. Downloaded a suspicious Chrome extension `.crx` file from a third-party website.
2. Enabled **Developer Mode** in Chrome and manually installed the extension.
3. The extension began logging user keystrokes and browsing behavior.
4. The attacker browsed internal company systems to capture sensitive information.
5. The extension attempted to connect to an external C2 (Command and Control) server (e.g., `http://malicious-extension-leak[.]xyz/api/steal`)
6. A temporary local storage file `extension-activity-log.json` was created.
7. The user deleted the `.crx` installer afterward.

---

## Tables Used to Detect IoCs:

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceFileEvents |
| **Info**| [Microsoft Docs - DeviceFileEvents](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefileevents-table) |
| **Purpose**| Used to detect the download of the `.crx` file, creation of local extension logs, and deletion of artifacts. |

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceProcessEvents |
| **Info**| [Microsoft Docs - DeviceProcessEvents](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table) |
| **Purpose**| Used to detect Chrome processes launched in **Developer Mode** or with unusual command-line arguments. |

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceNetworkEvents |
| **Info**| [Microsoft Docs - DeviceNetworkEvents](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table) |
| **Purpose**| Used to detect outbound connections made by Chrome to suspicious or blacklisted domains. |

---

## Related Queries:
```kql
// Detect download of any .crx extension file
DeviceFileEvents
| where FileName endswith ".crx"
| project Timestamp, DeviceName, FileName, FolderPath, ActionType, InitiatingProcessCommandLine

// Detect manual Chrome launches with Developer Mode enabled
DeviceProcessEvents
| where FileName =~ "chrome.exe"
| where ProcessCommandLine has " --enable-extensions" and ProcessCommandLine has "--load-extension"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine

// Detect creation or deletion of log file associated with extension
DeviceFileEvents
| where FileName contains "extension-activity-log.json"
| project Timestamp, DeviceName, FileName, FolderPath, ActionType

// Detect outbound connection to suspicious domain from Chrome
DeviceNetworkEvents
| where InitiatingProcessFileName == "chrome.exe"
| where RemoteUrl has_any ("malicious-extension-leak.xyz", "api.stealer-extension.net")
| project Timestamp, DeviceName, InitiatingProcessAccountName, RemoteUrl, RemoteIP, RemotePort
