
![image (5)](https://github.com/user-attachments/assets/8a686a3b-791e-40f5-89dd-5d6586bb47d1)

# 🔍Use Case
**Detection of Internet-facing sensitive assets**

## Example Scenario:
During routine maintenance, the security team is tasked with investigating any VMs in the shared services cluster (handling DNS, Domain Services, DHCP, etc.) that have mistakenly been exposed to the public internet. The goal is to identify any misconfigured VMs and check for potential brute-force login attempts/successes from external sources. Internal shared services device (e.g., a domain controller) is mistakenly exposed to the internet due to misconfiguration.

---

## Table:
| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceInfo|
| **Info**| [Microsoft Defender Info](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table)|
| **Purpose**| The DeviceInfo table in the advanced hunting schema contains information about devices in the organization, including OS version, active users, and computer name.|

---

### **Timeline Overview**  
1. **🔍 Archiving Activity:**  
   - **Observed Behavior:**  Windows-target-1 has been internet-facing for several days. Last Internet facing time: `2025-01-06T19:15:05.9710276Z`
  
   - **Detection Query:**
   ```kql
   DeviceInfo
   //| where DeviceName == "ms-edr" // Optional for specific device(s)
   | where isnull(IsInternetFacing) or IsInternetFacing == false
   | project Timestamp, DeviceName, OSPlatform, PublicIP, IsInternetFacing
   | order by Timestamp desc
   ```

## Sample Output:
![Screenshot 2025-01-13 141429](https://github.com/user-attachments/assets/52e33697-5539-4614-8148-ea9da55fc4c5)

---

### Brute Force Attempts Detection

Several bad actors have been discovered attempting to log into the target machine.

```kql
DeviceLogonEvents
| where DeviceName == "windows-target-1"
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonFailed"
| where isnotempty(RemoteIP)
| summarize Attempts = count() by ActionType, RemoteIP, DeviceName
| order by Attempts
```

![Brute Force Attempt](https://github.com/user-attachments/assets/17ba8bdd-bd3b-4469-a374-15046cf45b1c)

---

The top 5 most failed login attempt IP addresses have not been able to successfully break into VM.

```kql
let RemoteIPsInQuestion = dynamic(["87.251.75.99","194.180.49.96", "194.180.48.11", "149.102.152.2", "141.98.11.191", "92.63.197.55", "185.7.214.87"]);
DeviceLogonEvents
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonSuccess"
| where RemoteIP has_any(RemoteIPsInQuestion)
```

**<Query no results>**

---

The only successful remote/network logins in the last 30 days for 'labuser' account (57 total):

```kql
DeviceLogonEvents
| where DeviceName == "windows-target-1"
| where LogonType == "Network"
| where ActionType == "LogonSuccess"
| where AccountName == "labuser"
| summarize count()
```

There were zero (0) failed logons for the 'labuser' account, indicating that a brute force attempt for this account didn't take place, and a 1-time password guess is unlikely.

```kql
DeviceLogonEvents
| where DeviceName == "windows-target-1"
| where LogonType == "Network"
| where ActionType == "LogonFailed"
| where AccountName == "labuser"
| summarize count()
```

---

We checked all of the successful login IP addresses for the 'labuser' account to see if any of them were unusual or from an unexpected location. All were normal.

```kql
DeviceLogonEvents
| where DeviceName == "windows-target-1"
| where LogonType == "Network"
| where ActionType == "LogonSuccess"
| where AccountName == "labuser"
| summarize LoginCount = count() by DeviceName, ActionType, AccountName, RemoteIP
```

![Successful Logins](https://github.com/user-attachments/assets/15512ee9-41d7-4fc2-8f5b-abae6948ff04)

---

Though the device was exposed to the internet and clear brute force attempts have taken place, there is no evidence of any brute force success or unauthorized access from the legitimate account 'labuser'.

Here's how the relevant TTPs and detection elements can be organized into a chart for easy reference:

---

# 🛡️ MITRE ATT&CK TTPs for Incident Detection

| **TTP ID** | **TTP Name**                     | **Description**                                                                                          | **Detection Relevance**                                                         |
|------------|-----------------------------------|----------------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------|
| T1071      | Application Layer Protocol        | Observing network traffic and identifying misconfigurations (e.g., device exposed to the internet).       | Helps detect exposed devices via application protocols, identifying misconfigurations. |
| T1075      | Pass the Hash                     | Failed login attempts suggesting brute-force or password spraying attempts.                               | Identifies failed login attempts from external sources, indicative of password spraying.  |
| T1110      | Brute Force                       | Multiple failed login attempts from external sources trying to gain unauthorized access.                 | Identifies brute-force login attempts and suspicious login behavior.            |
| T1046      | Network Service Scanning          | Exposure of internal services to the internet, potentially scanned by attackers.                         | Indicates potential reconnaissance and scanning by external actors.            |
| T1021      | Remote Services                   | Remote logins via network/interactive login types showing external interaction attempts.                   | Identifies legitimate and malicious remote service logins to an exposed device.  |
| T1070      | Indicator Removal on Host         | No indicators of success in the attempted brute-force attacks, showing system defenses were effective.     | Confirms the lack of successful attacks due to effective defense measures.      |
| T1213      | Data from Information Repositories| Device exposed publicly, indicating potential reconnaissance activities.                                  | Exposes possible adversary reconnaissance when a device is publicly accessible.  |
| T1078      | Valid Accounts                    | Successful logins from the legitimate account ('labuser') were normal and monitored.                      | Monitors legitimate access and excludes unauthorized access attempts.           |

---

This chart clearly organizes the MITRE ATT&CK techniques (TTPs) used in this incident, detailing their relevance to the detection process.

**📝 Response:**  
- Hardened the NSG attached to windows-target-1 to allow only RDP traffic from specific endpoints (no public internet access), Implemented account lockout policy, Implemented MFA, awaiting further instructions.

---

## Steps to Reproduce:
1. Provision a virtual machine with a public IP address.
2. Ensure the device is actively communicating or available on the internet. (Test ping, etc.)
3. Onboard the device to Microsoft Defender for Endpoint.
4. Verify the relevant logs (e.g., network traffic logs, exposure alerts) are being collected in MDE.
5. Execute the KQL query in the MDE advanced hunting to confirm detection.

---

## Supplemental:
- **More on "Shared Services" in the context of PCI DSS**: [PCI DSS Scoping and Segmentation](https://www.pcisecuritystandards.org%2Fdocuments%2FGuidance-PCI-DSS-Scoping-and-Segmentation_v1.pdf)

---

## Created By:
- **Author Name**: Trevino Parker  
- **Author Contact**: [LinkedIn](https://www.linkedin.com/in/trevinoparker/)  
- **Date**: Jan 2025

## Validated By:
- **Reviewer Name**: Josh Madakor  
- **Reviewer Contact**: [LinkedIn](https://www.linkedin.com/in/joshmadakor/)  
- **Validation Date**: Jan 2025

---

## Additional Notes:
- **None**

---

## Revision History:
| **Version** | **Changes**                   | **Date**         | **Modified By**   |
|-------------|-------------------------------|------------------|-------------------|
| 1.0         | Initial draft                  | `Jan 2025`    | `Trevino Parker`   |
```

