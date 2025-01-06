# Use Case
**Detection of Internet-facing sensitive assets**

## Example Scenario:
Internal shared services device (e.g., a domain controller) is mistakenly exposed to the internet due to misconfiguration.

---

## Table:
| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceInfo|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table|
| **Purpose**| The DeviceInfo table in the advanced hunting schema contains information about devices in the organization, including OS version, active users, and computer name.|

---

## Detection Query:
```kql
DeviceInfo
//| where DeviceName == "ms-edr" // Optional for specific device(s)
| where isnull(IsInternetFacing) or IsInternetFacing == false
| project Timestamp, DeviceName, OSPlatform, PublicIP, IsInternetFacing
| order by Timestamp desc
```

## Sample Output:
<img width="760" alt="image" src="https://github.com/user-attachments/assets/0681069a-2f5f-4beb-9253-ae89558b1981">

---

**📝 Response:**  
   - Shared findings with the manager, the device was isolated, awaiting further instructions.

## Steps to Reproduce:
1. Provision a virtual machine with a public IP address
2. Ensure the device is actively communicating or available on the internet. (Test ping, etc.)
3. Onboard the device to Microsoft Defender for Endpoint
4. Verify the relevant logs (e.g., network traffic logs, exposure alerts) are being collected in MDE.
5. Execute the KQL query in the MDE advanced hunting to confirm detection.

---

## Supplemental:
- **More on "Shared Services" in the context of PCI DSS**: [PCI DSS Scoping and Segmentation](https://www.pcisecuritystandards.org%2Fdocuments%2FGuidance-PCI-DSS-Scoping-and-Segmentation_v1.pdf)

---

## Created By:
- **Author Name**: Trevino Parker
- **Author Contact**: https://www.linkedin.com/in/trevinoparker/
- **Date**: Jan 1, 2025

## Validated By:
- **Reviewer Name**: Josh Madakor
- **Reviewer Contact**: https://www.linkedin.com/in/joshmadakor/
- **Validation Date**: Jan 1, 2025

---

## Additional Notes:
- **None**

---

## Revision History:
| **Version** | **Changes**                   | **Date**         | **Modified By**   |
|-------------|-------------------------------|------------------|-------------------|
| 1.0         | Initial draft                  | `Jan 1, 2025`  | `Trevino Parker`   
