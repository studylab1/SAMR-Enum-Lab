# Metasploit Tool Evaluation

Metasploit is a penetration testing framework that provides various modules, including auxiliary tools, for conducting security assessments. In the context of SAMR enumeration requests, Metasploit offers modules to interact with the SAMR protocol, allowing testers to enumerate user accounts and computers objects on remote domain controllers.

## Request Specification Compliance in Detail

This evaluation analyzed compliance with the SAMR protocol's "Desired Access" field, focusing on access permissions requested during operations. The "Desired Access" field in the SAMR header specifies permissions requested for each operation.
The analysis followed the sequence of operations observed in the network traffic. 

Module used:  
- `auxiliary/scanner/smb/smb_enumusers`
- `auxiliary/admin/dcerpc/samr_account` LOOKUP_ACCOUNT for user and computer

**No SAMR requests specifying the “Desired Access” field were identified in the network traffic captures.**

## Completeness and Accuracy Comparison Criterion

This subsection evaluates the ability of tools to parse and display data attributes retrieved through SAMR operations. The analysis includes the completeness of the attributes retrieved for each SAMR operation and the accuracy of the values compared to expected results. Tools are assessed for handling expected data types, edge cases, and inconsistencies.

| **OpNum** | **OpNum Name**             | **SAMR Field Name**     | **Domain Attribute Name**  | **Expected Data Type**   | **Completeness** | **Field Displayed?** | **Accuracy** | **Field Description** |
|-----------|----------------------------|-------------------------|----------------------------|--------------------------|------------------|----------------------|--------------|----------------------|
| 8         | `QueryDomainInfo`          | `LockoutThreshold`         | `lockoutThreshold`          | Integer (32-bit)            | Yes       | Yes                  | Accurate     | Maximum failed login attempts before account lockout.                                |
| 8         | `QueryDomainInfo`          | `LockoutDuration`          | `lockoutDuration`           | Relative Time Structure     | N/A       | No                   | N/A          | Time (in ticks) that accounts remain locked after reaching lockout threshold.         |
| 8         | `QueryDomainInfo`          | `LockoutObservationWindow` | `lockoutWindow`             | Relative Time Structure     | N/A       | No                   | N/A          | Time window (in ticks) for failed login attempt observation before lockout occurs.    |
| 8         | `QueryDomainInfo`          | `MinPasswordLength`        | `minPasswordLength`         | Integer (32-bit)            | Yes       | Yes                  | Accurate     | Minimum number of characters required in a password.                                  |
| 8         | `QueryDomainInfo`          | `PasswordHistoryLength`    | `passwordHistoryLength`     | Integer (32-bit)            | N/A       | No                   | N/A          | Number of previous passwords that must not be reused.                                 |
| 8         | `QueryDomainInfo`          | `MaxPasswordAge`           | `maxPasswordAge`            | Relative Time Structure     | N/A       | No                   | N/A          | Maximum period a password can remain unchanged.                                       |
| 8         | `QueryDomainInfo`          | `MinPasswordAge`           | `minPasswordAge`            | Relative Time Structure     | N/A       | No                   | N/A          | Minimum period before a password can be changed.                                      |
| 8         | `QueryDomainInfo`          | `PasswordProperties`       | `passwordProperties`        | Bit Field (Flags)           | N/A       | No                   | N/A          | Flags indicating password policies such as complexity requirements.                   |
| 13        | `SamrEnumerateUsersInDomain`| `RelativeId`              | `objectSid`                 | Integer (32-bit)            | N/A       | No                   | N/A          | A unique identifier assigned to the user within the domain.                          |
| 13        | `SamrEnumerateUsersInDomain`| `Name`                    | `sAMAccountName`            | Unicode string (20 characters)| Yes     | Yes                  | Accurate     | A computer or service account name, logon name of the user.                          |
| 5         | `SamrLookupDomainInSamServer`| `DomainSID`              | `objectSid`                 | Security Identifier (SID)   | Yes       | Yes                  | Accurate     | The resulting SID corresponding to the domain name.                                   |
| 17        | `SamrLookupNames`           | `Rids`                 | `objectSid`                | Array of RIDs (Relative Identifiers) | Yes  | Yes                  | Accurate     | The RIDs associated with the input names, which are part of the full SIDs.          |
| 17        | `SamrLookupNames`           | `Types`                | N/A                        | Array of Integers        | N/A              | No                   | N/A          | Indicates the type of object (e.g., user, group, or alias) associated with the RID.     |
| 65        | `SamrQueryInformationUser` | `SID`                  | `objectSid`                 | Security Identifier      | Yes              | Yes                  | Accurate     | The security identifier (SID) corresponding to the provided RID.                     |
| 65        | `SamrQueryInformationUser` | `RID`                  | `RelativeId`                | Integer (32-bit)         | Yes              | Yes                  | Accurate     | A relative identifier within the domain used to construct the full SID.              |





