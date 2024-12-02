# SAMR Enumeration Tools Comparison

This page provides a comparison of tools used for SAMR enumeration in Active Directory environments. Each tool's specifications, supported SAMR operations (OpNums), compatibility, and limitations are documented. This data was collected to show how different tools access, retrieve, and handle SAMR data, including in cross-forest configurations.

## Table of Contents
1. [Introduction](#introduction)
2. [System Configuration and Enumeration Vector](#system-configuration-and-enumeration-vector)
3. [Tool Versions and Specifications](#tool-versions-and-specifications)
4. [Criteria for Tool Evaluation](#criteria-for-tool-evaluation)
5. [Tool Comparison Results](#tool-comparison-results)
   - [Evaluation of Tool Comparison Criteria](#evaluation-of-tool-comparison-criteria)
   - [Detailed Evaluation of OpNum Coverage](#detailed-evaluation-of-opnum-coverage)
6. [OpNum Descriptions](#opnum-descriptions)

---

## Introduction

This comparison covers tools used for Active Directory reconnaissance through the SAMR protocol, which retrieves information on users, groups, domains, and other security settings.

## System Configuration and Enumeration Vector
The detailed configuration of the lab is specified on the Lab Setup page.  
Other aspects to specify are as follows:  
- **Domain Functional Level**: Windows Server 2016.
- **Forest Functional Level**: Windows Server 2016.

The lab environment was established with two one-way forest trusts between `domain-y.local` and `domain-z.local`, configured with forest-wide authentication. The SAMR enumeration scan was conducted from workstation `yws1` to `zdc1` domain controller in cases where tools supported cross-forest requests and from workstation `yws1` to `ydc1` domain controller where they did not.
The data on `ydc1` and `zdc1` were populated using the BadBlood tool.

## Tool Versions and Specifications

The following table provides version numbers for the tools evaluated during this research.

| Tool Name           | Version       | Additional Notes                    |
|---------------------|---------------|-------------------------------------|
| net user            | Built-in      | Windows 11 Enterprise x86-64 (version 23H2, OS build 22631.4317)    |
| net group           | Built-in      | Windows 11 Enterprise x86-64 (version 23H2, OS build 22631.4317)    |
| PowerShell         | 1.0.1.0           | ActiveDirectory Module. Windows 11 Enterprise x86-64 (version 23H2, OS build 22631.4317) |
| Impacket            | 0.12.0    | For this research, only samrdump.py and net.py from the Impacket suite were used.      |
| CrackMapExec        |          |  |
| rpcclient    |         | Part of the Samba suite          |
| smbclient    |         | Part of the Samba suite        |
| BloodHound          |          |          |
| Nmap   |           | Part of the Nmap suite              |
| Enum4linux          |          |    |
| Enum4linux-ng       |          |      |
| Metasploit|     |  Part of the Metasploit Framework                |
| PowerSploit         |          |             |
| SAMRi10             |          |  |
| RPC Investigator    |          |     |

## Criteria for Tool Evaluation

The following criteria were used to evaluate each tool's SAMR enumeration capabilities:

- **OpNum Coverage**: Lists supported SAMR operation numbers.
- **Cross-forest Support**: Indicates if the tool can perform enumeration across domains within a forest trust.
- **Permissions Compliance**: Specifies the default access permissions required by each tool.
- **Error Handling**: Describes the tool’s ability to handle restricted permissions or errors.
- **Authentication Methods**: Details whether NTLM, Kerberos, or both protocols are supported.
- **Access Level Requirements**: Specifies whether administrator privileges are required for operation.

---

## Tool Comparison Results 

### Evaluation of Tool Comparison Criteria
> **Note:** The evaluation results focus on analyzing tools’ support for cross-forest SAMR requests. If a tool does not support cross-forest SAMR requests or uses a different protocol for such requests, other evaluation criteria are not assessed, and the corresponding values are marked as N/A (Not Applicable).


---

| Tool Name             | Cross-Forest Request Support | OpNum Coverage | Excessive Permission Detection | Data Parsing and Accuracy | Supported Authentication Types | Access Level Requirements |
|-----------------------|-----------------------------|----------------|-------------------------------|---------------------------|-------------------------------|---------------------------|
| net user              |  No                           | N/A            | N/A                           | N/A                       | N/A                           | N/A                       |
| PowerShell            |  Yes                         | N/A            | N/A                           | N/A                       | N/A                           | N/A                       |
| Impacket              |  Yes                         |  Moderate      |  Yes                           |                           |   NTLM and Kerberos           | Standard Access    |
| CrackMapExec          |                             |                |                               |                           |                               |                      |
| rpcclient      |                             |                |                               |                           |                               |                           |
| smbclient     |                             |                |                               |                           |                               |                           |
| BloodHound            |                             |                |                               |                           |                               |                    |
| Nmap   |                             |                |                               |                           |                               |                           |
| Enum4linux            |                             |                |                               |                           |                               |                     |
| Enum4linux-ng         |                             |                |                               |                           |                               |                      |
| Metasploit   |                             |                |                               |                           |                               |                           |
| PowerSploit           |                             |                |                               |                           |                               |                        |
| SAMRi10               |                             |                |                               |                           |                               |                        |
| RPC Investigator      |                             |                |                               |                           |                               |                        |

---

### Detailed Evaluation of OpNum Coverage
> **Note:** The evaluation results in this section are based on cross-forest SAMR requests.  

⚫️ - Supported  
○ - Not Supported


| Tool \ OpNum         | 0  | 1  | 3  | 5  | 6  | 7  | 8  | 11 | 13 | 15 | 16 | 17 | 18 | 19 | 25 | 27 | 33 | 34 | 36 | 39 | 40 | 41 | 47 | 51 | 56 | 64 | 65 |
|----------------------|----|----|----|----|----|----|----|----|----|----|----|----|----|----|----|----|----|----|----|----|----|----|----|----|----|----|----|
| "net user", "net group" | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○ |
| PowerShell           | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  |
| Impacket             | ●  | ●  | ○  | ●  | ●  | ●  | ○  | ●  | ●  | ●  | ●  | ●  | ●  | ●  | ●  | ●  | ●  | ●  | ○  | ●  | ○  | ○  | ●  | ○  | ○  | ○  | ●  |
| CrackMapExec         |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |
| rpcclient            |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |
| smbclient            |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |
| BloodHound           |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |
| Nmap                 |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |
| Enum4linux           |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |
| Enum4linux-ng        |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |
| Metasploit           |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |
| PowerSploit          |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |
| SAMRi10              |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |
| RPC Investigator     |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |

---

The table below provides an overview of SAMR operation numbers (OpNums) relevant to enumeration. Each OpNum represents a specific operation that can be performed through the SAMR protocol. The table includes the following details for each OpNum:
- OpNum: The unique identifier for the operation.
- Name: The official name of the operation.
- Data Type in Response: The format of the data returned in response to the operation.
- Description: A brief explanation of the operation’s functionality and purpose.

| **OpNum** | **Name**                       | **Data Type in Response**             | **Description**                                                                                   |
|-----------|--------------------------------|----------------------------------------|---------------------------------------------------------------------------------------------------|
| 0         | `SamrConnect`                 | Handle                                | Establishes an initial connection to the SAM server, allowing subsequent operations to be performed. |
| 1         | `SamrCloseHandle`             | N/A                                   | Closes an open handle to a SAM object, releasing the associated resources.                        |
| 3         | `SamrQuerySecurityObject`     | Security Descriptor                   | Retrieves security information for a specified SAM object, such as permissions and access control details. |
| 5         | `SamrLookupDomainInSamServer` | SID                                   | Resolves a domain name to its corresponding SID within the SAM server.                            |
| 6         | `SamrEnumerateDomainsInSamServer` | List of Strings                       | Lists all domains managed by the SAM server.                                                     |
| 7         | `SamrOpenDomain`              | Handle                                | Opens a handle to a specific domain for further operations.                                       |
| 8         | `SamrQueryInformationDomain`  | Varies (based on Information Level)   | Retrieves specific information about a domain, such as security policies or account statistics.   |
| 11        | `SamrEnumerateGroupsInDomain` | List of Strings and Integers          | Retrieves a list of group names (strings) and their RIDs (relative identifiers, integers).        |
| 13        | `SamrEnumerateUsersInDomain`  | List of Strings and Integers          | Retrieves user account names (strings) and their RIDs (relative identifiers, integers).           |
| 15        | `SamrEnumerateAliasesInDomain`| List of Strings and Integers          | Lists alias groups (local groups) within a domain along with their RIDs.                         |
| 16        | `SamrGetAliasMembership`      | List of SIDs                          | Shows alias memberships for a specific user or SID.                                              |
| 17        | `SamrLookupNamesInDomain`     | List of SIDs                          | Converts account names into SIDs within a domain.                                                |
| 18        | `SamrLookupIdsInDomain`       | List of Strings                       | Maps SIDs back to account names.                                                                 |
| 19        | `SamrOpenGroup`               | Handle                                | Opens a handle to a specific group for further operations.                                       |
| 25        | `SamrGetMembersInGroup`       | List of Integers                      | Retrieves the list of members' RIDs for a given group.                                           |
| 27        | `SamrOpenAlias`               | Handle                                | Opens a handle to a specific alias (local group) for further operations.                         |
| 33        | `SamrGetMembersInAlias`       | List of SIDs                          | Retrieves a list of members for a specified alias (local group).                                 |
| 34        | `SamrOpenUser`                | Handle                                | Opens a handle to a specific user account for further operations.                                |
| 36        | `SamrQueryInformationUser`    | Varies (based on Information Level)   | Retrieves detailed information on a specific user account.                                       |
| 39        | `SamrGetGroupsForUser`        | List of Integers                      | Lists all group memberships for a specified user.                                                |
| 40        | `SamrQueryDisplayInformation` | Paginated List of Strings             | Provides display information (e.g., names) for a set of domain accounts, such as users or groups.|
| 41        | `SamrGetDisplayEnumerationIndex` | Integer                              | Retrieves the display index for paginated enumerations.                                          |
| 47        | `SamrQueryInformationUser2`   | Varies (based on Information Level)   | Provides additional detailed information about a user account, similar to `SamrQueryInformationUser`.|
| 51        | `SamrQueryDisplayInformation3`| Paginated and Filtered List of Strings| Enables detailed and filtered queries for large-scale user, group, or machine account enumeration.|
| 56        | `SamrGetDomainPasswordInformation` | Structure                           | Retrieves password policy information for the domain.                                            |
| 64        | `SamrConnect5`                | Handle                                | Establishes a connection to the SAM server for domain enumeration and lookup.                   |
| 65        | `SamrRidToSid`                | SID                                   | Converts a relative identifier (RID) to a security identifier (SID) within the domain.          |


### Attribute Parsing Completeness and Accuracy
The following table represents mapping between SAMR Protocol Attributes and LDAP Domain Object Attributes for understanding how enumeration data retrieved via SAMR corresponds to the underlying Active Directory schema. SAMR protocol attributes are designed for remote access and use different naming conventions than LDAP, which is the standard protocol for accessing directory information.

| **SAMR Attribute (Protocol)**       | **LDAP Attribute (Active Directory)** | **Description**                                   |
|-------------------------------------|---------------------------------------|-------------------------------------------------|
| `UserName`                          | `sAMAccountName`                     | The user's account name (logon name).           |
| `FullName`                          | `displayName`                        | The full name of the user.                      |
| `HomeDirectory`                     | `homeDirectory`                      | The user's home directory path.                 |
| `HomeDrive`                         | `homeDrive`                          | The drive letter for the home directory.        |
| `ScriptPath`                        | `scriptPath`                         | The path of the user's logon script.            |
| `AdminComment`                      | `description`                        | An administrator's comment about the user.      |
| `UserAccountControl` (UAC Flags)    | `userAccountControl`                 | Flags controlling the user's account behavior.  |
| `PrimaryGroupId`                    | `primaryGroupID`                     | The RID of the user's primary group.            |
| `BadPasswordCount`                  | `badPwdCount`                        | The number of recent bad password attempts.     |
| `LogonCount`                        | `logonCount`                         | The number of times the user has logged on.     |
| `LastLogon`                         | `lastLogon`                          | The last time the user successfully logged on.  |
| `LogoffTime`                        | `logoffTime`                         | The user's expected logoff time.                |
| `PasswordLastSet`                   | `pwdLastSet`                         | The last time the user's password was changed.  |

---

This subsection evaluates the ability of tools to parse and display data attributes retrieved through SAMR operations. The analysis includes the completeness of the attributes retrieved for each SAMR operation and the accuracy of the values compared to expected results. Tools are assessed for handling expected data types, edge cases, and inconsistencies.

| **OpNum** | **Attribute** | **Expected Data Type**  | **Completeness** | **Accuracy** | **Remarks**   |
|-----------|---------------|-------------------------|------------------|--------------|---------------|

