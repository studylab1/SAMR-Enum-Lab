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

#### OpNum Descriptions
- **OpNum 0**: `SamrConnect` – Establishes an initial connection to the SAM server, allowing subsequent operations to be performed.
- **OpNum 1**: `SamrCloseHandle` – Closes an open handle to a SAM object, releasing the associated resources. 
- **OpNum 3**: `SamrQuerySecurityObject` – Retrieves security information for a specified SAM object, such as permissions and access control details. 
- **OpNum 5**: `SamrLookupDomainInSamServer` – Resolves a domain name to its corresponding SID within the SAM server.
- **OpNum 6**: `SamrEnumerateDomainsInSamServer` – Lists all domains managed by the SAM server.
- **OpNum 7**: `SamrOpenDomain` – Converts a list of account or domain names within a domain to their corresponding SIDs
- **OpNum 8**: `SamrQueryInformationDomain` – Retrieves specific information about a domain, such as security policies or account statistics, based on the requested information level.  
- **OpNum 11**: `SamrEnumerateGroupsInDomain` – Retrieves a list of groups within a specific domain.
- **OpNum 13**: `SamrEnumerateUsersInDomain` – Retrieves user accounts within a specific domain.
- **OpNum 15**: `SamrEnumerateAliasesInDomain` – Lists alias groups within a domain.
- **OpNum 16**: `SamrGetAliasMembership` – Shows alias memberships for a specific user or SID.
- **OpNum 17**: `SamrLookupNamesInDomain` – Converts account names into SIDs within a domain.
- **OpNum 18**: `SamrLookupIdsInDomain` – Maps SIDs back to account names.
- **OpNum 19**: `SamrOpenGroup` – Used to open a handle to a specific group, enabling operations on that group object.
- **OpNum 25**: `SamrGetMembersInGroup` – Retrieves the list of members for a given group, supporting group enumeration.
- **OpNum 27**: `SamrOpenAlias` – Opens a handle to a specific alias (local group), enabling operations on that alias object.
- **OpNum 33**: `SamrGetMembersInAlias` – Retrieves a list of members for a specified alias (local group).
- **OpNum 34**: `SamrOpenUser` – Opens a handle to a specific user account within a domain, allowing for further operations on the user object.
- **OpNum 36**: `SamrQueryInformationUser` – Retrieves detailed information on a specific user account.
- **OpNum 39**: `SamrGetGroupsForUser` – Lists all group memberships for a specified user.
- **OpNum 40**: `SamrQueryDisplayInformation` – Provides display information in a paginated format.
- **OpNum 41**: `SamrGetDisplayEnumerationIndex` – Retrieves the display index for paginated enumerations.
- **OpNum 47**: `SamrQueryInformationUser2` – Provides additional detailed information about a user account, similar to `SamrQueryInformationUser` but with different levels of information.
- **OpNum 51**: `SamrQueryDisplayInformation3` – Enables detailed and filtered queries for large-scale user, group, or machine account enumeration.
- **OpNum 56**: `SamrGetDomainPasswordInformation` – Retrieves password policy information for the domain.
- **OpNum 64**: `SamrConnect5` – Establishes a connection to the SAM server for domain enumeration and lookup. Typically required to establish a connection for SAMR communication.
- **OpNum 65**: `SamrRidToSid` – Converts a relative identifier (RID) to a security identifier (SID) within the domain.


### Attribute Parsing Completeness and Accuracy

This subsection evaluates the ability of tools to parse and display data attributes retrieved through SAMR operations. The analysis includes the completeness of the attributes retrieved for each SAMR operation and the accuracy of the values compared to expected results. Tools are assessed for handling expected data types, edge cases, and inconsistencies.

| **OpNum** | **Attribute** | **Expected Data Type**  | **Completeness** | **Accuracy** | **Remarks**   |
|-----------|---------------|-------------------------|------------------|--------------|---------------|

