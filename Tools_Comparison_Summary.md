# SAMR Enumeration Tools Comparison

This page provides a comparison of tools used for SAMR enumeration in Active Directory environments. Each tool's specifications, supported SAMR operations (OpNums), compatibility, and limitations are documented. This data was collected to show how different tools access, retrieve, and handle SAMR data, including in multi-forest configurations.

## Table of Contents
1. [Introduction](#introduction)
2. [System Configuration and Enumeration Vector](#system-configuration-and-enumeration-vector)
3. [Tool Versions and Specifications](#tool-versions-and-specifications)
4. [Criteria for Tool Evaluation](#criteria-for-tool-evaluation)
5. [Tool Comparison Results](#tool-comparison-results)
   - [Evaluation of Tool Comparison Criteria](#evaluation-of-tool-comparison-criteria)
   - [Detailed Evaluation of OpNum Coverage](#detailed-evaluation-of-opnum-coverage)
6. [OpNum Descriptions](#opnum-descriptions)
7. [Evaluation of "Desired Access" Compliance in Detail](#evaluation-of-desired-access-compliance-in-detail)
   - ["net user" (to local domain controller)](#net-user-to-local-domain-controller)
   - ["net group" (to local domain controller)](#net-group-to-local-domain-controller)
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
| PowerShell          |            |  |
| Impacket            |         |          |
| CrackMapExec        |          |  |
| rpcclient (Samba)   |         |          |
| smbclient (Samba)   |         |         |
| BloodHound          |          |          |
| Nmap (NSE Scripts)  |           |               |
| Enum4linux          |          |    |
| Enum4linux-ng       |          |      |
| Metasploit Framework|     |                  |
| PowerSploit         |          |             |
| SAMRi10             |          |  |
| RPC Investigator    |          |     |

## Criteria for Tool Evaluation

The following criteria were used to evaluate each tool's SAMR enumeration capabilities:

- **OpNum Coverage**: Lists supported SAMR operation numbers.
- **Multi-forest Support**: Indicates if the tool can perform enumeration across domains within a forest trust.
- **Permissions Compliance**: Specifies the default access permissions required by each tool.
- **Error Handling**: Describes the tool’s ability to handle restricted permissions or errors.
- **Authentication Methods**: Details whether NTLM, Kerberos, or both protocols are supported.
- **Access Level Requirements**: Specifies whether administrator privileges are required for operation.

---

## Tool Comparison Results 

### Evaluation of Tool Comparison Criteria
> **Note:** The evaluation results in this section are based on cross-forest SAMR requests. If a tool does not support cross-forest requests or uses a different protocol for cross-forest requests, the corresponding criteria are marked as N/A (Not Applicable).


| Tool Name |OpNum Coverage| Access Rights Evaluation| Error Handling |Authentication Methods| Access Level Requirements |
|-----------|---------------------|------------------------|----------------|---------------------|---------------------------|
| net user  | N/A                 | N/A                    |  N/A           |  N/A                | N/A                       |
| PowerShell| N/A                 | N/A                    |  N/A           |  N/A                | N/A                       |
| Impacket  |                     |                        |                |                     |                           |
| CrackMapExec         |          |                        |                |                     |                           |
| rpcclient (Samba)    |                        |                          |                          |                          |                           |
| smbclient (Samba)    |                        |                          |                          |                          |                           |
| BloodHound           |                        |                          |                          |                          |                           |
| Nmap (NSE Scripts)    |                        |                          |                          |                          |                           |
| Enum4linux            |                        |                          |                          |                          |                           |
| Enum4linux-ng        |                        |                          |                          |                          |                           |
| Metasploit Framework |                        |                          |                          |                          |                           |
| PowerSploit          |                        |                          |                          |                          |                           |
| SAMRi10              |                        |                          |                          |                          |                           |
| RPC Investigator     |                        |                          |                          |                          |                           |


### Detailed Evaluation of OpNum Coverage
> **Note:** The evaluation results in this section are based on cross-forest SAMR requests.  

"⚫️" - Supported  
"○" - Not Supported


| Tool \ OpNum         | 1  | 3  | 5  | 6  | 7  | 8  | 11 | 13 | 15 | 16 | 17 | 18 | 34 | 36 | 39 | 40 | 41 | 51 | 56 | 64 |
|----------------------|----|----|----|----|----|----|----|----|----|----|----|----|----|----|----|----|----|----|----|----|
| "net user", "net group"                  | ○  | ○  |  ○ | ○  | ○  | ○  |  ○ | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  |
| PowerShell                           | ○  | ○  |  ○ | ○  | ○  | ○  |  ○ | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  |
| Impacket             |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |
| CrackMapExec         |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |
| rpcclient (Samba)    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |
| smbclient (Samba)    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |
| BloodHound           |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |
| Nmap (NSE Scripts)   |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |
| Enum4linux           |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |
| Enum4linux-ng        |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |
| Metasploit Framework |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |
| PowerSploit          |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |
| SAMRi10              |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |
| RPC Investigator     |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |


### OpNum Descriptions

- **OpNum 1**: `SamrCloseHandle` – Closes an open handle to a SAM object, releasing the associated resources. 
- **OpNum 3**: `SamrQuerySecurityObject` – Retrieves security information for a specified SAM object, such as permissions and access control details. 
- **OpNum 5**: `SamrLookupDomainInSamServer` – Resolves a domain name to its corresponding SID within the SAM server. (Mandatory for SAMR communication?) - MISSING IN THE TABLE
- **OpNum 6**: `SamrEnumerateDomainsInSamServer` – Lists all domains managed by the SAM server. (Mandatory for SAMR communication?)
- **OpNum 7**: `SamrOpenDomain` – Converts a list of account or domain names within a domain to their corresponding SIDs
- **OpNum 8**: `SamrQueryInformationDomain` – Retrieves specific information about a domain, such as security policies or account statistics, based on the requested information level.  
- **OpNum 11**: `SamrEnumerateGroupsInDomain` – Retrieves a list of groups within a specific domain. (Mandatory for SAMR communication?)
- **OpNum 13**: `SamrEnumerateUsersInDomain` – Retrieves user accounts within a specific domain. (Mandatory for SAMR communication?)
- **OpNum 15**: `SamrEnumerateAliasesInDomain` – Lists alias groups within a domain.
- **OpNum 16**: `SamrGetAliasMembership` – Shows alias memberships for a specific user or SID. (Mandatory for SAMR communication?)
- **OpNum 17**: `SamrLookupNamesInDomain` – Converts account names into SIDs within a domain. (Mandatory for SAMR communication?)
- **OpNum 18**: `SamrLookupIdsInDomain` – Maps SIDs back to account names. (Mandatory for SAMR communication?)
- **OpNum 34**: `SamrOpenUser` – Opens a handle to a specific user account within a domain, allowing for further operations on the user object.
- **OpNum 36**: `SamrQueryInformationUser` – Retrieves detailed information on a specific user account.
- **OpNum 39**: `SamrGetGroupsForUser` – Lists all group memberships for a specified user.
- **OpNum 40**: `SamrQueryDisplayInformation` – Provides display information in a paginated format.
- **OpNum 41**: `SamrGetDisplayEnumerationIndex` – Retrieves the display index for paginated enumerations.
- **OpNum 51**: `SamrQueryDisplayInformation3` – Enables detailed and filtered queries for large-scale user, group, or machine account enumeration.
- **OpNum 56**: `SamrGetDomainPasswordInformation` – Retrieves password policy information for the domain.
- **OpNum 64**: `SamrConnect5` – Establishes a connection to the SAM server for domain enumeration and lookup. (Mandatory for SAMR communication?)

## Evaluation of "Desired Access" Compliance in Detail

The order of operations is based on the sequence in the traffic capture. Duplicate entries with identical requested permissions were omitted. The accesses marked in bold are not compliant with the protocol specification.

### "net user" (to local domain controller)

The `net user` command was executed in the local domain, with all SAMR requests sent from `yws1` (workstation) to `ydc1` (domain controller)  
Following commands were executed:
- `net user /domain`
- `net user administrator /domain`

N/A - Not Applicable

| SAMR Operation | Wireshark Label | OpNum | Requested Access Rights (Hex) | Rights Description | Required for Operation? | Compliance with Requested Access |
|------------------|-----------------|-------|--------------------|-----------------------------|---------------------|--------------------------------|
| `SamrConnect5`   | `Connect5`        |  64   | `0x00000030` | `SAM_SERVER_ENUMERATE_DOMAINS` (`0x00000010`), `SAM_SERVER_LOOKUP_DOMAIN` (`0x00000020`)             | Yes                 | Compliant |
|  `SamrEnumerateDomainsInSamServer` | `EnumDomains`   | 6  | Access is not requested  | N/A | N/A  | N/A  |
|  `SamrLookupDomainInSamServer`     | `LookupDomain`  | 5  | Access is not requested  | N/A | N/A  | N/A  |
|  `SamrOpenDomain`                  | `OpenDomain`    | 7  |  `0x00000200` | `DOMAIN_LOOKUP`  |  Yes |  Compliant |
|  `SamrOpenDomain`                  | `OpenDomain`    | 7  |  `0x00000280` | **`DOMAIN_GET_ALIAS_MEMBERSHIP` (`0x00000080`)**, `DOMAIN_LOOKUP` (`0x00000200`) |  No | Not Compliant |
|  `SamrLookupNamesInDomain`         | `LookupNames`   | 17  |  Access is not requested | N/A  |  N/A | N/A |
|  `SamrOpenUser`                    | `OpenUser`      | 34  |  `0x0002011b` | `USER_READ_GENERAL` (`0x00000001`),<br> `USER_READ_PREFERENCES` (`0x00000002`),<br> `USER_READ_LOGON` (`0x00000008`),<br> `USER_READ_ACCOUNT` (`0x00000010`),<br> `USER_LIST_GROUPS` (`0x00000100`),<br> `READ_CONTROL` (`0x00020000`) |  Compliant | Compliant |
|  `SamrQueryInformationUser`                    | `QueryUserInfo`      | 36  | Access is not requested | N/A |  N/A | N/A |
|  `SamrQuerySecurityObject`  | `QuerySecurity` | 3 | Access is not requested | N/A | N/A | N/A | 
| `SamrGetGroupsForUser` | `GetGroupForUser`| 39| Access is not requested | N/A | N/A | N/A | 
| `SamrGetAliasMembership`| `GetAliasMembership` | 16 | Access is not requested| N/A | N/A | N/A | 
| `SamrCloseHandle` | `Close` | 1 | Access is not requested | N/A | N/A | N/A | 
|  `SamrOpenDomain`  | `OpenDomain`    | 7  |  `0x00000205` | `DOMAIN_READ_PASSWORD_PARAMETERS` (`0x00000001`),<br> `DOMAIN_READ_OTHER_PARAMETERS` (`0x00000004`),<br> `DOMAIN_LOOKUP` (`0x00000200`)  |  Yes |  Compliant |
| `SamrQueryInformationDomain` | `QueryDomainInfo` | 8 | Access is not requested | N/A | N/A | N/A | 
| `SamrConnect5`   | `Connect5`        |  64   | `0x00020031` | `SAM_SERVER_CONNECT` (`0x00000001`),<br>`SAM_SERVER_ENUMERATE_DOMAINS` (`0x00000010`),<br> `SAM_SERVER_LOOKUP_DOMAIN` (`0x00000020`),<br> `READ_CONTROL` (`0x00020000`) | Yes                 | Compliant                       |
|  `SamrOpenDomain`                  | `OpenDomain`    | 7  |  `0x00020385` | `DOMAIN_READ_PASSWORD_PARAMETERS` (`0x00000001`),<br> `DOMAIN_READ_OTHER_PARAMETERS` (`0x00000004`),<br> **`DOMAIN_GET_ALIAS_MEMBERSHIP` (`0x00000080`)**, <br>`DOMAIN_LIST_ACCOUNTS` (`0x00000100`),<br> `DOMAIN_LOOKUP` (`0x00000200`), <br>`READ_CONTROL` (`0x00020000`) |  No | Not Compliant |
| `SamrLookupIdsInDomain` | `LookupRids` | 18 | Access is not requested | N/A |  N/A | N/A |
| `SamrOpenDomain`                  | `OpenDomain`    | 7  |  `0x00000304` | `DOMAIN_READ_OTHER_PARAMETERS` (`0x00000004`),<br>`DOMAIN_LIST_ACCOUNTS` (`0x00000100`),<br>`DOMAIN_LOOKUP` (`0x00000200`) |  Yes | Compliant |
| `SamrEnumerateUsersInDomain` | `EnumDomainUsers` | 13 | Access is not requested | N/A | N/A | N/A | 

### "net group" (to local domain controller)

The `net group` command was used in the local domain. As with `net user`, SAMR traffic was directed solely from `yws1` to `ydc1`. This section highlights the behavior of SAMR when scoped to a single domain environment.  
Following commands were executed:
- `net group /domain`
- `net group administrator /domain`

| SAMR Operation | Wireshark Label | OpNum | Requested Access Rights (Hex) | Rights Description | Required for Operation? | Compliance with Requested Access |
|------------------|---------------|------|--------------|-----------------------------|---------------------|-----------------------|
| `SamrConnect5`   | `Connect5`    |  64  | `0x00000030` | `SAM_SERVER_ENUMERATE_DOMAINS` (`0x00000010`), `SAM_SERVER_LOOKUP_DOMAIN` (`0x00000020`)   | Yes   | Compliant  |
|  `SamrEnumerateDomainsInSamServer` | `EnumDomains`   | 6  | Access is not requested  | N/A | N/A  | N/A  |
|  `SamrLookupDomainInSamServer`     | `LookupDomain`  | 5  | Access is not requested  | N/A | N/A  | N/A  |
|  `SamrOpenDomain`  | `OpenDomain`  | 7  |  `0x00000304` | `DOMAIN_WRITE_OTHER_PARAMETERS` (`0x00000008`),<br> `DOMAIN_LIST_ACCOUNTS` (`0x00000100`),<br> `DOMAIN_LOOKUP` (`0x00000200`) |  Yes |  Compliant |
| `SamrQueryInformationDomain` | `QueryDomainInfo` | 8 | Access is not requested | N/A | N/A | N/A | 
| `SamrQueryDisplayInformation2` | `QueryDisplayInfo2` | 48 | Access is not requested | N/A | N/A | N/A | 
| `SamrCloseHandle` | `Close` | 1 | Access is not requested | N/A | N/A | N/A | 
|  `SamrOpenDomain`  | `OpenDomain`  | 7  |  `0x00000200` | `DOMAIN_LOOKUP` (`0x00000200`) |  Yes |  Compliant |
|  `SamrLookupNamesInDomain`  | `LookupNma`  | 17  | Access is not requested | N/A | N/A | N/A |
|  `SamrOpenGroup`  | `OpenGroup`  | 19  | `0x00000001`| `GROUP_READ_INFORMATION` (`0x00000001`) | Yes | Yes |
|  `SamrQueryInformationGroup`  | `QueryGroupInfo`  | Access is not requested | N/A | N/A | N/A |
|  `SamrOpenGroup`  | `OpenGroup`  | 19  | `0x00000010`| `GROUP_LIST_MEMBERS` (`0x00000010`) | Yes | Yes |
|  `SamrGetMembersInGroup`  | `QueryGroupMember`  | 25  | Access is not requested | N/A | N/A | N/A |
| `SamrLookupIdsInDomain` | `LookupRids` | 18 | Access is not requested | N/A |  N/A | N/A |
