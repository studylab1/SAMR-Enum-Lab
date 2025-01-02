# SAMR Enumeration Tools Comparison

## Table of Contents
1. [Introduction](#introduction)
2. [System Configuration and Enumeration Vector](#system-configuration-and-enumeration-vector)
3. [Tool Versions and Specifications](#tool-versions-and-specifications)
4. [Criteria for Tool Evaluation](#criteria-for-tool-evaluation)
5. [Tool Comparison Results](#tool-comparison-results)
6. [Criteria Evaluation Details](#criteria-evaluation-details)
   1. [OpNum Coverage Criterion](#opnum-coverage-criterion)
   2. [Excessive Permission Detection Criterion](#excessive-permission-detection-criterion)
   3. [Data Parsing and Accuracy Criterion](#data-parsing-and-accuracy-criterion)

## Introduction

This comparison evaluates tools used for Active Directory reconnaissance through the SAMR protocol. The SAMR protocol enables the retrieval of information on users, groups, computers, domains, and security settings.

## System Configuration and Enumeration Vector

The detailed configuration of the lab is described on the [Lab Setup](Lab_Setup.md) page. The lab environment was configured with four one-way forest trusts among `domain-y.local`, `domain-z.local`, and `domain-x.local`, set up with forest-wide authentication.

SAMR enumeration scans were conducted from the following workstations:
- `yws1` (Microsoft Windows)** and `xws1` (Ubuntu Linux) to the domain controllers:
  - `zdc1.domain-z.local`
  - `xdc1.domain-x.local`  

These scans were performed in cases where tools supported cross-forest requests. When tools did not support cross-forest requests, scans were conducted only to the domain controller `ydc1.domain-y.local` from the same workstations.

The data in Active Directory was populated using the BadBlood tool. Key details of the environment include:
- The `zdc1.domain-z.local` domain controller hosted users, groups, and computers with:
  - Special characters in their names such as   `@`, `#`, `$`, `%`, `^`, `&`, `*`, `!`, `~`, `'`, `+`, `=`, `_`, `-`, `<`, `>`, `,`, `.`, `?`, `/`, `"`.
  - Fields in foreign language such as Russian and Chinese.
  - Fields like names, descriptions, and others with long values.
- The `zdc1.domain-z.local` domain controller contained:
  - 20,000 users.
  - 10,000 computers and groups.

## Tool Versions and Specifications

The following table provides version numbers for the tools evaluated during this research.

| Tool Name           | Version       | Additional Notes                                                                                                                                         |
|---------------------|---------------|----------------------------------------------------------------------------------------------------------------------------------------------------------|
| Net                 | Built-in      | Windows 11 Enterprise x86-64 (version 23H2, OS build 22631.4317).                                                                                        |
| Enum4linux          | 0.9.1         | A legacy enumeration tool commonly used for SMB and NetBIOS reconnaissance. While functional, it lacks updates and advanced features found in modern tools.|
| Enum4linux-ng       | 1.3.4         | A modernized version of Enum4linux, designed to provide enhanced enumeration capabilities, better output formatting, and support for contemporary SMB versions. |
| PowerShell          | 1.0.1.0       | ActiveDirectory Module. Windows 11 Enterprise x86-64 (version 23H2, OS build 22631.4317). Cmdlets from the Active Directory module in PowerShell did not use the SAMR for communication. Instead, these cmdlets primarily relied on the Microsoft .NET Naming Service (MS-NNS) and Microsoft .NET Message Framing Protocol (MS-NMF) for their operations. |
| SharpHound          | 2.5.9         | Part of the BloodHound project. Specifically designed to collect data from Active Directory environments for attack path visualization and analysis.    |
| Metasploit          | 6.4.41 dev    | A penetration testing framework that provides various modules, including auxiliary tools, for conducting security assessments. In the context of SAMR enumeration requests, Metasploit offers modules to interact with the SAMR protocol, allowing testers to enumerate user accounts and computer objects on remote domain controllers. |
| CrackMapExec        | 6.1.0 - John Wick | A post-exploitation and pentesting tool designed to streamline network enumeration, lateral movement, and credential validation within Active Directory environments. Features SAMR-based enumeration for identifying domain objects. |
| Impacket            | 0.12.0        | A library and suite of tools for interacting with network protocols. For this research, only `samrdump.py` and `net.py` from the Impacket suite were used. These tools facilitate detailed enumeration through SAMR. |
| rpcclient           | 4.15.13       | A command-line tool, part of the Samba suite, used to interact with the Microsoft Remote Procedure Call (MS-RPC) protocol. It allows querying and managing Windows-based systems remotely over SMB, enabling tasks like enumerating users, groups, shares, and retrieving domain or system information. |


## Criteria for Tool Evaluation

The following criteria were used to evaluate each tool's SAMR enumeration capabilities:

- **Cross-forest Support**: Indicates if the tool can perform enumeration across domains within a forest trust.
- **OpNum Coverage**: Lists supported SAMR operation numbers.
- **Excessive Permission Detection**: Specifies the default access permissions required by each tool.
- **Data Parsing and Accuracy**: Evaluates whether tools correctly interpret and retrieve all fields from SAMR responses and align the output with the expected protocol structures. Includes verification of field completeness and consistency in results across SAMR operations.
- **Supported Authentication Types**: Details whether NTLM, Kerberos, or both protocols are supported (Multi-Authentication Compatible).
- **Access Level Requirements**: Specifies whether administrator privileges are required for operation.

## Tool Comparison Results 

> **Note:** The evaluation results analyze tools’ support for cross-forest SAMR requests. If a tool does not support cross-forest SAMR or uses a different protocol for enumeration, other criteria are not assessed, and the corresponding values are marked as "Not Applicable".

| Tool Name    | Cross-Forest Request Support | OpNum Coverage | Excessive Permission Detection | Data Parsing and Accuracy | Supported Authentication Types | Access Level Requirements |
|--------------|------------------------------|----------------|--------------------------------|---------------------------|--------------------------------|---------------------------|
| Net          | Not Supported                | Not Applicable | Not Applicable                 | Not Applicable            | Not Applicable                 | Not Applicable            |
| Enum4linux   | Not Supported                | Not Applicable | Not Applicable                 | Not Applicable            | Not Applicable                 | Not Applicable            |
| Enum4linux-ng| Not Supported                | Not Applicable | Not Applicable                 | Not Applicable            | Not Applicable                 | Not Applicable            |
| PowerShell   | Supported                    | Not Applicable | Not Applicable                 | Not Applicable            | Not Applicable                 | Not Applicable            |
| SharpHound   | Supported                    | Low Coverage (25%) | Not Detected               | Accurate                  | Multi-Authentication Compatible| Standard Access Sufficient|
| Metasploit   | Supported                    | Low Coverage (28.1%) | Not Detected             | Accurate                  | NTLM                           | Standard Access Sufficient|
| CrackMapExec | Supported                    | Low Coverage (34.3%) | Detected                 | Accurate                  | Multi-Authentication Compatible| Standard Access Sufficient|
| Impacket     | Supported                    | Moderate Coverage (59.3%)| Detected             | Accurate                  | Multi-Authentication Compatible| Standard Access Sufficient|
| rpcclient    | Supported                    | High Coverage (84.3%) | Detected                | Accurate                  | Multi-Authentication Compatible| Standard Access Sufficient|

> Cmdlets from the Active Directory module in PowerShell did not use the SAMR for communication. Instead, these cmdlets primarily relied on the Microsoft .NET Naming Service (MS-NNS) and Microsoft .NET Message Framing Protocol (MS-NMF) for their operations.
> For Metasploit, only the "auxiliary/scanner/smb/smb_enumusers" and "auxiliary/admin/dcerpc/samr_account" modules were examined.

## Criteria Evaluation Details

### OpNum Coverage Criterion
> **Note:** The evaluation results in this section are based on cross-forest SAMR requests.  
> OpNum references are available on the [Resources](Resources.md) page.

⚫️ - Supported  
○ - Not Supported


| Tool \ OpNum         | 0  | 1  | 3  | 5  | 6  | 7  | 8  | 11 | 13 | 15 | 16 | 17 | 18 | 19 | 20 | 25 | 27 | 33 | 34 | 36 | 39 | 40 | 41 | 44 | 46 | 47 | 48 | 51 | 56 | 57 | 64 | 65 |
|----------------------|----|----|----|----|----|----|----|----|----|----|----|----|----|----|----|----|----|----|----|----|----|----|----|----|----|----|----|----|----|----|----|----|
| Net                  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | 
| Enum4linux           | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  |
| Enum4linux-ng        | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  |
| PowerShell           | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  |
| SharpHound           | ○  | ●  | ○  | ●  | ●  | ●  | ○  | ○  | ○  | ●  | ○  | ○  | ○  | ○  | ○  | ○  | ●  | ●  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ●  | ○  | 
| Metasploit           | ●  | ●  | ○  | ●  | ●  | ●  | ●  | ○  | ●  | ○  | ○  | ●  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ●  |
| CrackMapExec         | ●  | ●  | ○  | ●  | ●  | ●  | ○  | ○  | ●  | ●  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ●  | ○  | ○  | ○  | ○  | ○  | ●  | ●  | ○  | ○  | ○  | ●  | ○  | ○  |
| Impacket             | ●  | ●  | ○  | ●  | ●  | ●  | ○  | ●  | ●  | ●  | ●  | ●  | ●  | ●  | ○  | ●  | ●  | ●  | ●  | ○  | ●  | ○  | ○  | ○  | ○  | ●  | ○  | ○  | ○  | ○  | ○  | ●  |
| rpcclient            | ●  | ○  | ●  | ●  | ●  | ●  | ●  | ●  | ●  | ●  | ●  | ●  | ●  | ●  | ●  | ●  | ●  | ●  | ●  | ●  | ●  | ●  | ●  | ●  | ○  | ○  | ●  | ●  | ●  | ○  | ●  | ○  |


### Excessive Permission Detection Criterion

The evaluation focuses on analyzing the **'Desired Access'** field in SAMR requests. For clarity:

- The **'Desired Access'** field is a key component of the SAMR header. It specifies the access rights requested during operations.
- Operations are presented in the order observed in network traffic captures.
- Duplicate entries with identical permissions are excluded for simplicity.
- **Bold entries** highlight instances of non-compliance with protocol specifications.
- Entries marked as `N/A` denote cases where access was neither requested nor required for the operation.

#### Net.exe

The `net` command was executed within the local domain, with all SAMR requests initiated from the workstation `yws1` and directed to the domain controller `ydc1`.The following commands were executed:
- `net user /domain`
- `net user administrator /domain`

| **SAMR Operation**               | **Wireshark Label** | **OpNum** | **Requested Access Rights (Hex)** | **Rights Description**                                                                                   | **Required for Operation?** | **Compliance with Requested Access** |
|-----------------------------------|---------------------|-----------|------------------------------------|----------------------------------------------------------------------------------------------------------|-----------------------------|---------------------------------------|
| `SamrConnect5`                    | `Connect5`          | 64        | `0x00000030`                       | `SAM_SERVER_ENUMERATE_DOMAINS` (`0x00000010`), `SAM_SERVER_LOOKUP_DOMAIN` (`0x00000020`)                | Yes                         | Compliant                              |
| `SamrEnumerateDomainsInSamServer` | `EnumDomains`       | 6         | Access not requested               | N/A                                                                                                      | N/A                         | N/A                                   |
| `SamrLookupDomainInSamServer`     | `LookupDomain`      | 5         | Access not requested               | N/A                                                                                                      | N/A                         | N/A                                   |
| `SamrOpenDomain`                  | `OpenDomain`        | 7         | `0x00000200`                       | `DOMAIN_LOOKUP`                                                                                         | Yes                         | Compliant                              |
| `SamrOpenDomain`                  | `OpenDomain`        | 7         | **`0x00000280`**                   | **`DOMAIN_GET_ALIAS_MEMBERSHIP` (`0x00000080`)**, `DOMAIN_LOOKUP` (`0x00000200`)                        | No                          | Not Compliant                         |
| `SamrLookupNamesInDomain`         | `LookupNames`       | 17        | Access not requested               | N/A                                                                                                      | N/A                         | N/A                                   |
| `SamrOpenUser`                    | `OpenUser`          | 34        | `0x0002011b`                       | `USER_READ_GENERAL` (`0x00000001`),<br>`USER_READ_PREFERENCES` (`0x00000002`),<br>`USER_LIST_GROUPS` (`0x00000100`),<br>`READ_CONTROL` (`0x00020000`) | Yes                         | Compliant                              |
| `SamrQueryInformationUser`        | `QueryUserInfo`     | 36        | Access not requested               | N/A                                                                                                      | N/A                         | N/A                                   |
| `SamrQuerySecurityObject`         | `QuerySecurity`     | 3         | Access not requested               | N/A                                                                                                      | N/A                         | N/A                                   |
| `SamrGetGroupsForUser`            | `GetGroupForUser`   | 39        | Access not requested               | N/A                                                                                                      | N/A                         | N/A                                   |

The following commands were executed:
- `net group /domain`
- `net group administrator /domain`

| **SAMR Operation**         | **Wireshark Label** | **OpNum** | **Requested Access Rights (Hex)** | **Rights Description**                                                                  | **Required for Operation?** | **Compliance with Requested Access** |
|-----------------------------|---------------------|-----------|------------------------------------|-----------------------------------------------------------------------------------------|-----------------------------|---------------------------------------|
| `SamrConnect5`              | `Connect5`          | 64        | `0x00000030`                       | `SAM_SERVER_ENUMERATE_DOMAINS` (`0x00000010`), `SAM_SERVER_LOOKUP_DOMAIN` (`0x00000020`) | Yes                         | Compliant                              |
| `SamrOpenDomain`            | `OpenDomain`        | 7         | `0x00000304`                       | `DOMAIN_WRITE_OTHER_PARAMETERS` (`0x00000008`),<br>`DOMAIN_LIST_ACCOUNTS` (`0x00000100`),<br>`DOMAIN_LOOKUP` (`0x00000200`) | Yes                         | Compliant                              |
| `SamrOpenGroup`             | `OpenGroup`         | 19        | `0x00000001`                       | `GROUP_READ_INFORMATION` (`0x00000001`)                                                | Yes                         | Compliant                              |
| `SamrOpenGroup`             | `OpenGroup`         | 19        | `0x00000010`                       | `GROUP_LIST_MEMBERS` (`0x00000010`)                                                    | Yes                         | Compliant                              |
| `SamrGetMembersInGroup`     | `QueryGroupMember`  | 25        | Access not requested               | N/A                                                                                     | N/A                         | N/A                                   |

#### SharpHound

Executed with the following parameters:  
`SharpHound.exe -c All --domaincontroller zdc1.domain-z.local`

| **SAMR Operation**  | **Wireshark Label** | **OpNum** | **Requested Access Rights (Hex)** | **Rights Description**  | **Required for Operation?** | **Compliance with Requested Access** |
|---------------------|---------------------|-----------|-----------------------------------|-------------------------|-----------------------------|--------------------------------------|
| `SamrConnect5`      | `Connect5`          | 64        | `0x00000031`                      | `SAM_SERVER_CONNECT` (`0x00000001`),<br> `SAM_SERVER_ENUMERATE_DOMAINS` (`0x00000010`),<br> `SAM_SERVER_LOOKUP_DOMAIN` (`0x00000020`)  | Yes | Compliant  |
| `SamrEnumerateDomainsInSamServer`| `EnumDomains`| 6   | Access not requested              | N/A                     | N/A                         | N/A                                  |
| `SamrLookupDomainInSamServer`| `LookupDomain`| 5      | Access not requested              | N/A                     | N/A                         | N/A                                  |
| `SamrOpenDomain`    | `OpenDomain`        | 7         | `0x00000300`                      | `DOMAIN_LIST_ACCOUNTS` (`0x00000100`),<br> `DOMAIN_LOOKUP` (`0x00000200`)| Yes | Compliant   |
| `SamrEnumerateAliasesInDomain`| `EnumDomainAliases`| 15| Access not requested              | N/A                     | N/A                         | N/A                                  |
| `SamrOpenAlias`   | `OpenAlias`            | 27       | `0x00000004`                      | `ALIAS_LIST_MEMBERS` (`0x00000004`) | Yes             | Compliant                            |
| `SamrGetMembersInAlias` | `GetMembersInAlias`| 33     | Access not requested              | N/A                     | N/A                         | N/A                                  |
| `SamrCloseHandle` | `Close` | 1                       | Access not requested              | N/A                     | N/A                         | N/A                                  |

#### Metasploit

Module used:  
- `auxiliary/scanner/smb/smb_enumusers`
- `auxiliary/admin/dcerpc/samr_account`

> No SAMR requests specifying the “Desired Access” field were detected in the network traffic captures.

#### CrackMapExec

The SMB layer in the network traffic capture was encrypted. To decrypt the capture in Wireshark, the NT requestor password (LabAdm1!) was entered under the following setting:`Preferences > Protocols > NTLMSSP > NT Password`.

Executed with the following parameters:  
- `crackmapexec smb zdc1.domain-z.local -d domain-y.local -u enum -p "LabAdm1!" --users`
- `crackmapexec smb zdc1.domain-z.local -d domain-y.local -u enum -p "LabAdm1!" --groups`
- `crackmapexec smb zdc1.domain-z.local -d domain-y.local -u enum -p "LabAdm1!" --local-groups`
- `crackmapexec smb zdc1.domain-z.local -d domain-y.local -u enum -p "LabAdm1!" --computers`
- `crackmapexec smb zdc1.domain-z.local -d domain-y.local -u enum -p "LabAdm1!" --pass-pol`
- `crackmapexec smb zdc1.domain-z.local -d domain-y.local -u enum -p "LabAdm1!" --lsa`

| **SAMR Operation**  | **Wireshark Label** | **OpNum** | **Requested Access Rights (Hex)** | **Rights Description**  | **Required for Operation?** | **Compliance with Requested Access** |
|---------------------|---------------------|-----------|-----------------------------------|-------------------------|-----------------------------|--------------------------------------|
| `SamrConnect`       | `Connect2`          | 57        | `0x02000000`                      | **`MAXIMUM_ALLOWED` (``0x02000000``)**   | No         | Not Compliant                        |
| `SamrEnumerateDomainsInSamServer` | `EnumDomains`| 6  | Access not requested              | N/A                     | N/A                         | N/A                                  |
| `SamrLookupDomainInSamServer`     | `LookupDomain`| 5 | Access not requested              | N/A                     | N/A                         | N/A                                  |
| `SamrOpenDomain`    | `OpenDomain`        | 7         | `0x02000000`                      | **`MAXIMUM_ALLOWED` (``0x02000000``)**   | No         | Not Compliant                        |
| `SamrEnumerateUsersInDomain` | `EnumDomainUsers` | 13 | Access not requested              | N/A                     | N/A                         | N/A                                  |
| `SamrOpenUser`      | `OpenUser`          | 34        | `0x02000000`                      | **`MAXIMUM_ALLOWED` (``0x02000000``)**   | No         | Not Compliant                        |
| `SamrQueryInformationUser2` | `QueryUserInfo2` | 47   | Access not requested              | N/A                     | N/A                         | N/A                                  |
| `SamrCloseHandle`   | `Close`             | 1         | Access not requested              | N/A                     | N/A                         | N/A                                  |
| `SamrConnect`       | `Connect`           | 0         | `0x02000000`                      | **`MAXIMUM_ALLOWED` (``0x02000000``)**   | No         | Not Compliant                        |
| `SamrEnumerateAliasesInDomain`| `EnumDomainAliases`| 15| Access not requested             | N/A                     | N/A                         | N/A                                  |
| `SamrQueryInformationDomain`| `QueryDomainInfo2`| 46  | Access not requested              | N/A                     | N/A                         | N/A                                  |


#### Impacket

The SMB layer in the network traffic capture was encrypted. To decrypt the capture in Wireshark, the NT requestor password (LabAdm1!) was entered under the following setting:`Preferences > Protocols > NTLMSSP > NT Password`.

Executed with the following parameters:  
`python.exe samrdump.py domain-y/enum:LabAdm1!@zdc1.domain-z.local`

| **SAMR Operation**  | **Wireshark Label** | **OpNum** | **Requested Access Rights (Hex)** | **Rights Description**  | **Required for Operation?** | **Compliance with Requested Access** |
|---------------------|---------------------|-----------|-----------------------------------|-------------------------|-----------------------------|--------------------------------------|
| `SamrConnect`       | `Connect`           | 0         | `0x02000000`     | **`MAXIMUM_ALLOWED` (``0x02000000``)**   | No                          | Not Compliant                        |
| `SamrEnumerateDomainsInSamServer` | `EnumDomains`| 6  | Access not requested               | N/A                    | N/A                         | N/A                                  |
| `SamrLookupDomainInSamServer`     | `LookupDomain`    | 5   | Access not requested         | N/A                    | N/A                         | N/A                                  |
| `SamrOpenDomain`    | `OpenDomain`        | 7         | `0x02000000`     | **`MAXIMUM_ALLOWED` (``0x02000000``)**   | No                          | Not Compliant                        |
| `SamrEnumerateUsersInDomain` | `EnumDomainUsers` | 13 | Access not requested               | N/A                    | N/A                         | N/A                                  |
| `SamrOpenUser`      | `OpenUser`          | 34        | `0x02000000`     | **`MAXIMUM_ALLOWED` (``0x02000000``)**   | No                          | Not Compliant                        |
| `SamrQueryInformationUser2` | `QueryUserInfo2` | 47   | Access not requested               | N/A                    | N/A                         | N/A                                  |
| `SamrCloseHandle` | `Close` | 1                       | Access not requested               | N/A                    | N/A                         | N/A                                  |


Executed with the following parameters:  
- `python.exe net.py domain-y/enum:LabAdm1!@zdc1.domain-z.local user`
- `python.exe net.py domain-y/enum:LabAdm1!@zdc1.domain-z.local user -name Administrator`
- `python.exe net.py domain-y/enum:LabAdm1!@zdc1.domain-z.local group`
- `python.exe net.py domain-y/enum:LabAdm1!@zdc1.domain-z.local group -name "Domain Admins"`
- `python.exe net.py domain-y/enum:LabAdm1!@zdc1.domain-z.local localgroup`
- `python.exe net.py domain-y/enum:LabAdm1!@zdc1.domain-z.local localgroup -name Administrators`
- `python.exe net.py domain-y/enum:LabAdm1!@zdc1.domain-z.local computer`

| **SAMR Operation**  | **Wireshark Label** | **OpNum** | **Requested Access Rights (Hex)** | **Rights Description**  | **Required for Operation?** | **Compliance with Requested Access** |
|---------------------|---------------------|-----------|-----------------------------------|-------------------------|-----------------------------|--------------------------------------|
| `SamrConnect`       | `Connect`           | 0         | `0x02000000`     | **`MAXIMUM_ALLOWED` (``0x02000000``)**   | No                          | Not Compliant                        |
| `SamrEnumerateDomainsInSamServer` | `EnumDomains`| 6  | Access not requested               | N/A                    | N/A                         | N/A                                  |
| `SamrLookupDomainInSamServer`     | `LookupDomain`    | 5   | Access not requested         | N/A                    | N/A                         | N/A                                  |
| `SamrOpenDomain`    | `OpenDomain`        | 7         | `0x02000000`     | **`MAXIMUM_ALLOWED` (``0x02000000``)**   | No                          | Not Compliant                        |
| `SamrEnumerateUsersInDomain` | `EnumDomainUsers` | 13 | Access not requested               | N/A                    | N/A                         | N/A                                  |
| `SamrLookupNamesInDomain`    | `LookupNames`     | 17 | Access not requested               | N/A                    | N/A                         | N/A                                  |
| `SamrOpenUser`      | `OpenUser`          | 34        | `0x02000000`     | **`MAXIMUM_ALLOWED` (``0x02000000``)**   | No                          | Not Compliant                        |
| `SamrQueryInformationUser2` | `QueryUserInfo2` | 47   | Access not requested               | N/A                    | N/A                         | N/A                                  |
| `SamrGetGroupsForUser` | `GetGroupsForUser` | 39      | Access not requested               | N/A                    | N/A                         | N/A                                  |
| `SamrOpenGroup`        | `OpenGroup`        | 19      | `0x02000000`     | **`MAXIMUM_ALLOWED` (``0x02000000``)**   | No                          | Not Compliant                        |
| `SamrRidToSid`         | `RidToSid`         | 65      | Access not requested               | N/A                    | N/A                         | N/A                                  |
| `SamrCloseHandle` | `Close` | 1                       | Access not requested               | N/A                    | N/A                         | N/A                                  |
| `SamrLookupIdsInDomain` | `LookupRids`      |  18     | Access not requested               | N/A                    | N/A                         | N/A                                  |
| `SamrLookupDomainInSamServer` | `LookupDomain` | 5    | Access not requested               | N/A                    | N/A                         | N/A                                  |
| `SamrGetAliasMembership` | `GetAliasMembership` | 16  | Access not requested               | N/A                    | N/A                         | N/A                                  |
| `SamrEnumerateGroupsInDomain`|`EnumDomainGroups`| 11  | Access not requested               | N/A                    | N/A                         | N/A                                  |
| `SamrOpenGroup`             | `OpenGroup`       | 19  | `0x02000000`     | **`MAXIMUM_ALLOWED` (``0x02000000``)**   | No                          | Not Compliant                        |
| `SamrGetMembersInGroup`     | `QueryGroupMember`  | 25| Access not requested               | N/A                    | N/A                         | N/A                                  |
| `SamrEnumerateAliasesInDomain`| EnumDomainAliases`| 15| Access not requested               | N/A                    | N/A                         | N/A                                  |
| `SamrOpenAlias`   | `OpenAlias`            | 27       | `0x02000000`     | **`MAXIMUM_ALLOWED` (``0x02000000``)**   | No                          | Not Compliant                        |
| `SamrGetMembersInAlias` | `GetMembersInAlias`| 33     | Access not requested               | N/A                    | N/A                         | N/A                                  |

#### rpcclient

Executed following commands:  
- `rpcclient -U "domain-y.local\\enum%LabAdm1!" 192.168.12.11 -c "enumdomusers"`
- `rpcclient -U "domain-y.local\\enum%LabAdm1!" 192.168.12.11 -c "enumdomgroups"`
- `rpcclient -U "domain-y.local\\enum%LabAdm1!" 192.168.12.11 -c "enumdomgroups domain"`
- `rpcclient -U "domain-y.local\\enum%LabAdm1!" 192.168.12.11 -c "enumdomgroups builtin"`
- `rpcclient -U "domain-y.local\\enum%LabAdm1!" 192.168.12.11 -c "enumprivs"`
- `rpcclient -U "domain-y.local\\enum%LabAdm1!" 192.168.12.11 -c "enumalsgroups builtin"`
- `rpcclient -U "domain-y.local\\enum%LabAdm1!" 192.168.12.11 -c "enumalsgroups domain"`
- `rpcclient -U "domain-y.local\\enum%LabAdm1!" 192.168.12.11 -c "lookupnames username"`
- `rpcclient -U "domain-y.local\\enum%LabAdm1!" 192.168.12.11 -c "lookupsids sid_value"`
- `rpcclient -U "domain-y.local\\enum%LabAdm1!" 192.168.12.11 -c "queryaliasmem builtin 544"`
- `rpcclient -U "domain-z.local\\enum%LabAdm1!" 192.168.12.11 -c "queryaliasmem domain 4194"`
- `rpcclient -U "domain-y.local\\enum%LabAdm1!" 192.168.12.11 -c "queryuser 0x1f4"`
- `rpcclient -U "domain-y.local\\enum%LabAdm1!" 192.168.12.11 -c "querygroup 4212"`
- `rpcclient -U "domain-y.local\\enum%LabAdm1!" 192.168.12.11 -c "queryusergroups 500"`
- `rpcclient -U "domain-y.local\\enum%LabAdm1!" 192.168.12.11 -c "queryuseraliases builtin S-1-5-21-2189324197-3478012550-1180063049-500"`
- `rpcclient -U "domain-y.local\\enum%LabAdm1!" 192.168.12.11 -c "queryuseraliases domain S-1-5-21-2189324197-3478012550-1180063049-4202"`
- `rpcclient -U "domain-y.local\\enum%LabAdm1!" 192.168.12.11 -c "querygroupmem 512"`
- `rpcclient -U "domain-y.local\\enum%LabAdm1!" 192.168.12.11 -c "queryaliasinfo builtin 544" -d 10`
- `rpcclient -U "domain-y.local\\enum%LabAdm1!" 192.168.12.11 -c "querydispinfo"`
- `rpcclient -U "domain-y.local\\enum%LabAdm1!" 192.168.12.11 -c "querydispinfo2"`
- `rpcclient -U "domain-y.local\\enum%LabAdm1!" 192.168.12.11 -c "querydispinfo3"`
- `rpcclient -U "domain-y.local\\enum%LabAdm1!" 192.168.12.11 -c "querydominfo"`
- `rpcclient -U "domain-y.local\\enum%LabAdm1!" 192.168.12.11 -c "getdompwinfo"`
- `rpcclient -U "domain-y.local\\enum%LabAdm1!" 192.168.12.11 -c "samlookupnames domain Administrator"`
- `rpcclient -U "domain-y.local\\enum%LabAdm1!" 192.168.12.11 -c "samlookupnames builtin Users"`
- `rpcclient -U "domain-y.local\\enum%LabAdm1!" 192.168.12.11 -c "samlookuprids domain 512"`
- `rpcclient -U "domain-y.local\\enum%LabAdm1!" 192.168.12.11 -c "samlookuprids builtin 544"`
- `rpcclient -U "domain-y.local\\enum%LabAdm1!" 192.168.12.11 -c "samquerysecobj"`
- `rpcclient -U "domain-y.local\\enum%LabAdm1!" 192.168.12.11 -c "lookupdomain domain-z.local"`
- `rpcclient -U "domain-y.local\\enum%LabAdm1!" 192.168.12.11 -c "getdispinfoidx Administrator 1"`
- `rpcclient -U "domain-y.local\\enum%LabAdm1!" 192.168.12.11 -c "enumdomains"`


| **SAMR Operation**  | **Wireshark Label** | **OpNum** | **Requested Access Rights (Hex)** | **Rights Description**  | **Required for Operation?** | **Compliance with Requested Access** |
|---------------------|---------------------|-----------|-----------------------------------|-------------------------|-----------------------------|--------------------------------------|
| `SamrConnect5`      | `Connect5`          | 64        | `0x02000000`                      | **`MAXIMUM_ALLOWED` (``0x02000000``)**   | No         | Not Compliant                        |
| `SamrEnumerateDomainsInSamServer` | `EnumDomains`| 6  | Access not requested              | N/A                     | N/A                         | N/A                                  |
| `SamrLookupDomainInSamServer`     | `LookupDomain` | 5| Access not requested              | N/A                     | N/A                         | N/A                                  |
| `SamrOpenDomain`    | `OpenDomain`        | 7         | `0x02000000`     | **`MAXIMUM_ALLOWED` (``0x02000000``)**   | No                          | Not Compliant                        |
| `SamrEnumerateAliasesInDomain`| `EnumDomainAliases`| 15| Access not requested               | N/A                    | N/A                         | N/A                                  |
| `SamrCloseHandle`   | `Close`             | 1         | Access not requested               | N/A                    | N/A                         | N/A                                  |
| `SamrOpenDomain`    | `OpenDomain`        | 7         | `0x0000000b`     | `MDOMAIN_READ_PASSWORD_PARAMETERS` (`0x00000001`) <br> `DOMAIN_WRITE_PASSWORD_PARAMS` (`0x00000002`) <br> `DOMAIN_WRITE_OTHER_PARAMETERS` (`0x00000008`)   | Yes  | Compliant  |
| `SamrOpenDomain`    | `OpenDomain`        | 7         | `0x0000000d`     | `MDOMAIN_READ_PASSWORD_PARAMETERS` (`0x00000001`) <br> `DOMAIN_READ_OTHER_PARAMETERS` (`0x00000004`) <br> `DOMAIN_WRITE_OTHER_PARAMETERS` (`0x00000008`)   | Yes  | Compliant  |
| `SamrOpenUser`      | `OpenUser`          | 34        | `0x02000000`     | **`MAXIMUM_ALLOWED` (``0x02000000``)**   | No                          | Not Compliant                        |
| `SamrOpenAlias`     | `OpenAlias`         | 27        | `0x02000000`     | **`MAXIMUM_ALLOWED` (``0x02000000``)**   | No                          | Not Compliant                        |
| `SamrOpenGroup`     | `OpenGroup`         | 19        | `0x02000000`     | **`MAXIMUM_ALLOWED` (``0x02000000``)**   | No                          | Not Compliant                        |


### Data Parsing and Accuracy Criterion
 
This section displays how tools parse and present data attributes retrieved through SAMR operations. The analysis evaluates the completeness of the attributes retrieved for each SAMR operation and the accuracy of the values compared to expected results. Tools are assessed based on their handling of expected data types, edge cases, and inconsistencies.

#### Metasploit 

Module used:  
- `auxiliary/scanner/smb/smb_enumusers`
- `auxiliary/admin/dcerpc/samr_account`

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

#### SharpHound

Executed with the following parameters:  
`SharpHound.exe -c All --domaincontroller zdc1.domain-z.local`

| **OpNum** | **OpNum Name**             | **SAMR Field Name**     | **Domain Attribute Name**  | **Expected Data Type**   | **Completeness** | **Field Displayed?** | **Accuracy** | **Field Description** |
|-----------|----------------------------|-------------------------|----------------------------|--------------------------|------------------|----------------------|--------------|-----------------------|
| 15        | `SamrEnumerateAliasesInDomain`| `RelativeId`         | `objectSid`                | Integer (32-bit)         | Yes              | Yes                  | Accurate     | A unique identifier assigned to the alias within the domain.                         |
| 15        | `SamrEnumerateAliasesInDomain`| `Name`               | `sAMAccountName`           | Unicode string           | Yes              | Yes                  | Accurate     | The name of the alias (built-in groups).                                             |
| 33        | `SamrGetMembersInAlias`      | `MemberSIDs`          | `objectSid`                | Array of SIDs            | Yes              | Yes                  | Accurate     | Retrieves a list of SIDs for the members of a specified alias.                        |


#### CrackMapExec

| **OpNum** | **OpNum Name**             | **SAMR Field Name**     | **Domain Attribute Name**  | **Expected Data Type**   | **Completeness** | **Field Displayed?** | **Accuracy** | **Field Description**  |
|-----------|----------------------------|-------------------------|----------------------------|--------------------------|------------------|----------------------|--------------|--------------------------------------------------------------------------------------|
| 13        | `SamrEnumerateUsersInDomain`| `RelativeId`           | `objectSid`                | Integer (32-bit)         | N/A              | No                   | N/A          | A unique identifier assigned to the user within the domain.                          |
| 13        | `SamrEnumerateUsersInDomain`| `Name`                 | `sAMAccountName`           | Unicode string (20 characters)| Yes         | Yes                  | Accurate   | A computer or service account name, logon name of the user.                          |
| 47        | `SamrQueryInformationUser2` | `RelativeId`           | `objectSid`                | Integer (32-bit)         | N/A              | No                   | N/A          | A unique identifier assigned to the user within the domain.                          |
| 47        | `SamrQueryInformationUser2` | `Name`                 | `sAMAccountName`           | Unicode string           | Yes              | Yes                  | Accurate     | The logon name of the user.                                                          |
| 47        | `SamrQueryInformationUser2` | `LastLogon`            | `lastLogon`                | FileTime structure       | N/A              | No                    | N/A          | Timestamp of the user’s last successful logon.                                       |
| 47        | `SamrQueryInformationUser2` | `LastLogoff`           | `lastLogoff`               | FileTime structure       | N/A              | No                    | N/A          | Timestamp of the user’s last logoff.                                                 |
| 47        | `SamrQueryInformationUser2` | `PasswordLastSet`      | `pwdLastSet`               | FileTime structure       | N/A              | No                    | N/A          | Timestamp indicating when the user’s password was last changed.                      |
| 47        | `SamrQueryInformationUser2` | `AccountExpires`       | `accountExpires`           | FileTime structure       | N/A              | No                    | N/A          | Date when the account will expire, if applicable.                                    |
| 47        | `SamrQueryInformationUser2` | `PasswordCanChange`    | Not explicitly defined     | FileTime structure       | N/A              | No                    | N/A          | The date when the user can next change their password.                               |
| 47        | `SamrQueryInformationUser2` | `PasswordMustChange`   | `pwdLastSet` (calculated)  | FileTime structure       | N/A              | No                    | N/A          | The date when the user’s password must be changed.                                   |
| 47        | `SamrQueryInformationUser2` | `FullName`             | `displayName`              | Unicode string           | N/A              | No                    | N/A          | The full name of the user, as stored in the domain.                                  |
| 47        | `SamrQueryInformationUser2` | `HomeDirectory`        | `homeDirectory`            | Unicode string           | N/A              | No                    | N/A          | The user’s home directory path.                                                      |
| 47        | `SamrQueryInformationUser2` | `HomeDrive`            | `homeDrive`                | Unicode string           | N/A              | No                    | N/A          | Drive letter associated with the user’s home directory.                              |
| 47        | `SamrQueryInformationUser2` | `ScriptPath`           | `scriptPath`               | Unicode string           | N/A              | No                    | N/A          | Path to the user’s login script, if any.                                             |
| 47        | `SamrQueryInformationUser2` | `Workstations`         | `userWorkstations`         | Unicode string           | N/A              | No                    | N/A          | A list of workstations from which the user is allowed to log on.                     |
| 47        | `SamrQueryInformationUser2` | `AdminComment`         | `description`              | Unicode string           | Yes              | Yes                   | Accurate     | A textual description of the user account, typically used for organizational purposes.|
| 47        | `SamrQueryInformationUser2` | `PrimaryGroupId`       | `primaryGroupID`           | Integer (32-bit)         | N/A              | No                    | N/A          | RID of the user’s primary group.                                                     |
| 47        | `SamrQueryInformationUser2` | `ProfilePath`          | `profilePath`              | Unicode string           | N/A              | No                    | N/A          | Path to the user’s roaming profile, if any.                                          |
| 47        | `SamrQueryInformationUser2` | `Acct Flags: ACB_NORMAL`| `userAccountControl`       | Bitmask                 | N/A              | No                    | N/A          | Indicates the account is a regular user account.                                     |
| 47        | `SamrQueryInformationUser2` | `Acct Flags: ACB_PWNOEXP`| `userAccountControl`       | Bitmask                | N/A              | No                    | N/A          | Specifies that the account's password does not expire.                               |
| 47        | `SamrQueryInformationUser2` | `Acct Flags: AccountIsDisabled` | `userAccountControl` | Bitmask               | N/A              | No                    | N/A          | Indicates the account is disabled.                                                   |
| 47        | `SamrQueryInformationUser2` | `Acct Flags: ACB_SMARTCARD_REQUIRED` | `userAccountControl` | Bitmask          | N/A              | No                    | N/A          | Specifies whether smart card is required for login.                                  |
| 47        | `SamrQueryInformationUser2` | `Acct Flags: ACB_TRUSTED_FOR_DELEGATION` | `userAccountControl` | Bitmask      | N/A              | No                    | N/A          | Specifies whether the account is trusted for delegation.                             |
| 47        | `SamrQueryInformationUser2` | `LogonHours`           | `logonHours`               | Bitmask                  | N/A              | No                    | N/A          | A bitmask indicating the hours during which the user is allowed to log on.           |
| 47        | `SamrQueryInformationUser2` | `BadPasswordCount`     | `badPwdCount`              | Integer (32-bit)         | N/A              | No                    | N/A          | The number of failed password attempts.                                              |
| 47        | `SamrQueryInformationUser2` | `LogonCount`           | `logonCount`               | Integer (32-bit)         | N/A              | No                    | N/A          | The number of times the user has successfully logged on to the domain.               |
| 47        | `SamrQueryInformationUser2` | `Country Code`         | N/A                        | Integer                  | N/A              | No                    | N/A          | The country code associated with the user account.                                   |
| 47        | `SamrQueryInformationUser2` | `Code Page`            | N/A                        | Integer                  | N/A              | No                    | N/A          | The code page used for the account's character encoding.                             |
| 47        | `SamrQueryInformationUser2` | `Password Expired`     | Derived (based on policies)| Boolean                  | N/A              | No                    | N/A          | Indicates if the account's password is expired.                                      |
| 15        | `SamrEnumerateAliasesInDomain`| `AliasName`          | `sAMAccountName`           | Unicode string           | Yes              | Yes                   | Accurate     | The name of the alias (built-in group).                                              |
| 15        | `SamrEnumerateAliasesInDomain`| `RelativeId`         | `objectSid`                | Integer (32-bit)         | Yes              | Yes                   | Accurate     | A unique identifier assigned to the alias within the domain.                         |
| 46        | `SamrQueryDomainInformation2` | `MinPasswordLength`            | `minPwdLength`               | Integer (32-bit)  | Yes         | Yes                   | Accurate     | Specifies the minimum number of characters required for a password.                   |
| 46        | `SamrQueryDomainInformation2` | `PasswordHistoryLength`        | `pwdHistoryLength`           | Integer (32-bit)  | Yes         | Yes                   | Accurate     | Indicates how many previous passwords are stored and cannot be reused.                |
| 46        | `SamrQueryDomainInformation2` | `PasswordProperties`           | `pwdProperties`              | Bitmask           | Yes         | Yes                   | Accurate     | Bitmask defining password policy properties, such as complexity requirements.          |
| 46        | `SamrQueryDomainInformation2` | `MaxPasswordAge`               | `maxPwdAge`                  | FileTime structure| Yes         | Yes                   | Accurate     | Specifies the maximum duration for which a password is valid.                         |
| 46        | `SamrQueryDomainInformation2` | `MinPasswordAge`               | `minPwdAge`                  | FileTime structure| Yes         | Yes                   | Accurate     | Specifies the minimum duration before a password can be changed.                      |
| 46        | `SamrQueryDomainInformation2` | `ResetAccountLockoutCounter`   | `lockoutObservationWindow`   | FileTime structure| Yes         | Yes                   | Accurate     | Specifies the duration after which the lockout counter is reset.                      |
| 46        | `SamrQueryDomainInformation2` | `LockedAccountDuration`        | `lockoutDuration`            | FileTime structure| Yes         | Yes                   | Accurate     | Duration for which the account remains locked after exceeding the lockout threshold.  |
| 46        | `SamrQueryDomainInformation2` | `AccountLockoutThreshold`      | `lockoutThreshold`           | FileTime structure| Yes         | Yes                   | Accurate     | Number of failed login attempts before an account is locked.                          |
| 46        | `SamrQueryDomainInformation2` | `ForcedLogoffTime`             | `forceLogoffTime`            | FileTime structure| Yes         | Yes                   | Accurate     | Indicates if there is a specific time when users are forcibly logged off.             |
| 46        | `SamrQueryDomainInformation2` | `DomainPasswordComplex`        | Derived from `pwdProperties` | Boolean           | Yes         | Yes                   | Accurate     | Indicates whether password complexity is enforced.                                     |
| 46        | `SamrQueryDomainInformation2` | `DomainPasswordNoAnonChange`   | Derived from `pwdProperties` | Boolean           | Yes         | Yes                   | Accurate     | Indicates if anonymous users are prohibited from changing passwords.                   |
| 46        | `SamrQueryDomainInformation2` | `DomainPasswordNoClearChange`  | Derived from `pwdProperties` | Boolean           | Yes         | Yes                   | Accurate     | Indicates if cleartext passwords cannot be changed.                                    |
| 46        | `SamrQueryDomainInformation2` | `DomainPasswordLockoutAdmins`  | Derived from `pwdProperties` | Boolean           | Yes         | Yes                   | Accurate     | Specifies if administrators are locked out after too many failed password attempts.    |
| 46        | `SamrQueryDomainInformation2` | `DomainPasswordStoreCleartext` | Derived from `pwdProperties` | Boolean           | Yes         | Yes                   | Accurate     | Indicates if passwords can be stored in cleartext.                                     |
| 46        | `SamrQueryDomainInformation2` | `DomainRefusePasswordChange`   | Derived from `pwdProperties` | Boolean           | Yes         | Yes                   | Accurate     | Specifies if password changes are refused for certain accounts.                        |


#### Impacket

Executed with the following parameters:  
- `python.exe samrdump.py domain-y/enum:LabAdm1!@zdc1.domain-z.local`
- `python.exe net.py domain-y/enum:LabAdm1!@zdc1.domain-z.local user`
- `python.exe net.py domain-y/enum:LabAdm1!@zdc1.domain-z.local user -name Administrator`
- `python.exe net.py domain-y/enum:LabAdm1!@zdc1.domain-z.local group`
- `python.exe net.py domain-y/enum:LabAdm1!@zdc1.domain-z.local group -name "Domain Admins"`
- `python.exe net.py domain-y/enum:LabAdm1!@zdc1.domain-z.local localgroup`
- `python.exe net.py domain-y/enum:LabAdm1!@zdc1.domain-z.local localgroup -name Administrators`
- `python.exe net.py domain-y/enum:LabAdm1!@zdc1.domain-z.local computer`

| **OpNum** | **OpNum Name**             | **SAMR Field Name**     | **Domain Attribute Name**  | **Expected Data Type**   | **Completeness** | **Field Displayed?** | **Accuracy** | **Field Description**                                                                 |
|-----------|----------------------------|-------------------------|----------------------------|--------------------------|------------------|-----------------------|--------------|--------------------------------------------------------------------------------------|
| 13        | `SamrEnumerateUsersInDomain`| `RelativeId`           | `objectSid`                | Integer (32-bit)         | Yes              | Yes                   | Accurate     | A unique identifier assigned to the user within the domain.                          |
| 13        | `SamrEnumerateUsersInDomain`| `Name`                 | `sAMAccountName`           | Unicode string (20 characters)| Yes         | Yes                   | Accurate     | A computer or service account name, logon name of the user.                          |
| 47        | `SamrQueryInformationUser2` | `RelativeId`           | `objectSid`                | Integer (32-bit)         | Yes              | Yes                   | Accurate     | A unique identifier assigned to the user within the domain.                          |
| 47        | `SamrQueryInformationUser2` | `Name`                 | `sAMAccountName`           | Unicode string           | Yes              | Yes                   | Accurate     | The logon name of the user.                                                          |
| 47        | `SamrQueryInformationUser2` | `LastLogon`            | `lastLogon`                | FileTime structure       | Yes              | Yes                   | Accurate     | Timestamp of the user’s last successful logon.                                       |
| 47        | `SamrQueryInformationUser2` | `LastLogoff`           | `lastLogoff`               | FileTime structure       | N/A              | No                    | N/A          | Timestamp of the user’s last logoff.                                                 |
| 47        | `SamrQueryInformationUser2` | `PasswordLastSet`      | `pwdLastSet`               | FileTime structure       | Yes              | Yes                   | Accurate     | Timestamp indicating when the user’s password was last changed.                      |
| 47        | `SamrQueryInformationUser2` | `AccountExpires`       | `accountExpires`           | FileTime structure       | Yes              | Yes                   | Accurate     | Date when the account will expire, if applicable.                                    |
| 47        | `SamrQueryInformationUser2` | `PasswordCanChange`    | Not explicitly defined     | FileTime structure       | Yes              | Yes                   | Accurate     | The date when the user can next change their password.                               |
| 47        | `SamrQueryInformationUser2` | `PasswordMustChange`   | `pwdLastSet` (calculated)  | FileTime structure       | Yes              | Yes                   | Accurate     | The date when the user’s password must be changed.                                   |
| 47        | `SamrQueryInformationUser2` | `FullName`             | `displayName`              | Unicode string           | Yes              | Yes                   | Accurate     | The full name of the user, as stored in the domain.                                  |
| 47        | `SamrQueryInformationUser2` | `HomeDirectory`        | `homeDirectory`            | Unicode string           | Yes              | Yes                   | Accurate     | The user’s home directory path.                                                      |
| 47        | `SamrQueryInformationUser2` | `HomeDrive`            | `homeDrive`                | Unicode string           | N/A              | No                    | N/A          | Drive letter associated with the user’s home directory.                              |
| 47        | `SamrQueryInformationUser2` | `ScriptPath`           | `scriptPath`               | Unicode string           | Yes              | Yes                   | Accurate     | Path to the user’s login script, if any.                                             |
| 47        | `SamrQueryInformationUser2` | `Workstations`         | `userWorkstations`         | Unicode string           | Yes              | Yes                   | Accurate     | A list of workstations from which the user is allowed to log on.                     |
| 47        | `SamrQueryInformationUser2` | `AdminComment`         | `description`              | Unicode string           | Yes              | Yes                   | Accurate     | A textual description of the user account, typically used for organizational purposes.|
| 47        | `SamrQueryInformationUser2` | `PrimaryGroupId`       | `primaryGroupID`           | Integer (32-bit)         | Yes              | Yes                   | Accurate     | RID of the user’s primary group.                                                     |
| 47        | `SamrQueryInformationUser2` | `ProfilePath`          | `profilePath`              | Unicode string           | Yes              | Yes                   | Accurate     | Path to the user’s roaming profile, if any.                                          |
| 47        | `SamrQueryInformationUser2` | `Acct Flags: ACB_NORMAL`| `userAccountControl`       | Bitmask                 | N/A              | No                    | N/A          | Indicates the account is a regular user account.                                     |
| 47        | `SamrQueryInformationUser2` | `Acct Flags: ACB_PWNOEXP`| `userAccountControl`       | Bitmask                | Yes              | Yes                   | Accurate     | Specifies that the account's password does not expire.                               |
| 47        | `SamrQueryInformationUser2` | `Acct Flags: AccountIsDisabled` | `userAccountControl` | Bitmask               | Yes              | Yes                   | Accurate     | Indicates the account is disabled.                                                   |
| 47        | `SamrQueryInformationUser2` | `Acct Flags: ACB_SMARTCARD_REQUIRED` | `userAccountControl` | Bitmask          | N/A              | No                    | N/A          | Specifies whether smart card is required for login.                                  |
| 47        | `SamrQueryInformationUser2` | `Acct Flags: ACB_TRUSTED_FOR_DELEGATION` | `userAccountControl` | Bitmask      | N/A              | No                    | N/A          | Specifies whether the account is trusted for delegation.                             |
| 47        | `SamrQueryInformationUser2` | `LogonHours`           | `logonHours`               | Bitmask                  | Yes              | Yes                   | Accurate     | A bitmask indicating the hours during which the user is allowed to log on.           |
| 47        | `SamrQueryInformationUser2` | `BadPasswordCount`     | `badPwdCount`              | Integer (32-bit)         | Yes              | Yes                   | Accurate     | The number of failed password attempts.                                              |
| 47        | `SamrQueryInformationUser2` | `LogonCount`           | `logonCount`               | Integer (32-bit)         | Yes              | Yes                   | Accurate     | The number of times the user has successfully logged on to the domain.               |
| 47        | `SamrQueryInformationUser2` | `Country Code`         | N/A                        | Integer                  | Yes              | Yes                   | Accurate     | The country code associated with the user account.                                   |
| 47        | `SamrQueryInformationUser2` | `Code Page`            | N/A                        | Integer                  | N/A              | No                    | N/A          | The code page used for the account's character encoding.                             |
| 47        | `SamrQueryInformationUser2` | `Password Expired`     | Derived (based on policies)| Boolean                  | N/A              | No                    | N/A          | Indicates if the account's password is expired.                                      |
| 39        | `SamrGetGroupsForUser`      | `RelativeId`           | `primaryGroupID`           | Integer (32-bit)         | N/A              | No                    | N/A          | A unique identifier of a group the user belongs to.                                  |
| 39        | `SamrGetGroupsForUser`      | `Attributes`           | `groupType`                | Integer (32-bit)         | N/A              | No                    | N/A          | Membership attributes specifying group relationships or roles.                       |
| 11        | `SamrEnumerateGroupsInDomain`| `RelativeId`          | `objectSid`                | Integer (32-bit)         | Yes              | Yes                   | Accurate     | A unique identifier assigned to the group within the domain.                         |
| 11        | `SamrEnumerateGroupsInDomain`| `Name`                | `cn`                       | Unicode string           | Yes              | Yes                   | Accurate     | The common name of the group as stored in the domain.                                |
| 25        | `SamrGetMembersInGroup`     | `MemberRids`           | `member`                   | Array of Integer (32-bit)|N/A               | No                    | N/A          | The RIDs (Relative Identifiers) of all members in the specified group.               |
| 25        | `SamrGetMembersInGroup`     | `MemberTypes`          | N/A                        | Array of Integer (32-bit)| N/A              | No                    | N/A          | Indicates the types or roles of members in the group, such as normal user or group.  |
| 15        | `SamrEnumerateAliasesInDomain`| `RelativeId`         | `objectSid`                | Integer (32-bit)         | N/A              | No                    | N/A          | A unique identifier assigned to the alias within the domain.                         |
| 15        | `SamrEnumerateAliasesInDomain`| `Name`               | `sAMAccountName`           | Unicode string           | Yes              | Yes                   | Accurate     | The name of the alias (built-in groups).                                             |
| 33        | `SamrGetMembersInAlias`     | `MemberSIDs`           | `objectSid`                | Array of SID structures  | N/A              | No                    | N/A          | Returns the list of SIDs for the members of the specified alias.                     |


#### rpcclient


Executed following commands:  
- `rpcclient -U "domain-y.local\\enum%LabAdm1!" 192.168.12.11 -c "enumdomusers"`
- `rpcclient -U "domain-y.local\\enum%LabAdm1!" 192.168.12.11 -c "enumdomgroups"`
- `rpcclient -U "domain-y.local\\enum%LabAdm1!" 192.168.12.11 -c "enumdomgroups domain"`
- `rpcclient -U "domain-y.local\\enum%LabAdm1!" 192.168.12.11 -c "enumdomgroups builtin"`
- `rpcclient -U "domain-y.local\\enum%LabAdm1!" 192.168.12.11 -c "enumprivs"`
- `rpcclient -U "domain-y.local\\enum%LabAdm1!" 192.168.12.11 -c "enumalsgroups builtin"`
- `rpcclient -U "domain-y.local\\enum%LabAdm1!" 192.168.12.11 -c "enumalsgroups domain"`
- `rpcclient -U "domain-y.local\\enum%LabAdm1!" 192.168.12.11 -c "lookupnames username"`
- `rpcclient -U "domain-y.local\\enum%LabAdm1!" 192.168.12.11 -c "lookupsids sid_value"`
- `rpcclient -U "domain-y.local\\enum%LabAdm1!" 192.168.12.11 -c "queryaliasmem builtin 544"`
- `rpcclient -U "domain-z.local\\enum%LabAdm1!" 192.168.12.11 -c "queryaliasmem domain 4194"`
- `rpcclient -U "domain-y.local\\enum%LabAdm1!" 192.168.12.11 -c "queryuser 0x1f4"`
- `rpcclient -U "domain-y.local\\enum%LabAdm1!" 192.168.12.11 -c "querygroup 4212"`
- `rpcclient -U "domain-y.local\\enum%LabAdm1!" 192.168.12.11 -c "queryusergroups 500"`
- `rpcclient -U "domain-y.local\\enum%LabAdm1!" 192.168.12.11 -c "queryuseraliases builtin S-1-5-21-2189324197-3478012550-1180063049-500"`
- `rpcclient -U "domain-y.local\\enum%LabAdm1!" 192.168.12.11 -c "queryuseraliases domain S-1-5-21-2189324197-3478012550-1180063049-4202"`
- `rpcclient -U "domain-y.local\\enum%LabAdm1!" 192.168.12.11 -c "querygroupmem 512"`
- `rpcclient -U "domain-y.local\\enum%LabAdm1!" 192.168.12.11 -c "queryaliasinfo builtin 544" -d 10`
- `rpcclient -U "domain-y.local\\enum%LabAdm1!" 192.168.12.11 -c "querydispinfo"`
- `rpcclient -U "domain-y.local\\enum%LabAdm1!" 192.168.12.11 -c "querydispinfo2"`
- `rpcclient -U "domain-y.local\\enum%LabAdm1!" 192.168.12.11 -c "querydispinfo3"`
- `rpcclient -U "domain-y.local\\enum%LabAdm1!" 192.168.12.11 -c "querydominfo"`
- `rpcclient -U "domain-y.local\\enum%LabAdm1!" 192.168.12.11 -c "getdompwinfo"`
- `rpcclient -U "domain-y.local\\enum%LabAdm1!" 192.168.12.11 -c "samlookupnames domain Administrator"`
- `rpcclient -U "domain-y.local\\enum%LabAdm1!" 192.168.12.11 -c "samlookupnames builtin Users"`
- `rpcclient -U "domain-y.local\\enum%LabAdm1!" 192.168.12.11 -c "samlookuprids domain 512"`
- `rpcclient -U "domain-y.local\\enum%LabAdm1!" 192.168.12.11 -c "samlookuprids builtin 544"`
- `rpcclient -U "domain-y.local\\enum%LabAdm1!" 192.168.12.11 -c "samquerysecobj"`
- `rpcclient -U "domain-y.local\\enum%LabAdm1!" 192.168.12.11 -c "lookupdomain domain-z.local"`
- `rpcclient -U "domain-y.local\\enum%LabAdm1!" 192.168.12.11 -c "getdispinfoidx Administrator 1"`
- `rpcclient -U "domain-y.local\\enum%LabAdm1!" 192.168.12.11 -c "enumdomains"`


| **OpNum** | **OpNum Name**             | **SAMR Field Name**     | **Domain Attribute Name**  | **Expected Data Type**   | **Completeness** | **Field Displayed?** | **Accuracy** | **Field Description** |
|-----------|----------------------------|-------------------------|----------------------------|--------------------------|------------------|----------------------|--------------|-----------------------|
| 15        | `SamrEnumerateAliasesInDomain`| `RelativeId`         | `objectSid`                | Integer (32-bit)         | Yes              | Yes                  | Accurate     | A unique identifier assigned to aliases (local groups) within the domain.             |
| 15        | `SamrEnumerateAliasesInDomain`| `Name`               | `sAMAccountName`           | Unicode string           | Yes              | Yes                  | Accurate     | The name of the alias group.                                                          |
| 11        | `SamrEnumerateGroupsInDomain`| `RelativeId`          | `objectSid`                | Integer (32-bit)         | Yes              | Yes                  | Accurate     | A unique identifier assigned to each group within the domain.                         |
| 11        | `SamrEnumerateGroupsInDomain`| `Name`                | `cn`                       | Unicode string           | Yes              | Yes                  | Accurate     | The name of the group.                                                                |
| 13        | `SamrEnumerateUsersInDomain`| `RelativeId`           | `objectSid`                | Integer (32-bit)         | Yes              | Yes                  | Accurate     | A unique identifier assigned to the user within the domain.                          |
| 13        | `SamrEnumerateUsersInDomain`| `Name`                 | `sAMAccountName`           | Unicode string (20 characters)| Yes         | Yes                  | Accurate     | A computer or service account name, logon name of the user.                          |
| 41        | `SamrGetDisplayEnumerationIndex` | `EnumerationIndex`| N/A                        | Integer                  | Yes              | Yes                  | Accurate     | Retrieves the index for enumerations based on display names.                          |
| 56        | `SamrGetDomainPasswordInformation` | `MinPasswordLength`     | `minPwdLength`                 | Integer      | Yes              | Yes                  | Accurate     | Minimum length required for domain passwords.                                        |
| 56        | `SamrGetDomainPasswordInformation` | `PasswordComplexity`    | `DOMAIN_PASSWORD_COMPLEX`      | Bitmask      | Yes              | Yes                  | Accurate     | Indicates if password complexity is enforced (e.g., requires special characters).    |
| 56        | `SamrGetDomainPasswordInformation` | `PasswordNoAnonChange`  | `DOMAIN_PASSWORD_NO_ANON_CHANGE`| Bitmask     | Yes              | Yes                  | Accurate     | Disallows anonymous password changes.                                                |
| 56        | `SamrGetDomainPasswordInformation` | `PasswordNoClearChange` | `DOMAIN_PASSWORD_NO_CLEAR_CHANGE`| Bitmask    | Yes              | Yes                  | Accurate     | Prevents password changes using plaintext passwords.                                 |
| 56        | `SamrGetDomainPasswordInformation` | `PasswordLockoutAdmins` | `DOMAIN_PASSWORD_LOCKOUT_ADMINS`| Bitmask     | Yes              | Yes                  | Accurate     | Specifies if administrative accounts are locked out on failed attempts.              |
| 56        | `SamrGetDomainPasswordInformation` | `PasswordStoreCleartext`| `DOMAIN_PASSWORD_STORE_CLEARTEXT`| Bitmask    | Yes              | Yes                  | Accurate     | Determines whether passwords are stored in cleartext.                                |
| 56        | `SamrGetDomainPasswordInformation` | `PasswordRefuseChange`  | `DOMAIN_REFUSE_PASSWORD_CHANGE`| Bitmask      | Yes              | Yes                  | Accurate     | Denies password change requests.                                                     |
| 5         | `SamrLookupDomainInSamServer`| `DomainSID`           | `objectSid`                | Security Identifier (SID)| Yes              | Yes                  | Accurate     | The resulting SID corresponding to the domain name.                                   |
| 33        | `SamrGetMembersInAlias`      | `MemberSIDs`          | `objectSid`                | Array of SIDs            | Yes              | Yes                  | Accurate     | Retrieves a list of SIDs for the members of a specified alias.                        |
| 40        | `SamrQueryDisplayInfo`         | `Acct Flags         | `userAccountControl`       | Bitmask                  | Yes              | Yes                  | Accurate     | Specifies the account is a regular user account.                                     |
| 40        | `SamrQueryDisplayInfo`         | `Account Name`      | `sAMAccountName`           | Unicode string           | Yes              | Yes                  | Accurate     | The logon name of the user account.                                                  |
| 40        | `SamrQueryDisplayInfo`         | `Description`       | `description`              | Unicode string           | Yes              | Yes                  | Accurate     | Textual description of the user account.                                             |
| 40        | `SamrQueryDisplayInfo`         | `Full Name`         | `displayName`              | Unicode string           | Yes              | Yes                  | Accurate     | The full name of the user account.                                                   |
| 40        | `SamrQueryDisplayInfo`         | `RID`               | `objectSid`                | Integer (Relative ID)    | Yes              | Yes                  | Accurate     | A unique relative identifier assigned to the user or group.                          |
| 48        | `SamrQueryDisplayInfo2`        | `Acct Flags         | `userAccountControl`       | Bitmask                  | Yes              | Yes                  | Accurate     | Specifies the account is a regular user account.                                     |
| 48        | `SamrQueryDisplayInfo2`        | `Account Name`      | `sAMAccountName`           | Unicode string           | Yes              | Yes                  | Accurate     | The logon name of the user account.                                                  |
| 48        | `SamrQueryDisplayInfo2`        | `Description`       | `description`              | Unicode string           | Yes              | Yes                  | Accurate     | Textual description of the user account.                                             |
| 48        | `SamrQueryDisplayInfo2`        | `Full Name`         | `displayName`              | Unicode string           | Yes              | Yes                  | Accurate     | The full name of the user account.                                                   |
| 48        | `SamrQueryDisplayInfo2`        | `RID`               | `objectSid`                | Integer (Relative ID)    | Yes              | Yes                  | Accurate     | A unique relative identifier assigned to the user or group.                          |
| 51        | `SamrQueryDisplayInfo3`        | `Acct Flags         | `userAccountControl`       | Bitmask                  | Yes              | Yes                  | Accurate     | Specifies the account is a regular user account.                                     |
| 51        | `SamrQueryDisplayInfo3`        | `Account Name`      | `sAMAccountName`           | Unicode string           | Yes              | Yes                  | Accurate     | The logon name of the user account.                                                  |
| 51        | `SamrQueryDisplayInfo3`        | `Description`       | `description`              | Unicode string           | Yes              | Yes                  | Accurate     | Textual description of the user account.                                             |
| 51        | `SamrQueryDisplayInfo3`        | `Full Name`         | `displayName`              | Unicode string           | Yes              | Yes                  | Accurate     | The full name of the user account.                                                   |
| 51        | `SamrQueryDisplayInfo3`        | `RID`               | `objectSid`                | Integer (Relative ID)    | Yes              | Yes                  | Accurate     | A unique relative identifier assigned to the user or group.                          |
| 8         | `SamrQueryInformationDomain` | `ForceLogoff`         | `forceLogoff`              | Relative Time Structure  | Yes              | Yes                  | Accurate     | Specifies the force logoff time for inactive sessions.                               |
| 8         | `SamrQueryInformationDomain` | `DomainName`          | `domainName`               | Unicode String           | Yes              | Yes                  | Accurate     | The name of the domain being queried.                                                |
| 8         | `SamrQueryInformationDomain` | `DomainServerState`   | N/A                        | Integer                  | Yes              | Yes                  | Accurate     | Indicates the current state of the domain server (e.g., enabled/disabled).            |
| 8         | `SamrQueryInformationDomain` | `Role`                | `domainRole`               | Integer (Enum)           | Yes              | Yes                  | Accurate     | Identifies the role of the domain server, such as Primary Domain Controller (PDC).   |
| 8         | `SamrQueryInformationDomain` | `NumUsers`            | `numUsers`                 | Integer (32-bit)         | Yes              | Yes                  | Accurate     | Total number of user accounts in the domain.                                         |
| 8         | `SamrQueryInformationDomain` | `NumGroups`           | `numGroups`                | Integer (32-bit)         | Yes              | Yes                  | Accurate     | Total number of group accounts in the domain.                                        |
| 8         | `SamrQueryInformationDomain` | `NumAliases`          | `numAliases`               | Integer (32-bit)         | Yes              | Yes                  | Accurate     | Total number of aliases (local groups) in the domain.                                |
| 20        | `SamrQueryInformationGroup` | `Name`                 | `cn`                       | Unicode String           | Yes              | Yes                  | Accurate     | The name of the group, including long group names if applicable.                     |
| 20        | `SamrQueryInformationGroup` | `Attributes`           | `groupAttributes`          | Bitmask                  | Yes              | Yes                  | Accurate     | Group attribute flags indicating properties such as mandatory, enabled, or denied.   |
| 20        | `SamrQueryInformationGroup` | `NumMembers`           | `groupMemberCount`         | Integer (32-bit)         | Yes              | Yes                  | Accurate     | The number of members within the group.                                              |
| 20        | `SamrQueryInformationGroup` | `Description`          | `description`              | Unicode String           | Yes              | Yes                  | Accurate     | A textual description of the group, often containing long descriptive text.          |
| 25        | `SamrGetMembersInGroup`     | `MemberRids`           | `member`                   | Array of Integer (32-bit)| Yes              | Yes                  | Accurate     | The RIDs (Relative Identifiers) of all members in the specified group.               |
| 25        | `SamrGetMembersInGroup`     | `MemberTypes`          | N/A                        | Array of Integer (32-bit)| Yes              | Yes                  | Accurate     | Indicates the types or roles of members in the group, such as normal user or group.  |
| 36        | `SamrQueryInformationUser`  | `LastLogon`            | `lastLogon`                | `FileTime`               | Yes              | Yes                  | Accurate     | Timestamp of the user's last successful logon.                                       |
| 36        | `SamrQueryInformationUser`  | `LastLogoff`           | `lastLogoff`               | `FileTime`               | Yes              | Yes                  | Accurate     | Timestamp of the user's last logoff.                                                 |
| 36        | `SamrQueryInformationUser`  | `PasswordLastSet`      | `pwdLastSet`               | `FileTime`               | Yes              | Yes                  | Accurate     | Timestamp indicating when the user's password was last changed.                      |
| 36        | `SamrQueryInformationUser`  | `AllowPasswordChange`  | N/A                        | `FileTime`               | Yes              | Yes                  | Accurate     | The date when the user can next change their password.                               |
| 36        | `SamrQueryInformationUser`  | `ForcePasswordChange`  | N/A                        | `FileTime`               | Yes              | Yes                  | Accurate     | The date when the user must change their password.                                   |
| 36        | `SamrQueryInformationUser`  | `AccountName`          | `sAMAccountName`           | `Unicode string`         | Yes              | Yes                  | Accurate     | The logon name of the user.                                                          |
| 36        | `SamrQueryInformationUser`  | `FullName`             | `displayName`              | `Unicode string`         | Yes              | Yes                  | Accurate     | The full name of the user.                                                           |
| 36        | `SamrQueryInformationUser`  | `HomeDirectory`        | `homeDirectory`            | `Unicode string`         | Yes              | Yes                  | Accurate     | The user's home directory path.                                                      |
| 36        | `SamrQueryInformationUser`  | `HomeDrive`            | `homeDrive`                | `Unicode string`         | Yes              | Yes                  | Accurate     | Drive letter associated with the user's home directory.                              |
| 36        | `SamrQueryInformationUser`  | `ScriptPath`           | `scriptPath`               | `Unicode string`         | Yes              | Yes                  | Accurate     | Path to the user's logon script.                                                     |
| 36        | `SamrQueryInformationUser`  | `ProfilePath`          | `profilePath`              | `Unicode string`         | Yes              | Yes                  | Accurate     | Path to the user's roaming profile, if applicable.                                   |
| 36        | `SamrQueryInformationUser`  | `Description`          | `description`              | `Unicode string`         | Yes              | Yes                  | Accurate     | A textual description of the user account.                                          |
| 36        | `SamrQueryInformationUser`  | `Workstations`         | `userWorkstations`         | `Unicode string`         | Yes              | Yes                  | Accurate     | A list of workstations from which the user is allowed to log on.                     |
| 36        | `SamrQueryInformationUser`  | `Comment`              | N/A                        | `Unicode string`         | Yes              | Yes                  | Accurate     | A comment associated with the user account.                                          |
| 36        | `SamrQueryInformationUser`  | `LogonHours`           | `logonHours`               | `Bitmask`                | Yes              | Yes                  | Accurate     | Specifies the hours during which the user is allowed to log on.                      |
| 36        | `SamrQueryInformationUser`  | `BadPasswordCount`     | `badPwdCount`              | `uint32`                 | Yes              | Yes                  | Accurate     | The number of incorrect password attempts.                                           |
| 36        | `SamrQueryInformationUser`  | `LogonCount`           | `logonCount`               | `uint32`                 | Yes              | Yes                  | Accurate     | The number of times the user has successfully logged on.                             |
| 36        | `SamrQueryInformationUser`  | `CountryCode`          | `countryCode`              | `uint32`                 | N/A              | No                   | N/A          | The country code associated with the user account.                                   |
| 36        | `SamrQueryInformationUser`  | `CodePage`             | `codePage`                 | `uint32`                 | N/A              | No                   | N/A          | The code page used for the account's character encoding.                             |
| 36        | `SamrQueryInformationUser`  | `PrivateData`          | N/A                        | `Buffer`                 | N/A              | No                   | N/A          | Sensitive private data associated with the user account.                             |
| 36        | `SamrQueryInformationUser`  | `RID`                  | `objectSid`                | `uint32`                 | Yes              | Yes                  | Accurate     | The Relative Identifier (RID) of the user.                                           |
| 36        | `SamrQueryInformationUser`  | `PrimaryGroupId`       | `primaryGroupID`           | `uint32`                 | Yes              | Yes                  | Accurate     | RID of the user's primary group.                                                     |
| 36        | `SamrQueryInformationUser`  | `AcctFlags`            | `userAccountControl`       | `Bitmask`                | Yes              | Yes                  | Accurate     | User account control flags, such as disabled, locked out, or password expiration.    |
| 36        | `SamrQueryInformationUser`  | `FieldsPresent`        | N/A                        | `Bitmask`                | Yes              | Yes                  | Accurate     | Indicates which fields are present in the response.                                  |
| 16        | `SamrGetAliasMembership`    | `Rids`                 | `objectSid`                | Array of RIDs (Relative Identifiers) | Yes  | Yes                  | Accurate     | Lists the RIDs (Relative Identifiers) within the domain, which correspond to portions of the full **SID**. |
| 39        | `SamrGetGroupsForUser`      | `RelativeId`           | `primaryGroupID`           | Integer (32-bit)         | Yes              | Yes                  | Accurate     | A unique identifier of a group the user belongs to.                                  |
| 39        | `SamrGetGroupsForUser`      | `Attributes`           | `groupType`                | Integer (32-bit)         | Yes              | Yes                  | Accurate     | Membership attributes specifying group relationships or roles.                       |
| 17        | `SamrLookupNames`           | `Rids`                 | `objectSid`                | Array of RIDs (Relative Identifiers) | Yes  | Yes                  | Accurate     | The RIDs associated with the input names, which are part of the full SIDs.          |
| 17        | `SamrLookupNames`           | `Types`                | N/A                        | Array of Integers        | Yes              | Yes                  | Accurate     | Indicates the type of object (e.g., user, group, or alias) associated with the RID.     |
| 18        | `SamrLookupRids`            | `Names`                | N/A                        | Array of Strings (Unicode)| Yes             | Yes                  | Accurate     | The names corresponding to the given Relative Identifiers** (RIDs).                  |
| 18        | `SamrLookupRids`            | `Types`                | N/A                        | Array of Integers        | Yes              | Yes                  | Accurate     | Indicates the type of object (e.g., user, group, or alias) associated with the RID.     |
| 3         | `SamrQuerySecurityObject`   | `Revision`             | N/A                        | Integer (8-bit)          | Yes              | Yes                  | Accurate     | Security descriptor revision.                                                        |
| 3         | `SamrQuerySecurityObject`   | `Type`                 | N/A                        | Integer (16-bit)         | Yes              | Yes                  | Accurate     | Specifies the type and presence of DACL (Discretionary Access Control List).          |
| 3         | `SamrQuerySecurityObject`   | `DACL`                 | N/A                        | Binary                   | Yes              | Yes                  | Accurate     | Describes the Discretionary Access Control List.                                      |
| 3         | `SamrQuerySecurityObject`   | `Num ACEs`             | N/A                        | Integer (32-bit)         | Yes              | Yes                  | Accurate     | The number of Access Control Entries (ACEs) present in the DACL.                     |
| 3         | `SamrQuerySecurityObject`   | `ACE Type`             | N/A                        | Integer (8-bit)          | Yes              | Yes                  | Accurate     | Specifies the type of ACE, e.g., "Access Allowed" or "Access Denied".                |
| 3         | `SamrQuerySecurityObject`   | `Permissions`          | N/A                        | Bitmask                  | Yes              | Yes                  | Accurate     | Specifies the permissions granted or denied.                                         |
| 3         | `SamrQuerySecurityObject`   | `SID`                  | N/A                        | SID Structure            | Yes              | Yes                  | Accurate     | Security Identifier (SID) of the ACE owner.                                          |



