# SAMR Enumeration Tools Comparison

This page provides a comparison of tools used for SAMR enumeration in Active Directory environments. Each tool's specifications, supported SAMR operations (OpNums), compatibility, and limitations are documented. This data was collected to show how different tools access, retrieve, and handle SAMR data, including in multi-forest configurations.

## Table of Contents
1. [Introduction](#introduction)
2. [Criteria for Tool Evaluation](#criteria-for-tool-evaluation)
3. [Tool Comparison Table](#tool-comparison-table)
4. [Detailed Tool Descriptions](#detailed-tool-descriptions)
5. [Lab Setup](#lab-setup)

---

## Introduction

This comparison covers tools used for Active Directory reconnaissance through the SAMR protocol, which retrieves information on users, groups, domains, and other security settings.

## System Configuration and Enumeration vector
The detailed configuration of the lab is specified on the Lab_Setup page.  
Other aspects to specify are as follows:  
- **Domain Functional Level**: Windows Server 2016.
- **Forest Functional Level**: Windows Server 2016.

The lab environment was established with two one-way forest trusts between `domain-y.local` and `domain-z.local`, configured with forest-wide authentication. The SAMR enumeration scan is conducted from workstation `yws1` to `zdc1` domain controller in cases where tools support cross-forest requests and from workstation `yws1` to `ydc1` where they do not.
The data on the `ydc1` and `zdc1` are populated with BadBlood tool.

## Criteria for Tool Evaluation

The following criteria were used to evaluate each tool's SAMR enumeration capabilities:

- **OpNum Coverage**: Lists supported SAMR operation numbers.
- **Multi-Forest Support**: Indicates if the tool can perform enumeration across domains within a forest trust.
- **Permissions Compliance**: Specifies the default access permissions required by each tool.
- **Error Handling**: Describes the tool’s ability to handle restricted permissions or errors.
- **Authentication Methods**: Details whether NTLM, Kerberos, or both protocols are supported.
- **Access Level Requirements**: Specifies whether administrator privileges are required for operation.

---

## Tool Comparison Table

| Tool                 | Version                     | OpNum Coverage (%) | Multi-Forest Support | Permissions Compliance | Error Handling | Authentication Methods | Access Level Requirements | Supported OS       |
|----------------------|-----------------------------|--------------------|-----------------------|------------------------|----------------|------------------------|---------------------------|---------------------|
| net user             | Windows 11 23H2, OS build 22631.4317 |                    | No                    | Least-privilege        |                | NTLM                   | Regular                  | Windows            |
| PowerShell           |                             |                    |                       |                        |                |                        |                           |                     |
| Impacket             |                             |                    |                       |                        |                |                        |                           |                     |
| CrackMapExec         |                             |                    |                       |                        |                |                        |                           |                     |
| rpcclient (Samba)    |                             |                    |                       |                        |                |                        |                           |                     |
| smbclient (Samba)    |                             |                    |                       |                        |                |                        |                           |                     |
| BloodHound           |                             |                    |                       |                        |                |                        |                           |                     |
| Nmap (NSE Scripts)   |                             |                    |                       |                        |                |                        |                           |                     |
| Enum4linux           |                             |                    |                       |                        |                |                        |                           |                     |
| Enum4linux-ng        |                             |                    |                       |                        |                |                        |                           |                     |
| Metasploit Framework |                             |                    |                       |                        |                |                        |                           |                     |
| PowerSploit          |                             |                    |                       |                        |                |                        |                           |                     |
| SAMRi10              |                             |                    |                       |                        |                |                        |                           |                     |
| RPC Investigator     |                             |                    |                       |                        |                |                        |                           |                     |

## OpNum Coverage Table

### OpNum Descriptions

- **OpNum 6**: `SamrEnumerateDomainsInSamServer` – Lists all domains managed by the SAM server.
- **OpNum 11**: `SamrEnumerateGroupsInDomain` – Retrieves a list of groups within a specific domain.
- **OpNum 13**: `SamrEnumerateUsersInDomain` – Retrieves user accounts within a specific domain.
- **OpNum 15**: `SamrEnumerateAliasesInDomain` – Lists alias groups within a domain.
- **OpNum 16**: `SamrGetAliasMembership` – Shows alias memberships for a specific user or SID.
- **OpNum 17**: `SamrLookupNamesInDomain` – Converts account names into SIDs within a domain.
- **OpNum 18**: `SamrLookupIdsInDomain` – Maps SIDs back to account names.
- **OpNum 36**: `SamrQueryInformationUser` – Retrieves detailed information on a specific user account.
- **OpNum 39**: `SamrGetGroupsForUser` – Lists all group memberships for a specified user.
- **OpNum 40**: `SamrQueryDisplayInformation` – Provides display information in a paginated format.
- **OpNum 41**: `SamrGetDisplayEnumerationIndex` – Retrieves the display index for paginated enumerations.
- **OpNum 51**: `SamrQueryDisplayInformation3` – Enables detailed and filtered queries for large-scale user, group, or machine account enumeration.
- **OpNum 56**: `SamrGetDomainPasswordInformation` – Retrieves password policy information for the domain.

### Evaluation of OpNum Coverage

| Tool                 | 6  | 11 | 13 | 15 | 16 | 17 | 18 | 36 | 39 | 40 | 41 | 51 | 56 |
|----------------------|----|----|----|----|----|----|----|----|----|----|----|----|----|
| net user             |    |    |    |    |    |    |    |    |    |    |    |    |    |
| PowerShell           |    |    |    |    |    |    |    |    |    |    |    |    |    |
| Impacket             |    |    |    |    |    |    |    |    |    |    |    |    |    |
| CrackMapExec         |    |    |    |    |    |    |    |    |    |    |    |    |    |
| rpcclient (Samba)    |    |    |    |    |    |    |    |    |    |    |    |    |    |
| smbclient (Samba)    |    |    |    |    |    |    |    |    |    |    |    |    |    |
| BloodHound           |    |    |    |    |    |    |    |    |    |    |    |    |    |
| Nmap (NSE Scripts)   |    |    |    |    |    |    |    |    |    |    |    |    |    |
| Enum4linux           |    |    |    |    |    |    |    |    |    |    |    |    |    |
| Enum4linux-ng        |    |    |    |    |    |    |    |    |    |    |    |    |    |
| Metasploit Framework |    |    |    |    |    |    |    |    |    |    |    |    |    |
| PowerSploit          |    |    |    |    |    |    |    |    |    |    |    |    |    |
| SAMRi10              |    |    |    |    |    |    |    |    |    |    |    |    |    |
| RPC Investigator     |    |    |    |    |    |    |    |    |    |    |    |    |    |

---

## Evaluation for "Desired Access" Compliance

### "Net User"

| SAMR Operation | Wireshark Label | OpNum | Access Mask (Hex) | Access Rights (Description) | Required for Task? | Compliance with Desired Access |
|------------------|-----------------|-------|--------------------|-----------------------------|---------------------|--------------------------------|
| `SamrConnect5`   | `Connect5`        |  64   | `0x00000030`      | SAM_SERVER_LOOKUP_DOMAIN, SAM_SERVER_ENUMERATE_DOMAINS             | Yes                 | Compliant                       |
