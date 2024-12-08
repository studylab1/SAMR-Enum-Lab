### Scripts and Traffic Captures

This page offers downloadable resources, including traffic capture files, scripts, command outputs, and other materials generated and utilized during the research

| Tool Name       | Link                                                                                                     | Size  | Type  | Command Executed                                | Comments |
|-----------------|---------------------------------------------------------------------------------------------------------|-------|-------|------------------------------------------------|----------|
| `Net`        | [Download](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Capture_Files/net_user_administrator__domain.pcapng) | 47 KB     | Traffic Capture      | `net.exe user administrator /domain`  | Request to local domain |
| `Net`        |  | 26 KB    | Command Output      | `net.exe user administrator /domain`  | Request to local domain |
| `Net`        | [Download](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Capture_Files/net_user__domain.pcapng) | 56  KB    | Traffic Capture       | `net.exe user /domain` | Request to local domain         |
| `Net`        |  | 3 KB    | Command Output      | `net.exe user /domain`  | Request to local domain |
| `Net`       | [Download](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Capture_Files/net_group__domain.pcapng)                           | 47 KB      | Traffic Capture       | `net.exe group /domain`  |  Request to local domain        |
| `Net`       |   | 6 KB      | Command Output   | `net.exe group /domain`  |  Request to local domain        |
| `Net`       | [Download](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Capture_Files/net_group_domain_admins__domain.pcapng)                       | 24 KB      | Traffic Capture       | `net.exe group "domain admins" /domain'`  |  Request to local domain     
| `Net`       |   | 1 KB      | Command Output       | `net.exe group "domain admins" /domain'`  |  Request to local domain     
| `PowerShell` **ADD LINK TO SCRIPT**  |        | 6.8 MB      | Traffic Capture | `powershell_ad.ps1` |  Executed **ADD LINK** script with 42 ActiveDirectory cmdlets  |
| `PowerShell` |        | 6.4 KB      | Script | `powershell_ad.ps1` |  The script contains 42 ActiveDirectory cmdlets which are related to enumeration  |
| `Impacket samrdump.py` |        | 119 KB      | Traffic Capture | `python.exe samrdump.py domain-y/enum:LabAdm1!@zdc1.domain-z.local` |    |
| `Impacket net.py` |        |       | Traffic Capture | `python.exe net.py domain-y/enum:LabAdm1!@zdc1.domain-z.local user` |    |

---

### SAMR Operation Numbers Details

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


