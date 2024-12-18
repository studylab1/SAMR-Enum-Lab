# rpcclient Tool Evaluation

rpcclient is a command-line tool, part of the Samba suite, used to interact with the Microsoft Remote Procedure Call (MS-RPC) protocol. It allows querying and managing Windows-based systems remotely over SMB, enabling tasks like enumerating users, groups, shares, and retrieving domain or system information.
SAMR requests were executed against cross-forest domain controller `zdc1.domain-z.local` and `xdc1.domain-x.local` from the client `yws.domain-y.local`.

## Request Specification Compliance in Detail

This evaluation analyzed compliance with the SAMR protocol's "Desired Access" field, focusing on access permissions requested during operations. The "Desired Access" field in the SAMR header specifies permissions requested for each operation.
The analysis followed the sequence of operations observed in the network traffic. Duplicate entries within a tool with identical permissions were omitted for clarity. Non-compliant entries are explicitly highlighted.

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
| `SamrEnumerateAliasesInDomain`| EnumDomainAliases`| 15| Access not requested               | N/A                    | N/A                         | N/A                                  |
| `SamrCloseHandle`   | `Close`             | 1         | Access not requested               | N/A                    | N/A                         | N/A                                  |
| `SamrOpenDomain`    | `OpenDomain`        | 7         | `0x0000000b`     | `MDOMAIN_READ_PASSWORD_PARAMETERS` (`0x00000001`) <br> `DOMAIN_WRITE_PASSWORD_PARAMS` (`0x00000002`) <br> `DOMAIN_WRITE_OTHER_PARAMETERS` (`0x00000008`)   | Yes  | Compliant  |
| `SamrOpenDomain`    | `OpenDomain`        | 7         | `0x0000000d`     | `MDOMAIN_READ_PASSWORD_PARAMETERS` (`0x00000001`) <br> `DOMAIN_READ_OTHER_PARAMETERS` (`0x00000004`) <br> `DOMAIN_WRITE_OTHER_PARAMETERS` (`0x00000008`)   | Yes  | Compliant  |
| `SamrOpenUser`      | `OpenUser`          | 34        | `0x02000000`     | **`MAXIMUM_ALLOWED` (``0x02000000``)**   | No                          | Not Compliant                        |
| `SamrOpenAlias`     | `OpenAlias`         | 27        | `0x02000000`     | **`MAXIMUM_ALLOWED` (``0x02000000``)**   | No                          | Not Compliant                        |
| `SamrOpenGroup`     | `OpenGroup`         | 19        | `0x02000000`     | **`MAXIMUM_ALLOWED` (``0x02000000``)**   | No                          | Not Compliant                        |


---


### Completeness and Accuracy Comparison Criterion

This subsection evaluates the ability of tools to parse and display data attributes retrieved through SAMR operations. The analysis includes the completeness of the attributes retrieved for each SAMR operation and the accuracy of the values compared to expected results. Tools are assessed for handling expected data types, edge cases, and inconsistencies.
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
