# Impacket Tool Evaluation

Impacket library is a suite of tools for interacting with network protocols.  SAMR requests were executed against a cross-forest domain controller `zdc1.domain-z.local` from the client `yws.domain-y.local`.

The network traffic captured was encrypted. To decrypt the capture in Wireshark, the NT password `LabAdm1!` must be provided under:  
`Preferences > Protocols > NTLMSSP > NT Password`
**"LINK"**

## Request Specification Compliance in Detail

This evaluation analyzed compliance with the SAMR protocol's "Desired Access" field, focusing on access permissions requested during operations. The "Desired Access" field in the SAMR header specifies permissions requested for each operation.
The analysis followed the sequence of operations observed in the network traffic. Duplicate entries within a tool with identical permissions were omitted for clarity. Non-compliant entries are explicitly highlighted.

#### samrdump.py

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

---


#### net.py

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

### Completeness and Accuracy Comparison Criterion

This subsection evaluates the ability of tools to parse and display data attributes retrieved through SAMR operations. The analysis includes the completeness of the attributes retrieved for each SAMR operation and the accuracy of the values compared to expected results. Tools are assessed for handling expected data types, edge cases, and inconsistencies.
| **OpNum** | **OpNum Name**             | **SAMR Field Name**     | **Domain Attribute Name**  | **Expected Data Type**   | **Completeness** | **Field Displayed?** | **Accuracy** | **Field Description**                                                                 |
|-----------|----------------------------|-------------------------|----------------------------|--------------------------|------------------|-----------------------|--------------|---------------------------------------------------------------------------------------|
| 13        | `SamrEnumerateUsersInDomain`| `RelativeId`           | `objectSid`                | Integer (32-bit)         | Yes              | Yes                   | Accurate     | A unique identifier assigned to the user within the domain.                          |
| 13        | `SamrEnumerateUsersInDomain`| `Name`                 | `sAMAccountName`           | Unicode string (20 characters)| Yes         | Yes                   | Accurate     | The logon name of the user.                                                          |
| 47        | `SamrQueryInformationUser2` | `RelativeId`           | `objectSid`                | Integer (32-bit)         | Yes              | Yes                   | Accurate     | A unique identifier assigned to the user within the domain.                          |
| 47        | `SamrQueryInformationUser2` | `Name`                 | `sAMAccountName`           | Unicode string           | Yes              | Yes                   | Accurate     | The logon name of the user.                                                          |
| 47        | `SamrQueryInformationUser2` | `LastLogon`            | `lastLogon`                | FileTime structure       | Yes              | Yes                   | Accurate     | Timestamp of the user’s last successful logon.                                       |
| 47        | `SamrQueryInformationUser2` | `LastLogoff`           | `lastLogoff`               | FileTime structure       | N/A              | No                    | N/A          | Timestamp of the user’s last logoff.                                                 |
| 47        | `SamrQueryInformationUser2` | `PasswordLastSet`      | `pwdLastSet`               | FileTime structure       | Yes              | Yes                   | Accurate     | Timestamp indicating when the user’s password was last changed.                      |
| 47        | `SamrQueryInformationUser2` | `AccountExpires`       | `accountExpires`           | FileTime structure       | Yes              | Yes                   | Accurate     | Date when the account will expire, if applicable.                                    |
| 47        | `SamrQueryInformationUser2` | `PasswordCanChange`    | Not explicitly defined     | FileTime structure       | Yes              | Yes                   | Accurate     | The date when the user can next change their password.                               |
| 47        | `SamrQueryInformationUser2` | `PasswordMustChange`   | `pwdLastSet` (calculated)  | FileTime structure       | Yes              | Yes                   | Accurate     | The date when the user’s password must be changed.                                   |
| 13        | `SamrEnumerateUsersInDomain`| `Name`                 | `sAMAccountName`           | Unicode string (20 characters)| Yes         | Yes                   | Accurate     | The logon name of the user.                                                          |
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
| 39        | `SamrGetGroupsForUser`     | `RelativeId`            | `primaryGroupID`           | Integer (32-bit)         | N/A              | No                    | N/A          | A unique identifier of a group the user belongs to.                                   |
| 39        | `SamrGetGroupsForUser`     | `Attributes`            | `groupType`                | Integer (32-bit)         | N/A              | No                    | N/A          | Membership attributes specifying group relationships or roles.                        |
| 11        | `SamrEnumerateGroupsInDomain`| `RelativeId`          | `objectSid`                | Integer (32-bit)         | Yes              | Yes                   | Accurate     | A unique identifier assigned to the group within the domain.                         |
| 11        | `SamrEnumerateGroupsInDomain`| `Name`                | `cn`                       | Unicode string           | Yes              | Yes                   | Accurate     | The common name of the group as stored in the domain.                                |




