# CrackMapExec Tool Evaluation

CrackMapExec is a post-exploitation and pentesting tool designed to streamline network enumeration, lateral movement, and credential validation within Active Directory environments. SAMR requests were executed against a cross-forest domain controller `zdc1.domain-z.local` from the client `yws.domain-y.local`.

The network traffic captured was encrypted. To decrypt the capture in Wireshark, the NT password `LabAdm1!` must be provided under:  
`Preferences > Protocols > NTLMSSP > NT Password`
**"LINK"**

## Request Specification Compliance in Detail

This evaluation analyzed compliance with the SAMR protocol's "Desired Access" field, focusing on access permissions requested during operations. The "Desired Access" field in the SAMR header specifies permissions requested for each operation.
The analysis followed the sequence of operations observed in the network traffic. Duplicate entries within a tool with identical permissions were omitted for clarity. Non-compliant entries are explicitly highlighted.

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




### Completeness and Accuracy Comparison Criterion

This subsection evaluates the ability of tools to parse and display data attributes retrieved through SAMR operations. The analysis includes the completeness of the attributes retrieved for each SAMR operation and the accuracy of the values compared to expected results. Tools are assessed for handling expected data types, edge cases, and inconsistencies.
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
| 46        | `SamrQueryDomainInformation2` | `DomainPasswordComplex`        | Derived from `pwdProperties` | Boolean           | Yes         | Yes                   | Accurate     | Indicates whether password complexity is enforced.                                     |
| 46        | `SamrQueryDomainInformation2` | `DomainPasswordNoAnonChange`   | Derived from `pwdProperties` | Boolean           | Yes         | Yes                   | Accurate     | Indicates if anonymous users are prohibited from changing passwords.                   |
| 46        | `SamrQueryDomainInformation2` | `DomainPasswordNoClearChange`  | Derived from `pwdProperties` | Boolean           | Yes         | Yes                   | Accurate     | Indicates if cleartext passwords cannot be changed.                                    |
| 46        | `SamrQueryDomainInformation2` | `DomainPasswordLockoutAdmins`  | Derived from `pwdProperties` | Boolean           | Yes         | Yes                   | Accurate     | Specifies if administrators are locked out after too many failed password attempts.    |
| 46        | `SamrQueryDomainInformation2` | `DomainPasswordStoreCleartext` | Derived from `pwdProperties` | Boolean           | Yes         | Yes                   | Accurate     | Indicates if passwords can be stored in cleartext.                                     |
| 46        | `SamrQueryDomainInformation2` | `DomainRefusePasswordChange`   | Derived from `pwdProperties` | Boolean           | Yes         | Yes                   | Accurate     | Specifies if password changes are refused for certain accounts.                        |







