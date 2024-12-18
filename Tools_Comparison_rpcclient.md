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
| 40        | `SamrQueryDisplayInfo`         | `Account Name`                    | `sAMAccountName`               | Unicode string | Yes      | Yes                  | Accurate     | The logon name of the user account.                                                  |
| 40        | `SamrQueryDisplayInfo`         | `Description`                     | `description`                  | Unicode string | Yes      | Yes                  | Accurate     | Textual description of the user account.                                             |
| 40        | `SamrQueryDisplayInfo`         | `Full Name`                       | `displayName`                  | Unicode string | Yes      | Yes                  | Accurate     | The full name of the user account.                                                   |
| 40        | `SamrQueryDisplayInfo`         | `RID`                             | `objectSid`                    | Integer (Relative ID)| Yes| Yes                  | Accurate     | A unique relative identifier assigned to the user or group.                          |

