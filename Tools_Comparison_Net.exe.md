## Evaluation of SAMR Request Compliance in Detail

The evaluation focuses on analyzing "Desired Access" fields in SAMR requests. For clarity, "Desired Access" is marked as a SAMR header, highlighting the specific access rights requested during operations.

### Method
The order of operations follows the sequence observed in the network traffic capture. Duplicate entries with identical requested permissions were excluded for simplicity. Entries marked in **bold** indicate non-compliance with the protocol specification.

---

### "net user" (to local domain controller)

The `net user` command was executed within the local domain, with all SAMR requests originating from `yws1` (workstation) and directed to `ydc1` (domain controller).  
The following commands were executed:
- `net user /domain`
- `net user administrator /domain`

Entries marked as `N/A` indicate cases where access was not requested or required for the operation.

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

---

### "net group" (to local domain controller)

The `net group` command was executed within the local domain. SAMR traffic was observed between `yws1` and `ydc1`. The following commands were executed:
- `net group /domain`
- `net group administrator /domain`

| **SAMR Operation**         | **Wireshark Label** | **OpNum** | **Requested Access Rights (Hex)** | **Rights Description**                                                                  | **Required for Operation?** | **Compliance with Requested Access** |
|-----------------------------|---------------------|-----------|------------------------------------|-----------------------------------------------------------------------------------------|-----------------------------|---------------------------------------|
| `SamrConnect5`              | `Connect5`          | 64        | `0x00000030`                       | `SAM_SERVER_ENUMERATE_DOMAINS` (`0x00000010`), `SAM_SERVER_LOOKUP_DOMAIN` (`0x00000020`) | Yes                         | Compliant                              |
| `SamrOpenDomain`            | `OpenDomain`        | 7         | `0x00000304`                       | `DOMAIN_WRITE_OTHER_PARAMETERS` (`0x00000008`),<br>`DOMAIN_LIST_ACCOUNTS` (`0x00000100`),<br>`DOMAIN_LOOKUP` (`0x00000200`) | Yes                         | Compliant                              |
| `SamrOpenGroup`             | `OpenGroup`         | 19        | `0x00000001`                       | `GROUP_READ_INFORMATION` (`0x00000001`)                                                | Yes                         | Compliant                              |
| `SamrOpenGroup`             | `OpenGroup`         | 19        | `0x00000010`                       | `GROUP_LIST_MEMBERS` (`0x00000010`)                                                    | Yes                         | Compliant                              |
| `SamrGetMembersInGroup`     | `QueryGroupMember`  | 25        | Access not requested               | N/A                                                                                     | N/A                         | N/A                                   |
