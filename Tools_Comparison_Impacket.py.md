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

| **OpNum** | **Attribute** | **Expected Data Type**  | **Completeness** |**Attribute Displayed?** | **Accuracy** | **Attribute Description** |
|-----------|---------------|-------------------------|------------------|-------------------------|--------------|---------------------------|
| 13        | RID           | Integer (32-bit)        | ...              | ...                     | ...          | A unique identifier assigned to the user within the domain |
| 13        | Account Name  | String (variable length)| ...              | ...                     | ...          | The logon name of the user |

