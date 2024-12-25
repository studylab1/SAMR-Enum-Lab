# SharpHound Tool Evaluation

SharpHound is a data collection tool designed to gather information from Active Directory environments, enabling security assessments by mapping attack paths and potential privileges using the BloodHound platform. SAMR requests were executed against a cross-forest domain controller `zdc1.domain-z.local` from the client `yws.domain-y.local`.

## Request Specification Compliance in Detail

This evaluation analyzed compliance with the SAMR protocol's "Desired Access" field, focusing on access permissions requested during operations. The "Desired Access" field in the SAMR header specifies permissions requested for each operation.
The analysis followed the sequence of operations observed in the network traffic. Duplicate entries within a tool with identical permissions were omitted for clarity. Non-compliant entries are explicitly highlighted.

Executed with the following parameters:  
`SharpHound.exe -c All --domaincontroller zdc1.domain-z.local`

| **SAMR Operation**  | **Wireshark Label** | **OpNum** | **Requested Access Rights (Hex)** | **Rights Description**  | **Required for Operation?** | **Compliance with Requested Access** |
|---------------------|---------------------|-----------|-----------------------------------|-------------------------|-----------------------------|--------------------------------------|
| `SamrConnect5`      | `Connect5`          | 64        | `0x00000031`                      | `SAM_SERVER_CONNECT` (`0x00000001`),<br> `SAM_SERVER_ENUMERATE_DOMAINS` (`0x00000010`),<br> `SAM_SERVER_LOOKUP_DOMAIN` (`0x00000020`)  | Yes | Compliant  |
| `SamrEnumerateDomainsInSamServer`| `EnumDomains`| 6   | Access not requested              | N/A                     | N/A                         | N/A                                  |
| `SamrLookupDomainInSamServer`| `LookupDomain`| 5      | Access not requested              | N/A                     | N/A                         | N/A                                  |
| `SamrOpenDomain`    | `OpenDomain`        | 7         | `0x00000300`                      | `DOMAIN_LIST_ACCOUNTS` (`0x00000100`),<br> `DOMAIN_LOOKUP` (`0x00000200`)| Yes | Compliant   |
| `SamrEnumerateAliasesInDomain`| EnumDomainAliases`| 15| Access not requested              | N/A                     | N/A                         | N/A                                  |
| `SamrOpenAlias`   | `OpenAlias`            | 27       | `0x00000004`                      | `ALIAS_LIST_MEMBERS` (`0x00000004`) | Yes             | Compliant                            |
| `SamrGetMembersInAlias` | `GetMembersInAlias`| 33     | Access not requested              | N/A                     | N/A                         | N/A                                  |
| `SamrCloseHandle` | `Close` | 1                       | Access not requested              | N/A                     | N/A                         | N/A                                  |

### Completeness and Accuracy Comparison Criterion

This subsection evaluates the ability of tools to parse and display data attributes retrieved through SAMR operations. The analysis includes the completeness of the attributes retrieved for each SAMR operation and the accuracy of the values compared to expected results. Tools are assessed for handling expected data types, edge cases, and inconsistencies.
| **OpNum** | **OpNum Name**             | **SAMR Field Name**     | **Domain Attribute Name**  | **Expected Data Type**   | **Completeness** | **Field Displayed?** | **Accuracy** | **Field Description** |
|-----------|----------------------------|-------------------------|----------------------------|--------------------------|------------------|----------------------|--------------|-----------------------|
| 15        | `SamrEnumerateAliasesInDomain`| `RelativeId`         | `objectSid`                | Integer (32-bit)         | Yes              | Yes                  | Accurate     | A unique identifier assigned to the alias within the domain.                         |
| 15        | `SamrEnumerateAliasesInDomain`| `Name`               | `sAMAccountName`           | Unicode string           | Yes              | Yes                  | Accurate     | The name of the alias (built-in groups).                                             |
| 33        | `SamrGetMembersInAlias`      | `MemberSIDs`          | `objectSid`                | Array of SIDs            | Yes              | Yes                  | Accurate     | Retrieves a list of SIDs for the members of a specified alias.                        |
