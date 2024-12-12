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
|-----------|----------------------------|-------------------------|----------------------------|--------------------------|------------------|-----------------------|--------------|--------------------------------------------------------------------------------------|
