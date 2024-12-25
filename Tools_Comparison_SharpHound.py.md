# SharpHound Tool Evaluation

SharpHound is a data collection tool designed to gather information from Active Directory environments, enabling security assessments by mapping attack paths and potential privileges using the BloodHound platform. SAMR requests were executed against a cross-forest domain controller `zdc1.domain-z.local` from the client `yws.domain-y.local`.

## Request Specification Compliance in Detail

This evaluation analyzed compliance with the SAMR protocol's "Desired Access" field, focusing on access permissions requested during operations. The "Desired Access" field in the SAMR header specifies permissions requested for each operation.
The analysis followed the sequence of operations observed in the network traffic. Duplicate entries within a tool with identical permissions were omitted for clarity. Non-compliant entries are explicitly highlighted.

Executed with the following parameters:  
`SharpHound.exe -c All --domaincontroller zdc1.domain-z.local`

| **SAMR Operation**  | **Wireshark Label** | **OpNum** | **Requested Access Rights (Hex)** | **Rights Description**  | **Required for Operation?** | **Compliance with Requested Access** |
|---------------------|---------------------|-----------|-----------------------------------|-------------------------|-----------------------------|--------------------------------------|
| `SamrConnect5`      | `Connect5`          | 64        | `0x00000031`                      | `SAM_SERVER_CONNECT` (`0x00000001`), `SAM_SERVER_ENUMERATE_DOMAINS` (`0x00000010`), `SAM_SERVER_LOOKUP_DOMAIN` (`0x00000020`)   | Yes   | Compliant  |
| `SamrEnumerateDomainsInSamServer` | `EnumDomains`| 6  | Access not requested               | N/A                    | N/A                         | N/A                                  |
| `SamrLookupDomainInSamServer`     | `LookupDomain`    | 5   | Access not requested         | N/A                    | N/A                         | N/A                                  |
