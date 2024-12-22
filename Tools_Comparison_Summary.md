# SAMR Enumeration Tools Comparison

This page provides a comparison of tools used for SAMR enumeration in Active Directory environments. Each tool's specifications, supported SAMR operations (OpNums), compatibility, and limitations are documented. This data was collected to show how different tools access, retrieve, and handle SAMR data, including in cross-forest configurations.

## Table of Contents
1. [Introduction](#introduction)
2. [System Configuration and Enumeration Vector](#system-configuration-and-enumeration-vector)
3. [Tool Versions and Specifications](#tool-versions-and-specifications)
4. [Criteria for Tool Evaluation](#criteria-for-tool-evaluation)
5. [Tool Comparison Results](#tool-comparison-results)
   - [Evaluation of Tool Comparison Criteria](#evaluation-of-tool-comparison-criteria)
   - [Detailed Evaluation of OpNum Coverage](#detailed-evaluation-of-opnum-coverage)
6. [OpNum Descriptions](#opnum-descriptions)

---

## Introduction

This comparison covers tools used for Active Directory reconnaissance through the SAMR protocol, which retrieves information on users, groups, domains, and other security settings.

## System Configuration and Enumeration Vector
The detailed configuration of the lab is specified on the Lab Setup page.  
Other aspects to specify are as follows:  
- **Domain Functional Level**: Windows Server 2016.
- **Forest Functional Level**: Windows Server 2016.

The lab environment was established with two one-way forest trusts between `domain-y.local` and `domain-z.local`, configured with forest-wide authentication. The SAMR enumeration scan was conducted from workstation `yws1` to `zdc1` domain controller in cases where tools supported cross-forest requests and from workstation `yws1` to `ydc1` domain controller where they did not.
The data on `ydc1` and `zdc1` were populated using the BadBlood tool.

## Tool Versions and Specifications

The following table provides version numbers for the tools evaluated during this research.

| Tool Name           | Version       | Additional Notes                    |
|---------------------|---------------|-------------------------------------|
| Net                 | Built-in      | Windows 11 Enterprise x86-64 (version 23H2, OS build 22631.4317)    |
| PowerShell          | 1.0.1.0       | ActiveDirectory Module. Windows 11 Enterprise x86-64 (version 23H2, OS build 22631.4317) |
| Impacket            | 0.12.0        | For this research, only samrdump.py and net.py from the Impacket suite were used.      |
| CrackMapExec        | 6.1.0 - John Wick|                                  |
| Enum4linux          | 0.9.1         |                                     |
| Enum4linux-ng       | 1.3.4         |                                     |
| rpcclient           | 4.15.13       | Part of the Samba suite             |
| Metasploit          | 6.4.41 dev    | Part of the Metasploit Framework    |


## Criteria for Tool Evaluation

The following criteria were used to evaluate each tool's SAMR enumeration capabilities:

- **OpNum Coverage**: Lists supported SAMR operation numbers.
- **Cross-forest Support**: Indicates if the tool can perform enumeration across domains within a forest trust.
- **Permissions Compliance**: Specifies the default access permissions required by each tool.
- **Error Handling**: Describes the tool’s ability to handle restricted permissions or errors.
- **Authentication Methods**: Details whether NTLM, Kerberos, or both protocols are supported.
- **Access Level Requirements**: Specifies whether administrator privileges are required for operation.

---

## Tool Comparison Results 

### Evaluation of Tool Comparison Criteria
> **Note:** The evaluation results focus on analyzing tools’ support for cross-forest SAMR requests. If a tool does not support cross-forest SAMR requests or uses a different protocol for such requests, other evaluation criteria are not assessed, and the corresponding values are marked as N/A (Not Applicable).


---

| Tool Name    | Cross-Forest Request Support | OpNum Coverage | Excessive Permission Detection | Data Parsing and Accuracy | Supported Authentication Types | Access Level Requirements |
|--------------|------------------------------|----------------|--------------------------------|---------------------------|--------------------------------|---------------------------|
| Net          | No                           | N/A            | N/A                            | N/A                       | N/A                            | N/A                       |
| PowerShell   | Yes                          | N/A            | N/A                            | N/A                       | N/A                            | N/A                       |
| Impacket     | Yes                          |                | Yes                            | Accurate                  | NTLM and Kerberos              | Standard Access           |
| CrackMapExec | Yes                          |                | Yes                            | Accurate                  | NTLM and Kerberos              | Standard Access           |
| Enum4linux   | No                           | N/A            | N/A                            | N/A                       | N/A                            | N/A                       |
| Enum4linux-ng| No                           | N/A            | N/A                            | N/A                       | N/A                            | N/A                       |
| rpcclient    | Yes                          |                | Yes                            | Accurate                  | NTLM and Kerberos              | Standard Access           |
| rpcclient    | Yes                          |                | Yes                            | Accurate                  | NTLM and Kerberos              | Standard Access           |
| Metasploit   | Yes                          |                | No                             | Accurate                  | NTLM                           | Standard Access           |

---

### Detailed Evaluation of OpNum Coverage
> **Note:** The evaluation results in this section are based on cross-forest SAMR requests.  

⚫️ - Supported  
○ - Not Supported


| Tool \ OpNum         | 0  | 1  | 3  | 5  | 6  | 7  | 8  | 11 | 13 | 15 | 16 | 17 | 18 | 19 | 20 | 25 | 27 | 33 | 34 | 36 | 39 | 40 | 41 | 44 | 46 | 47 | 48 | 51 | 56 | 57 | 64 | 65 |
|----------------------|----|----|----|----|----|----|----|----|----|----|----|----|----|----|----|----|----|----|----|----|----|----|----|----|----|----|----|----|----|----|----|----|
| Net                  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | 
| PowerShell           | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  |
| Impacket             | ●  | ●  | ○  | ●  | ●  | ●  | ○  | ●  | ●  | ●  | ●  | ●  | ●  | ●  | ○  | ●  | ●  | ●  | ●  | ○  | ●  | ○  | ○  | ○  | ○  | ●  | ○  | ○  | ○  | ○  | ○  | ●  |
| CrackMapExec         | ●  | ●  | ○  | ●  | ●  | ●  | ○  | ○  | ●  | ●  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ●  | ○  | ○  | ○  | ○  | ○  | ●  | ●  | ○  | ○  | ○  | ●  | ○  | ○  |
| Enum4linux           | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  |
| Enum4linux-ng        | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  |
| rpcclient            | ●  | ○  | ●  | ●  | ●  | ●  | ●  | ●  | ●  | ●  | ●  | ●  | ●  | ●  | ●  | ●  | ●  | ●  | ●  | ●  | ●  | ●  | ●  | ●  | ○  | ○  | ●  | ●  | ●  | ○  | ●  | ○  |
| Metasploit           | ●  | ●  | ○  | ●  | ●  | ●  | ●  | ○  | ●  | ○  | ○  | ●  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ○  | ●  |

