# Laboratory Setup for SAMR Enumeration in Multi-Forest Trust Configurations

This page outlines the laboratory environment created to simulate multiple Active Directory forest trust configurations for investigating SAMR (Security Account Manager Remote) enumeration attacks. The setup is specifically designed to analyze how various trust relationships between forests impact SAMR enumeration, with a focus on identifying security risks related to cross-forest reconnaissance and privilege escalation. Rather than providing a step-by-step guide for building the lab, the page describes the essential components and the final structure of the environment, allowing flexibility in how the implementation is carried out. Administrators may choose different methods to achieve the same configuration, depending on their tools and expertise. This approach highlights the intended outcome rather than the specific steps, as there are multiple ways to set up the lab while arriving at an identical result.

## Security Considerations.
**⚠️ Important Security Note:**

> **⚠️ This laboratory setup includes certain configurations that are intentionally _**not secure for production environments**_. These insecure settings, such as disabling encryption in the SMB protocol or relaxing security controls, have been applied for research purposes. Specifically, these settings allow for easier analysis of network traffic and testing SAMR enumeration techniques in a controlled environment.**
> 
> **💡 These configurations are solely meant to facilitate research and should _not_ be used in live or production environments.** Using them outside of this context could expose critical vulnerabilities in your network. It is essential to ensure that production systems always follow secure configurations that align with best practices for security.**

---

## Research Goals

..text..

## Key Components of the Lab

### Active Directory Forests
The lab consists of multiple Active Directory (AD) forests, each configured with different trust types, including:

- **One-Way Trusts** (inbound and outbound)
- **Two-Way Trusts**
- **Transitive and Non-Transitive Trusts**
- **Selective and Forest-Wide Authentication Scopes**

### Domain Controllers
Each forest includes domain controllers (DCs) running the latest version of Windows Server to ensure a realistic and up-to-date testing environment. The domain controllers facilitate SAMR enumeration by simulating real-world trust configurations across forests.

### Trust Configurations
Various trust relationships between the forests are established to test the impact of:

- **Trust Direction** (e.g., inbound, outbound, bidirectional)
- **Authentication Scopes** (e.g., selective vs. forest-wide)
- **Transitivity** (whether trust is passed to other domains or not)

### SAMR Enumeration
The SAMR protocol is used to perform enumeration of users, groups, and domain structure across forest boundaries. This setup allows researchers to investigate how trust configurations affect the data exposed by SAMR, which is critical for identifying potential security vulnerabilities.

## Objectives
The laboratory setup aims to provide insights into:

- The extent of data leakage via SAMR enumeration in different trust configurations.
- How forest trust types influence enumeration attack surfaces.
- Strategies for mitigating SAMR-based attacks in multi-forest environments.

## Virtual Environment Configuration

The virtual laboratory is hosted using Microsoft Hyper-V virtualization technology.

### The Host Server Specifications

- **Operating System:** Windows 10 Enterprise (Version 22H2)
- **RAM:** 32 GB
- **Processor:** AMD Ryzen 7 PRO 5750G with Radeon Graphics, 3.80 GHz
- **Virtualization Platform:** Microsoft Hyper-V
- **Networking:** "Private Network"

### The Virtual Machines Specifications

#### Workstation
- **Operating System:** Windows 11 Enterprise 23H2 x86-64 (version 23H2)
- **RAM:** 4 GB
- **Processor:** 2vCPU  

#### Domain Controller
- **Operating System:** Windows Server 2022 Standard x86-64
- **RAM:** 4 GB
- **Processor:** 4vCPU

### System Configuration
- **IPv6 is disabled** IPv6 is disabled in this lab setup to reduce potential complications arising from dual-stack networking, particularly when analyzing the SAMR and SMB protocols. Although IPv6 offers enhanced address space and security features like IPsec, disabling it ensures that all traffic flows over IPv4, which simplifies packet capture and traffic analysis using tools like Wireshark. Additionally, disabling IPv6 minimizes potential attack vectors associated with misconfigurations in dual-stack environments. The protocols is disabled by following:  
`Get-NetAdapterBinding -ComponentID *6|Disable-NetAdapterBinding`  
`Set-NetIsatapConfiguration -State Disabled`  
`Set-Net6to4Configuration -State Disabled`  
`Set-NetTeredoConfiguration -Type Disabled`  
- **SMBv2/3 encryption is disabled**. Disabling encryption allows the capture and inspection of clear-text traffic, which is essential for studying protocol behavior and potential vulnerabilities without interference from encryption layers. The encryption is disabled by following:  
`Set-SmbServerConfiguration -EncryptData $false`
- **Latest Patches on October 10, 2024.** The result is verified on the systems patched until October 10, 2024.
- **Data Population**. This lab utilizes the BadBlood tool (released on May 18, 2023) to populate synthetic data in Active Directory.

### Network Setup

The following table outlines the IP addressing scheme used for the lab environment. Each forest is assigned its own dedicated /24 subnet, with a domain controller (DC) and workstation (WS) residing in each subnet.

| Role              | Hostname  | Domain          | IP Address       |
|-------------------|-----------|-----------------|------------------|
| Domain Controller | dc        | domain-A.lab    | 192.168.1.10/24  |
| Workstation       | ws        | domain-A.lab    | 192.168.1.11/24  |
| Domain Controller | dc        | domain-B.lab    | 192.168.2.10/24  |
| Workstation       | ws        | domain-B.lab    | 192.168.2.11/24  |
| Domain Controller | dc        | domain-C.lab    | 192.168.3.10/24  |
| Workstation       | ws        | domain-C.lab    | 192.168.3.11/24  |
| Domain Controller | dc        | domain-D.lab    | 192.168.4.10/24  |
| Workstation       | ws        | domain-D.lab    | 192.168.4.11/24  |
| Domain Controller | dc        | domain-E.lab    | 192.168.5.10/24  |
| Workstation       | ws        | domain-E.lab    | 192.168.5.11/24  |
| Domain Controller | dc        | domain-F.lab    | 192.168.6.10/24  |
| Workstation       | ws        | domain-F.lab    | 192.168.6.11/24  |

The entire network is configured to be **isolated** from the host machine to ensure a controlled and contained environment. No traffic can enter or exit the lab network from the host server, preventing external interference and ensuring accurate testing conditions.

Additionally, **no traffic filtering** is applied within the lab. This means that:

- **No intermediate firewalls** are placed between subnets.
- **No host-based firewalls** are enabled on the domain controllers or workstations.

This unfiltered setup allows for unrestricted communication between all systems in the lab, which is essential for testing enumeration techniques and observing network traffic without interference from security controls. The isolated and unfiltered network ensures that the focus remains on the behavior of the enumeration techniques and attack vectors within the controlled lab environment.
