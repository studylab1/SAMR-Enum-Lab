# Laboratory Setup for SAMR Enumeration in Multi-Forest Trust Configurations

This page outlines the laboratory environment created to simulate multiple Active Directory forest trust configurations for investigating SAMR (Security Account Manager Remote) enumeration attacks. The setup is specifically designed to analyze how various trust relationships between forests impact SAMR enumeration, with a focus on identifying security risks related to cross-forest reconnaissance and privilege escalation. Rather than providing a step-by-step guide for building the lab, the page describes the essential components and the final structure of the environment, allowing flexibility in how the implementation is carried out. Administrators may choose different methods to achieve the same configuration, depending on their tools and expertise. This approach highlights the intended outcome rather than the specific steps, as there are multiple ways to set up the lab while arriving at an identical result.

**⚠️ Important Security Note:**

> **⚠️ This laboratory setup includes certain configurations that are intentionally _**not secure for production environments**_. These insecure settings, such as disabling encryption in the SMB protocol or relaxing security controls, have been applied for research purposes. Specifically, these settings allow for easier analysis of network traffic and testing SAMR enumeration techniques in a controlled environment.**
> 
> **💡 These configurations are solely meant to facilitate research and should _not_ be used in live or production environments.** Using them outside of this context could expose critical vulnerabilities in your network. It is essential to ensure that production systems always follow secure configurations that align with best practices for security.**

---
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
- **IPv6 is disabled** to simplify network analysis and ensure consistent results when investigating SAMR enumeration attacks. Disabling IPv6 reduces network complexity and ensures all traffic flows over IPv4, allowing for more focused research on SMB and SAMR protocol behavior without dual-stack complications. This configuration is for research purposes only and not recommended for production environments.
- **SMBv2/3 encryption is disabled**. This allows to perform network traffic analysis.
- **Latest Patches on October 10, 2024.** The result is verified on the systems patched until October 10, 2024.
