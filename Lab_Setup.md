# Laboratory Setup for SAMR Enumeration in Multi-Forest Trust Configurations

This page outlines the laboratory environment created to simulate multiple Active Directory forest trust configurations for investigating SAMR (Security Account Manager Remote) enumeration attacks. The setup is designed to analyze how different trust relationships between forests impact SAMR enumeration, focusing on security risks in cross-forest reconnaissance and privilege escalation.

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
- **Networking:** Private Network (isolated from the host server and Internet)

### The Virtual Machines Specifications

#### Workstation
- **Operating System:** Windows 11 Enterprise 23H2 x86-64 (version 23H2)
- **RAM:** 4 GB
- **Processor:** 2vCPU  

#### Domain Controller
- **Operating System:** Windows Server 2022 Standard x86-64
- **RAM:** 4 GB
- **Processor:** 4vCPU  

This setup allows for the creation and management of isolated virtual environments for testing SAMR enumeration in a multi-forest Active Directory configuration.
