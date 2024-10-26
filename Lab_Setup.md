# Laboratory Setup for SAMR Enumeration in Multi-Forest Trust Configurations

This page outlines the laboratory environment created to simulate multiple Active Directory forest trust configurations for investigating SAMR (Security Account Manager Remote) enumeration attacks. The setup is specifically designed to analyze how various trust relationships between forests impact SAMR enumeration, with a focus on identifying security risks related to cross-forest reconnaissance and privilege escalation. Rather than providing a step-by-step guide for building the lab, the page describes the essential components and the final structure of the environment, allowing flexibility in how the implementation is carried out. Administrators may choose different methods to achieve the same configuration, depending on their tools and expertise. This approach highlights the intended outcome rather than the specific steps, as there are multiple ways to set up the lab while arriving at an identical result.

## Security Considerations.
**⚠️ Important Security Note:**

> **⚠️ This laboratory setup includes certain configurations that are intentionally _**not secure for production environments**_. These insecure settings, such as disabling encryption in the SMB protocol or relaxing security controls, have been applied for research purposes. Specifically, these settings allow for easier analysis of network traffic and testing SAMR enumeration techniques in a controlled environment.**
> 
> **💡 These configurations are solely meant to facilitate research and should _not_ be used in live or production environments.** Using them outside of this context could expose critical vulnerabilities in your network. It is essential to ensure that production systems always follow secure configurations that align with best practices for security.

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
- **Networking:** All virtual machines are connected to one Hyper-V private network.  
  The "Private (Lab1)" Virtual Switch Extensions:
  - "Microsoft Windows Filtering Platform": Disabled
  - "Microsoft Azure VFP Switch Extension": Disabled
  - "Microsoft NDIS Capture": Enabled
  
### The Virtual Machines Specifications

#### Workstation
- **Operating System:** Windows 11 Enterprise x86-64 (version 23H2, OS build 22631.4317) 
- **RAM:** 4 GB
- **Processor:** 2vCPU
- **Virtual Machine Generation**: 2  

#### Domain Controller and Routing Service
- **Operating System:** Windows Server 2022 Standard x86-64 (version 21H2, OS build 20348.2762)
- **RAM:** 4 GB
- **Processor:** 2vCPU
- **Virtual Machine Generation**: 2

### Active Directory Domain Services Configuration
- **Domain Functional Level**: Windows Server 2016 or Windows Server 2012 R2, depending on the forest.
- **Forest Functional Level**: Windows Server 2016 or Windows Server 2012 R2, depending on the forest.
- **Time syncronization**: host server
- **DNS service**: The Conditional Forwarders in the DNS service on each domain controller are configured to forward DNS requests to the corresponding DNS server. Reverse Lookup Zone contains addresses of the foreign domain controllers to make it possible to resolve their IP addresses for DNS Conditional Forwarders.

### Data Population with BadBlood

This lab utilizes the **[BadBlood](https://github.com/davidprowe/BadBlood)** tool, which automates the process of populating Active Directory (AD) with synthetic data for testing purposes. BadBlood creates a wide range of Active Directory objects, including users, groups, computers, and group policy objects, to simulate a realistic AD environment. This data is critical for testing SAMR enumeration techniques, as it provides a representative set of AD objects that attackers could potentially enumerate across forest boundaries.

- **BadBlood Version:** The lab is configured using **BadBlood v1.0**, which was released on **May 18, 2023**.
  
- **Purpose of Populating Data:**
  - To simulate a populated AD environment, including the creation of users, groups, and computers with varied permissions.
  - To create real-world conditions for SAMR enumeration and cross-forest reconnaissance testing by allowing a variety of AD objects and relationships.
  - To help researchers evaluate the potential exposure of sensitive data in multi-forest trust scenarios.

### Cross-Forest Data Synchronization Setup

In this laboratory setup, a cross-forest synchronization of Active Directory data is achieved to ensure that each forest contains identical sets of objects for consistent testing. This synchronization allows for accurate analysis of SAMR enumeration in environments with various trust configurations.

After populating `xdc1.domain-x.local` with synthetic Active Directory data using the **BadBlood** tool, this data is replicated to other domains in separate forests (e.g., `domain-a.local`) using a temporary **two-way forest-wide trust**. This trust relationship enables the **Active Directory Migration Tool (ADMT)** to transfer users, groups, organizational units (OUs), and other relevant directory objects across forests. 

Key elements of the synchronization setup include:

- **Temporary Forest Trust**: A two-way, forest-wide trust is established between `domain-x.local` and each target forest, allowing ADMT to perform cross-forest migrations. This trust is removed following the data transfer to maintain the lab's isolated setup.

- **Data Replication via ADMT**: With the trust in place, ADMT is used to migrate key directory objects, including:
  - **Users and Groups**: ADMT transfers users, security groups, and distribution groups.
  - **Organizational Units (OUs)**: The OU hierarchy.
  - **Computer Accounts**
  - **Permissions and ACLs**: ADMT maintains the ACLs and permissions, preserving the access control settings applied in `domain-a.local`.

- **Schema Compatibility**: To prevent compatibility issues, schema extensions present in `domain-x.local` (such as those introduced by BadBlood) are applied to each target forest before initiating ADMT synchronization.

After the synchronization is complete, the trust relationship between `domain-x.local` and the target forests is removed, returning the lab to its isolated state. This setup ensures that each forest contains an identical dataset, allowing researchers to evaluate the effects of different trust relationships on SAMR enumeration within a controlled, consistent environment.

### Microsoft Routing and Remote Access Service (RRAS) Configuration
The purpuse of the service is to route the network traffic between lab internal subnets. The RRAS (LAN Routing feature) service does not require additional configurations. 

### Security Configuration on Operating System Level
- **Windows Defender Firewall**: Disabled in GUI "Customize Settings" all profiles ("Domain", "Private" and "Public").
- **Local and Group Policy Settings**: Default
- ......

### System Configuration
- **IPv6 is disabled** IPv6 is disabled in this lab setup to reduce potential complications arising from dual-stack networking, particularly when analyzing the SAMR and SMB protocols. Although IPv6 offers enhanced address space and security features like IPsec, disabling it ensures that all traffic flows over IPv4, which simplifies packet capture and traffic analysis using tools like Wireshark. Additionally, disabling IPv6 minimizes potential attack vectors associated with misconfigurations in dual-stack environments. The protocols is disabled by following:  
`Get-NetAdapterBinding -ComponentID *6|Disable-NetAdapterBinding`  
`Set-NetIsatapConfiguration -State Disabled`  
`Set-Net6to4Configuration -State Disabled`  
`Set-NetTeredoConfiguration -Type Disabled`  
- **SMBv2/3 encryption is disabled**. Disabling encryption allows the capture and inspection of clear-text traffic, which is essential for studying protocol behavior and potential vulnerabilities without interference from encryption layers. The encryption is disabled by following:  
`Set-SmbServerConfiguration -EncryptData $false`
- **Latest Patches on October 10, 2024.** The result is verified on the systems patched until October 22, 2024.
- **Data Population**. This lab utilizes the BadBlood tool (released on May 18, 2023) to populate synthetic data in Active Directory.

### Computer Naming Convention

The computer names follow this convention (excluding router server):

`<domain-letter><role><number-of-the-computer>`

- **Domain Letter:** A single letter representing the domain to which the computer belongs (e.g., `a`, `b`, `c`).
- **Role:** A two-letter abbreviation for the computer's role in the environment, such as:
  - **dc**: Domain Controller
  - **ws**: Workstation
- **Number of the Computer:** A sequential number indicating the specific machine within its role (e.g., `1`, `2`, `3`).

#### Examples:
- `adc1`: Domain Controller 1 in domain "A".
- `bws1`: Workstation 1 in domain "B".

### Network Setup

The following table outlines the IP addressing scheme used for the lab environment. Each forest is assigned its own dedicated /24 subnet, with a domain controller (DC) and workstation (WS) residing in each subnet.

| **Role**             | **Hostname**       | **Domain**      | **VLAN ID** | **IP Address/Subnet** | **Gateway (Routing Server)** |
|----------------------|--------------------|-----------------|-------------|-----------------------|------------------------------|
| **Routing Server**   | router             | N/A             | 5           | 192.168.0.1/24         | N/A                          |
|                      |                    |                 | 10          | 192.168.1.1/24         | N/A                          |
|                      |                    |                 | 20          | 192.168.2.1/24         | N/A                          |
|                      |                    |                 | 30          | 192.168.3.1/24         | N/A                          |
|                      |                    |                 | 40          | 192.168.4.1/24         | N/A                          |
|                      |                    |                 | 50          | 192.168.5.1/24         | N/A                          |
|                      |                    |                 | 60          | 192.168.6.1/24         | N/A                          |
| **Domain Controller** | xdc1                 | domain-x.local  | 5         | 192.168.0.10/24        | 192.168.0.1                  |
| **Domain Controller** | adc1                 | domain-a.local  | 10          | 192.168.1.10/24        | 192.168.1.1                  |
| **Workstation**       | aws1                 | domain-a.local  | 10          | 192.168.1.100/24       | 192.168.1.1                  |
| **Domain Controller** | bdc1                 | domain-b.local  | 20          | 192.168.2.10/24        | 192.168.2.1                  |
| **Workstation**       | bws1                 | domain-b.local  | 20          | 192.168.2.100/24       | 192.168.2.1                  |
| **Domain Controller** | cdc1                 | domain-c.local  | 30          | 192.168.3.10/24        | 192.168.3.1                  |
| **Workstation**       | cws1                 | domain-c.local  | 30          | 192.168.3.100/24       | 192.168.3.1                  |
| **Domain Controller** | ddc1                 | domain-d.local  | 40          | 192.168.4.10/24        | 192.168.4.1                  
| **Workstation**       | dws1                 | domain-d.local  | 40          | 192.168.4.100/24       | 192.168.4.1                  |
| **Domain Controller** | edc1                 | domain-e.local  | 50          | 192.168.5.10/24        | 192.168.5.1                  
| **Workstation**       | ews1                 | domain-e.local  | 50          | 192.168.5.100/24       | 192.168.5.1                  |
| **Domain Controller** | fdc1                 | domain-f.local  | 60          | 192.168.6.10/24        | 192.168.6.1                  
| **Workstation**       | fws1                 | domain-f.local  | 60          | 192.168.6.100/24       | 192.168.6.1                  |

The entire network is configured to be **isolated** from the host machine to ensure a controlled and contained environment. No traffic can enter or exit the lab network from the host server, preventing external interference and ensuring accurate testing conditions.

Additionally, **no traffic filtering** is applied within the lab. This means that:

- **No intermediate firewalls** are placed between subnets.
- **No host-based firewalls** are enabled on the domain controllers or workstations.

This unfiltered setup allows for unrestricted communication between all systems in the lab, which is essential for testing enumeration techniques and observing network traffic without interference from security controls. The isolated and unfiltered network ensures that the focus remains on the behavior of the enumeration techniques and attack vectors within the controlled lab environment.
