# Laboratory Setup

This laboratory represents a multi-forest Active Directory deployment for SAMR enumeration research. All forests run Windows Server 2022 at the Windows Server 2016 forest functional level. Every forest contains one domain controller. The forests share a two-way forest trust; the trust authentication mode is configured as either forest-wide authentication or selective authentication, depending on the enumeration scenario.

A stand-alone Ubuntu 24.04 workstation outside both forests runs the `samr-enum` client by using a non-privileged domain account from one of the forests. The workstation communicates with the domain controllers over IPv4-routable subnets; no host or network firewalls block SMB or RPC traffic. Packet capture is enabled on the domain controller under enumeration. SMB signing is active, and SMB encryption is negotiated when supported.

Directory data is produced with the BadBlood generator and manual entry. Forest **domain-b.local** holds user, group, computer, Managed Service Account, Group Managed Service Account, and Organisational Unit objects. Scenario-specific ACL changes are applied directly to these objects as required.

## Security Considerations.
**⚠️ Important Security Note:**

> **⚠️ This laboratory setup includes certain configurations that are intentionally _**not secure for production environments**_. These insecure settings, such as disabling encryption in the SMB protocol or relaxing security controls, are applied for research purposes. Specifically, these settings allow for easier analysis of network traffic and testing of SAMR enumeration techniques in a controlled environment.**
> 
> **💡 These configurations are solely meant to facilitate research and should _not_ be used in live or production environments.** Using them outside of this context could expose critical vulnerabilities in your network. It is essential to ensure that production systems always follow secure configurations that align with best practices for security.

---

## Key Components of the Lab

### Active Directory Forests
The lab consists of multiple Active Directory (AD) forests, each configured with different trust types, including:

- **Two-Way Forest Trust with Forest Level Authentication**
- **Two-Way Forest Trust with Selective Authentication**

<img width="1043" alt="image" src="https://github.com/user-attachments/assets/ef99bc04-4ea5-4aee-bd8b-0c56354ec2fa" />

### Domain Controllers
Each forest includes domain controllers (DCs) running the latest version of Windows Server 2022 (as of October 2024) to ensure a realistic and up-to-date testing environment. The domain controllers facilitate SAMR enumeration by simulating real-world trust configurations across forests.

### SAMR Enumeration
The SAMR protocol enables enumeration of users, groups, computers and domain structure across forest boundaries. This setup allows researchers to investigate how trust configurations affect the data exposed by SAMR, thereby identifying potential security vulnerabilities.

## Virtual Environment Configuration

The virtual laboratory is hosted using Microsoft Hyper-V virtualization technology.

### The Host Server Specifications for Tools Evaluation

- **Operating System:** Windows 10 Enterprise (Version 22H2)
- **RAM:** 32 GB
- **Processor:** AMD Ryzen 7 PRO 5750G with Radeon Graphics, 3.80 GHz.
- **Virtualization Platform:** Microsoft Hyper-V
- **Networking:** All virtual machines are connected to one Hyper-V private network.  
  The "Private (Lab1)" Virtual Switch Extensions:
  - "Microsoft Windows Filtering Platform": Disabled
  - "Microsoft Azure VFP Switch Extension": Disabled
  - "Microsoft NDIS Capture": Enabled
 
### The Host Server Specifications for samr-enum Tool Enumeration
The host server was used to enumerate domains in foreign forests using the `samr-enum` tool.

- **Operating System:** Windows 11 Enterprise (Version 23H2)
- **RAM:** 64 GB
- **Processor:** 12th Gen Intel(R) Core(TM) i9-12900   2.40 GHz
- **Virtualization Platform:** Microsoft Hyper-V
- **Networking:** All virtual machines are connected to one Hyper-V private network.  
  The "Private (Lab1)" Virtual Switch Extensions:
  - "Microsoft Windows Filtering Platform": Disabled
  - "Microsoft Azure VFP Switch Extension": Disabled
  - "Microsoft NDIS Capture": Enabled
  
### The Virtual Machines Specifications

#### Workstation
- **Operating System:** Windows 11 Enterprise x86-64 (version 23H2, OS build 22631.4317) or Ubuntu Desktop 24.04.1 LTS.
- **RAM:** 4 GB
- **Processor:** 2vCPU
- **Virtual Machine Generation**: 2  

#### Domain Controller and Routing Service
- **Operating System:** Windows Server 2022 Standard x86-64 (version 21H2, OS build 20348.2762)
- **RAM:** 4 GB
- **Processor:** 2vCPU
- **Virtual Machine Generation**: 2

### Active Directory Domain Services Configuration
- **Domain Functional Level**: Windows Server 2016
- **Forest Functional Level**: Windows Server 2016
- **Time syncronization**: Hyper-V host server.
- **DNS service**: The Conditional Forwarders in the DNS service on each domain controller are configured to forward DNS requests to the corresponding DNS server within the lab. Reverse Lookup Zone contains addresses of the foreign domain controllers in the lab to make it possible to resolve their IP addresses for DNS Conditional Forwarders.

### Data Population with BadBlood

This lab utilizes the **[BadBlood](https://github.com/davidprowe/BadBlood)** tool, which automates the process of populating Active Directory (AD) with synthetic data for testing purposes. BadBlood creates a wide range of Active Directory objects, including users, groups, computers, and group policy objects, to simulate a realistic AD environment. This data is critical for testing SAMR enumeration techniques, as it provides a representative set of AD objects that attackers could potentially enumerate across forest boundaries.

- **BadBlood Version:** The lab is configured using **BadBlood v1.0**, which was released on **May 18, 2023**.
  
- **Purpose of Populating Data:**
  - To simulate a populated AD environment, including the creation of users, groups, and computers with varied permissions.
  - To create real-world conditions for SAMR enumeration and cross-forest reconnaissance testing by allowing a variety of AD objects and relationships.
  - To help researchers evaluate the potential exposure of sensitive data in multi-forest trust scenarios.

### Microsoft Routing and Remote Access Service (RRAS) Configuration
The purpuse of the service is to route the network traffic between lab internal subnets. The RRAS (LAN Routing feature) service does not require additional configurations. 


### System Configuration
- **IPv6 is disabled** IPv6 is disabled in this lab setup to reduce potential complications arising from dual-stack networking, particularly when analyzing the SAMR and SMB protocols. Although IPv6 offers enhanced address space and security features like IPsec, disabling it ensures that all traffic flows over IPv4, which simplifies packet capture and traffic analysis using tools like Wireshark. Additionally, disabling IPv6 minimizes potential attack vectors associated with misconfigurations in dual-stack environments. The protocols is disabled by following:  
`Get-NetAdapterBinding -ComponentID *6|Disable-NetAdapterBinding`  
`Set-NetIsatapConfiguration -State Disabled`  
`Set-Net6to4Configuration -State Disabled`  
`Set-NetTeredoConfiguration -Type Disabled`  
- **Latest Patches** The result is verified on systems patched up to October 22, 2024.
- **Logging**. For auditing clients' requests the domain controllers have following configurations, for both `Success` and `Failure` in `Local Security Policy > Advanced Audit Policy Configuration > System Audit Policies - Local Group Policy Object`:
  - `Object Access - Audit SAM`
  - `Detailed Tracking - Audit RPC Events`
  - `DC Access - Security Settings > Advanced Audit Policy Configuration 
- **Windows Defender Firewall**: Disabled in GUI "Customize Settings" all profiles ("Domain", "Private" and "Public").

### Computer Naming Convention

The computer names follow this convention (excluding router server):

`<letter-representing-forest><role><number-of-the-computer>`

- **letter-representing-forest:** A single letter indicating the forest to which the computer belongs (e.g., `a`, `b`). The exception is xws1.
- **role:** A two-letter abbreviation representing the computer’s role in the environment, such as:
  - **dc**: Domain Controller
  - **ws**: Workstation
- **number-of-the-computer:** A sequential number indicating the specific machine within its role (e.g., `1`, `2`, `3`).

#### Examples:
- `adc1`: First domain controller in "domain-a.local" domain.
- `xws1`: First Workstation in "domain-x.local" domain.

#### Special hosts:
- `xdc1`: domain controller that contains a large dataset.
- `xws1`: Linux client used to execute the enumeration scan.

### Network Setup

The following table outlines the IP addressing scheme used for the lab environment. Each forest is assigned its own dedicated /24 subnet, with a domain controller (DC) and workstation (WS) residing in each subnet.

| **Role**              | **Hostname**      | **Domain**                                  | **VLAN ID** | **IP Address/Subnet** | **Gateway (Routing Server)** |
|-----------------------|-------------------|---------------------------------------------|-------------|-----------------------|------------------------------|
| **Routing Server**    | router            | <div align="right">N/A</div>                | 10          | 192.168.1.1/24         | N/A                          |
|                       |                   |                                             | 20          | 192.168.2.1/24         | N/A                          |
|                       |                   |                                             | 100         | 192.168.10.1/24        | N/A                          |
|                       |                   |                                             | 110         | 192.168.11.1/24        | N/A                          |
|                       |                   |                                             | 120         | 192.168.12.1/24        | N/A                          |
| **Domain Controller** | adc1              | <div align="right">domain-a.local</div>     | 10          | 192.168.1.11/24        | 192.168.1.1                  |
| **Domain Controller** | bdc1              | <div align="right">domain-b.local</div>     | 20          | 192.168.2.11/24        | 192.168.2.1                  |
| **Domain Controller** | xdc1              | <div align="right">domain-x.local</div>     | 100         | 192.168.10.11/24       | 192.168.10.1                 |
| **Workstation**       | xws1              | <div align="right">N/A</div>                | 100         | 192.168.10.101/24      | 192.168.10.1                 |
| **Domain Controller** | ydc1              | <div align="right">domain-y.local</div>     | 110         | 192.168.11.11/24       | 192.168.11.1                 |
| **Domain Controller** | zdc1              | <div align="right">domain-z.local</div>     | 120         | 192.168.12.11/24       | 192.168.12.1                 |

The entire network is configured to be **isolated** from the host machine to ensure a controlled and contained environment. No traffic can enter or exit the lab network from the host server, preventing external interference and ensuring accurate testing conditions.

Additionally, **no traffic filtering** is applied within the lab. This means that:

- **No intermediate firewalls** are placed between subnets.
- **No host-based firewalls** are enabled on the domain controllers or workstations.

This unfiltered setup allows for unrestricted communication between all systems in the lab, which is essential for testing enumeration techniques and observing network traffic without interference from security controls. The isolated and unfiltered network ensures that the focus remains on the behavior of the enumeration techniques and attack vectors within the controlled lab environment.


### Traffic Capture and Analysis

In this lab environment, traffic analysis is essential for monitoring and understanding SAMR enumeration activities across different domains and trust boundaries. The following setup and tools ensure visibility and facilitate packet analysis:

1. **Router Configuration for Traffic Visibility**:
   - The router system is responsible for routing traffic between the isolated subnets.
   - Since this is a lab setup, there are no firewall rules or security policies configured on the router, allowing unrestricted traffic flow for accurate traffic analysis. This setup is essential for observing SAMR enumeration and related cross-domain interactions without interference from security controls.

2. **Traffic Capture with Wireshark**:
   - Version 4.2.0
   - Installed on each domain controller
   - The logs are exported in PCAPNG format, allowing for later review and analysis. This is useful for studying historical traffic and analyzing SAMR requests without real-time constraints.

3. **Segmentation by Subnet**: Captures are separated by subnet to isolate traffic specific to each domain. This segmentation helps compare enumeration results across forests and assess differences in traffic patterns when trust configurations change.

This unfiltered, isolated, and documented setup ensures that traffic capture provides a picture of SAMR enumeration behavior within the lab environment. The focus remains on observing and understanding the interaction between trusted domains.

