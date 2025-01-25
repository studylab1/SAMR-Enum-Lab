# Laboratory Setup for SAMR Enumeration in Multi-Forest Trust Configurations

This page outlines the laboratory environment created to simulate multiple Active Directory forest trust configurations for investigating SAMR (Security Account Manager Remote) enumeration attacks. The setup is specifically designed to analyze how various trust relationships between forests impact SAMR enumeration, with a focus on identifying security risks related to cross-forest reconnaissance and privilege escalation. Rather than providing a step-by-step guide for building the lab, this page describes the essential components and the final structure of the environment, allowing flexibility in how the implementation is carried out. Administrators may choose different methods to achieve the same configuration, depending on their tools and expertise. This approach highlights the intended outcome rather than the specific steps, as there are multiple ways to set up the lab while arriving at an identical result.

## Security Considerations.
**⚠️ Important Security Note:**

> **⚠️ This laboratory setup includes certain configurations that are intentionally _**not secure for production environments**_. These insecure settings, such as disabling encryption in the SMB protocol or relaxing security controls, are applied for research purposes. Specifically, these settings allow for easier analysis of network traffic and testing of SAMR enumeration techniques in a controlled environment.**
> 
> **💡 These configurations are solely meant to facilitate research and should _not_ be used in live or production environments.** Using them outside of this context could expose critical vulnerabilities in your network. It is essential to ensure that production systems always follow secure configurations that align with best practices for security.

---

## Key Components of the Lab

### Active Directory Forests
The lab consists of multiple Active Directory (AD) forests, each configured with different trust types, including:

- **Forest and External Trusts**
- **One-Way Trusts** (inbound and outbound)
- **Selective and Forest-Wide Authentication Scopes**
- **Windows Server 2016 and Windows Server 2012 R2 Forest Functional Level**

![image](https://github.com/user-attachments/assets/6eaf4211-c1e0-4a82-a9d4-ac7fcafd7789)



### Domain Controllers
Each forest includes domain controllers (DCs) running the latest version of Windows Server to ensure a realistic and up-to-date testing environment. The domain controllers facilitate SAMR enumeration by simulating real-world trust configurations across forests.

### Trust Configurations
Various trust relationships between the forests are established to test the impact of:

- **Trust Direction** (e.g., inbound, outbound, bidirectional)
- **Authentication Scopes** (e.g., selective vs. forest-wide)
- **Transitivity** (whether trust is passed to other domains or not)

### SAMR Enumeration
The SAMR protocol is used to perform enumeration of users, groups, and domain structure across forest boundaries. This setup allows researchers to investigate how trust configurations affect the data exposed by SAMR, which is critical for identifying potential security vulnerabilities.

## Virtual Environment Configuration

The virtual laboratory is hosted using Microsoft Hyper-V virtualization technology.

### The Host Server Specifications for Tools Evaluation
The host server was used for tool evaluation activities and contained virtual machines in the domain-x.local, domain-y.local, and domain-z.local domains.

- **Operating System:** Windows 10 Enterprise (Version 22H2)
- **RAM:** 32 GB
- **Processor:** AMD Ryzen 7 PRO 5750G with Radeon Graphics, 3.80 GHz.
- **Virtualization Platform:** Microsoft Hyper-V
- **Networking:** All virtual machines are connected to one Hyper-V private network.  
  The "Private (Lab1)" Virtual Switch Extensions:
  - "Microsoft Windows Filtering Platform": Disabled
  - "Microsoft Azure VFP Switch Extension": Disabled
  - "Microsoft NDIS Capture": Enabled
 
### The Host Server Specifications for SAMRClient Tool Enumeration
The host server was used to enumerate domains in foreign forests using the SAMRClient tool.

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
- **Domain Functional Level**: Windows Server 2016 or Windows Server 2012 R2, depending on the forest.
- **Forest Functional Level**: Windows Server 2016 or Windows Server 2012 R2, depending on the forest.
- **Time syncronization**: host server.
- **DNS service**: The Conditional Forwarders in the DNS service on each domain controller are configured to forward DNS requests to the corresponding DNS server within the lab. Reverse Lookup Zone contains addresses of the foreign domain controllers in the lab to make it possible to resolve their IP addresses for DNS Conditional Forwarders.

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
- **Logging**. For auditing clients' requests the domain controllers have following configurations, for both `Success` and `Failure` in `Local Security Policy > Advanced Audit Policy Configuration > System Audit Policies - Local Group Policy Object`:
  - `Object Access - Audit SAM`
  - `Detailed Tracking - Audit RPC Events`
  - `DC Access - Audit Directory Service Access`

### Computer Naming Convention

The computer names follow this convention (excluding router server):

`<domain-letter><role><number-of-the-computer>`

- **Domain Letter:** A single letter representing the domain to which the computer belongs (e.g., `a`, `b`, `c`).
- **Role:** A two-letter abbreviation for the computer's role in the environment, such as:
  - **dc**: Domain Controller
  - **ws**: Workstation
- **Number of the Computer:** A sequential number indicating the specific machine within its role (e.g., `1`, `2`, `3`).

#### Examples:
- `adc1`: First Domain Controller in "domain-a.local" domain.
- `xws1`: First Workstation in "domain-x.local" domain.

#### Special hosts:
- `ydc1` and `zdc1`: domain controllers used to execute enumeration scans for comparing existing tools.
- `xdc1`: domain controller that contains a set of data for replication to other domains.
- `xws1`: Linux client used to execute the enumeration scan with tools available only on Linux.
- `xws2`: A development machine for programming and testing SAMRClient.
- `xws3`: A client to execute SAMR enumeration with SAMRCLient tool.
- `yws1`: workstation from which the enumeration scan is executed to compare existing tools.

### Network Setup

The following table outlines the IP addressing scheme used for the lab environment. Each forest is assigned its own dedicated /24 subnet, with a domain controller (DC) and workstation (WS) residing in each subnet.

| **Role**              | **Hostname**      | **Domain**                                  | **VLAN ID** | **IP Address/Subnet** | **Gateway (Routing Server)** |
|-----------------------|-------------------|---------------------------------------------|-------------|-----------------------|------------------------------|
| **Routing Server**    | router            | <div align="right">N/A</div>                | 10          | 192.168.1.1/24         | N/A                          |
|                       |                   |                                             | 20          | 192.168.2.1/24         | N/A                          |
|                       |                   |                                             | 30          | 192.168.3.1/24         | N/A                          |
|                       |                   |                                             | 40          | 192.168.4.1/24         | N/A                          |
|                       |                   |                                             | 50          | 192.168.5.1/24         | N/A                          |
|                       |                   |                                             | 100         | 192.168.10.1/24        | N/A                          |
|                       |                   |                                             | 110         | 192.168.11.1/24        | N/A                          |
|                       |                   |                                             | 120         | 192.168.12.1/24        | N/A                          |
| **Domain Controller** | adc1              | <div align="right">domain-a.local</div>    | 10          | 192.168.1.11/24        | 192.168.1.1                  |
| **Domain Controller** | bdc1              | <div align="right">domain-b.local</div>    | 20          | 192.168.2.11/24        | 192.168.2.1                  |
| **Domain Controller** | bdc2              | <div align="right">b1.domain-b.local</div> | 20          | 192.168.2.12/24        | 192.168.2.1                  |
| **Domain Controller** | cdc1              | <div align="right">domain-c.local</div>    | 30          | 192.168.3.11/24        | 192.168.3.1                  |
| **Domain Controller** | cdc2              | <div align="right">c1.domain-c.local</div> | 30          | 192.168.3.12/24        | 192.168.3.1                  |
| **Domain Controller** | ddc1              | <div align="right">domain-d.local</div>    | 40          | 192.168.4.11/24        | 192.168.4.1                  |
| **Domain Controller** | ddc2              | <div align="right">d1.domain-d.local</div> | 40          | 192.168.4.12/24        | 192.168.4.1                  |
| **Domain Controller** | edc1              | <div align="right">domain-e.local</div>    | 50          | 192.168.5.11/24        | 192.168.5.1                  |
| **Domain Controller** | edc2              | <div align="right">e1.domain-e.local</div> | 50          | 192.168.5.12/24        | 192.168.5.1                  |
| **Domain Controller** | xdc1              | <div align="right">domain-x.local</div>    | 100         | 192.168.10.11/24       | 192.168.10.1                 |
| **Workstation**       | xws1              | <div align="right">N/A</div>               | 100         | 192.168.10.101/24      | 192.168.10.1                 |
| **Workstation**       | xws2              | <div align="right">N/A</div>               | 100         | 192.168.10.102/24      | 192.168.10.1                 |
| **Workstation**       | xws3              | <div align="right">N/A</div>               | 100         | 192.168.10.103/24      | 192.168.10.1                 |
| **Domain Controller** | ydc1              | <div align="right">domain-y.local</div>    | 110         | 192.168.11.11/24       | 192.168.11.1                 |
| **Workstation**       | yws1              | <div align="right">domain-y.local</div>    | 110         | 192.168.11.101/24      | 192.168.11.1                 |
| **Domain Controller** | zdc1              | <div align="right">domain-z.local</div>    | 120         | 192.168.12.11/24       | 192.168.12.1                 |

The entire network is configured to be **isolated** from the host machine to ensure a controlled and contained environment. No traffic can enter or exit the lab network from the host server, preventing external interference and ensuring accurate testing conditions.

Additionally, **no traffic filtering** is applied within the lab. This means that:

- **No intermediate firewalls** are placed between subnets.
- **No host-based firewalls** are enabled on the domain controllers or workstations.

This unfiltered setup allows for unrestricted communication between all systems in the lab, which is essential for testing enumeration techniques and observing network traffic without interference from security controls. The isolated and unfiltered network ensures that the focus remains on the behavior of the enumeration techniques and attack vectors within the controlled lab environment.


### Traffic Capture and Analysis

In this lab environment, traffic analysis is essential for monitoring and understanding SAMR enumeration activities across different domains and trust boundaries. The **`router`** system, which manages traffic flow between all subnets, is configured to capture and log data for inspection. The following setup and tools ensure visibility and facilitate packet analysis:

1. **Router Configuration for Traffic Visibility**:
   - The **router** system, responsible for routing traffic between the isolated subnets, provides a single point of visibility for all inter-subnet communications. This centralized routing design allows all data exchanged between different domains to be captured without needing individual monitoring on each system.
   - Since this is a lab setup, there are no firewall rules or security policies configured on the router, allowing unrestricted traffic flow for accurate traffic analysis. This setup is essential for observing SAMR enumeration and related cross-domain interactions without interference from security controls.

2. **Domain Cotrollers in Tools Comparison Analysis**  
Another instance of Wireshark was installed on the `ydc1` and `zdc1` domain controllers. Installation on both is required because some tools do not support cross-forest requests, making it necessary to capture traffic on the local domain controller ydc1.

3. **Traffic Capture with Wireshark**:
   - **Wireshark v4.2.0** is installed on the router system to capture network packets. Wireshark is configured to capture traffic on all interfaces associated with the Hyper-V virtual networks, covering each VLAN and subnet.
   - **Capture Filters**: Custom capture filters focus on specific protocols (e.g., SAMR, SMB) or IP ranges, allowing targeted analysis of SAMR enumeration behavior. This minimizes unnecessary data and focuses on packets relevant to cross-forest trust and enumeration.
   - **Protocol Analysis**: Wireshark enables inspection of protocols such as SAMR, SMB, and RPC, helping to understand how enumeration requests traverse trust boundaries and which types of requests reveal the most information across different trust configurations.

4. **Data Logging and Exporting**:
   - Traffic logs are saved to disk for post-analysis. The logs are exported in **PCAP** format, allowing for later review and analysis. This is useful for studying historical traffic and analyzing SAMR requests without real-time constraints.
   - **Segmentation by Subnet**: Captures are separated by subnet to isolate traffic specific to each domain. This segmentation helps compare enumeration results across forests and assess differences in traffic patterns when trust configurations change.

5. **Analysis of Enumeration Techniques**:
   - The captured traffic allows analysis of how SAMR requests and responses vary depending on trust direction (e.g., one-way vs. two-way), authentication scope (e.g., selective vs. forest-wide), and transitivity (e.g., transitive vs. non-transitive trusts).
   - **Identification of Exposed Data**: By inspecting SAMR response packets, it’s possible to identify which types of Active Directory objects (users, groups, computers) and attributes are exposed across different trust relationships. This analysis highlights potential security risks tied to specific trust configurations and reveals how much data is exposed to external domains.

This unfiltered, isolated, and documented setup ensures that traffic capture provides a picture of SAMR enumeration behavior within the lab environment. The focus remains on observing and understanding the interaction between trusted domains and the potential security risks associated with enumeration techniques.
