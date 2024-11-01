# SAMR-Enum-Lab

# Investigating SAMR Enumeration Attacks in Active Directory Multi-Forest Environments

## What the project does
This project investigates SAMR enumeration attacks in multi-forest Active Directory environments. It develops a Python tool to explore the full capabilities of the SAMR protocol and analyzes how different forest trust configurations impact the amount of accessible data, which could be exploited by attackers.

The laboratory setup aims to provide insights into:

- The extent of data leakage via SAMR enumeration in different trust configurations.
- How forest trust types influence enumeration attack surfaces.
- Strategies for mitigating SAMR-based attacks in multi-forest environments.

## Why the project is useful
The SAMR protocol allows attackers to gather critical information about users, groups, and domain structures, even from non-privileged accounts. This research develops a tool that simulates these attacks in various Active Directory trust configurations, providing insights into how attackers could exploit trust relationships during lateral movement. The findings will guide organizations in optimizing their security configurations, improving risk management, and developing countermeasures and detection tools.

## How users can get started with the project
Users can start by setting up a controlled lab environment using Hyper-V, following the configuration guidelines in the project documentation in Lab Setup. The SAMR enumeration tool can be used to simulate attacks and analyze vulnerabilities in different trust setups.

## References
- [Lab Setup](Lab_Setup.md): Detailed instructions for setting up a virtual lab environment on Hyper-V, designed for SAMR enumeration testing across multiple Active Directory forests. This setup includes six forest trusts with various configurations to analyze SAMR’s enumeration capabilities under different trust relationships and authentication scopes.

- [SAMR Tools Comparison](SAMR_Tools_Comparison.md): A comparative analysis of existing tools used for SAMR enumeration, focusing on factors like OpNum coverage, multi-forest support, permissions compliance, and error handling. This document evaluates tools such as Impacket, CrackMapExec, and rpcclient, identifying limitations and gaps that led to the development of a new enumeration tool.
