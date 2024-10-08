# SAMR-Enum-Lab

# Investigating SAMR Enumeration Attacks in Active Directory Multi-Forest Environments

## What the project does
This project investigates SAMR enumeration attacks in multi-forest Active Directory environments. It develops a Python tool to explore the full capabilities of the SAMR protocol and analyzes how different forest trust configurations impact the amount of accessible data, which could be exploited by attackers.

## Why the project is useful
The SAMR protocol allows attackers to gather critical information about users, groups, and domain structures, even from non-privileged accounts. This research develops a tool that simulates these attacks in various Active Directory trust configurations, providing insights into how attackers could exploit trust relationships during lateral movement. The findings will guide organizations in optimizing their security configurations, improving risk management, and developing countermeasures and detection tools.

## How users can get started with the project
Users can start by setting up a controlled lab environment using Hyper-V, following the configuration guidelines in the project documentation (to be added later). The SAMR enumeration tool can be used to simulate attacks and analyze vulnerabilities in different trust setups.

### Example of Tool Usage
The following is an example of how to run the SAMR enumeration tool:

```bash
python samr-enum.py --domain-controller <domain_controller_ip> --username <username> --password <password> --output <output_file>
