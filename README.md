# SAMR Enumeration in Multi-Forest Active Directory Environments

## Overview

This project explores the enumeration capabilities of the **Security Account Manager Remote (SAMR)** protocol in **Active Directory (AD)** environments, with a focus on multi-forest configurations. The research evaluates SAMR's ability to extract information such as user accounts, groups, domain structures, and access permissions, highlighting its security implications in trust-based AD setups.

The project includes:
- Comparative analysis of existing tools for SAMR enumeration.
- A custom tool designed to leverage select SAMR operation numbers (OpNums) for detailed enumeration.
- Experimental results on how trust configurations affect data accessibility.

## Key Features

- **Custom SAMR Enumeration Tool**: A Python-based tool utilizing a subset of SAMR OpNums to perform targeted enumeration in multi-forest AD setups.
- **Comparative Study**: Evaluates tools such as `Impacket`, `CrackMapExec`, `rpcclient`, `Metasploit`, and `SharpHound` based on their OpNum coverage, authentication support, and performance in multi-forest scenarios.
- **Laboratory Setup**: Simulated AD environment with diverse trust configurations, authentication scopes, and functional levels.

## Research Highlights

- **Impact of Trust Configurations**: Analyzes how one-way, two-way, and selective authentication scopes influence SAMR enumeration results.
- **Tool Limitations**: Identifies gaps in existing tools, including restricted OpNum support and dependency on excessive permissions.
- **Security Insights**: Provides recommendations to mitigate risks associated with SAMR enumeration in multi-forest setups.

## Repository Structure

- **`src/`**: Contains the custom SAMR enumeration tool.
- **`tests/`**: Automated tests for various SAMR operations.
- **`docs/`**:
  - [`Lab_Setup.md`](Lab_Setup.md): Details the AD lab configuration and experimental setup.
  - [`Resources.md`](Resources.md): References and supplementary reading.
  - [`Tools_Comparison.md`](Tools_Comparison.md): Comparative evaluation of SAMR enumeration tools.

## Requirements

- **Python 3.8+**
- **Dependencies**: Listed in `requirements.txt` (e.g., `impacket`, `pycrypto`).
- **Environment**: Windows or Linux systems with access to a configured Active Directory lab.

## Usage

1. Clone the repository:
   ```bash
   git clone https://github.com/your-repo-url.git
   cd samr-enumeration
