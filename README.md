# SAMR Enumeration in Multi-Forest Active Directory Environments

**Version 1.0 (Draft)**

## Overview

This project explores the enumeration capabilities of the **Security Account Manager Remote (SAMR)** protocol in **Active Directory (AD)** environments, with a focus on multi-forest configurations. The research evaluates SAMR’s ability to extract information, such as user accounts, groups, domain structures, and access permissions, and highlights its security implications in a trust-based AD setup. The project includes:
- A comparative analysis of existing tools for SAMR enumeration.
- A custom Python-based tool designed to leverage selected SAMR operation numbers (OpNums) for detailed enumeration.
- Experimental results on how trust configurations affect data accessibility.


## Key Features

- **Comparative Study**: Evaluates tools such as `Impacket`, `CrackMapExec`, `rpcclient`, `Metasploit`, and `SharpHound` in terms of their OpNum coverage, authentication support, and performance.
- **Custom SAMR Enumeration Tool**: Utilizes a subset of SAMR OpNums to perform targeted enumeration in multi-forest AD setups.
- **Laboratory Setup**: Tested in a simulated AD environment with diverse trust configurations, authentication scopes, and functional levels.

## Research Highlights

- **Impact of Trust Configurations**: Analyzes how one-way, two-way, and selectively authenticated trusts influence SAMR enumeration results.
- **Tool Limitations**: Identifies gaps in existing tools, including restricted OpNum support and dependency on excessive permissions.
- **Security Insights**: Provides recommendations to mitigate risks associated with SAMR enumeration in multi-forest setups.

## Tool Requirements

- **Python**: 3.12.8
- **Dependencies**:
  - `Impacket` 0.12 (MIT License)  
    *Note: Microsoft Defender and CrowdStrike AV might block or flag Impacket components.*
- **Platform**: Windows or Linux systems with access to a configured Active Directory.

## Installation & Usage

1. **Clone the Repository**
```bash
git clone https://github.com/studylab1/SAMR-Enum-Lab.git
cd SAMR-Enum-Lab
```

2. **Install Dependencies**
```bash
pip install impacket==0.12
```

3. **Run the Tool**
   
   The tool contains a single Python file (samr-enum.py). Execute the tool from the command line:
```bash
python samr-enum.py [options]
 ```
   
   For detailed options:
```bash
python samr-enum.py --help
```

## Configuration & Troubleshooting
- Ensure your Python environment meets the specified version and dependency requirements.
- If you experience issues with antivirus software (e.g., Microsoft Defender, CrowdStrike, or other AV solutions), consider adjusting your AV settings, as Impacket components may be flagged.

## Contributing

Contributions are welcome! Please adhere to PEP 8 styling and include appropriate PEP 257 docstrings in your code. Fork the repository, implement your changes, and submit a pull request.

## License

- This project is licensed under the MIT License. See the LICENSE file for details.
- Impacket is licensed under the Apache License 2.0. See the NOTICE file for more details.

## Acknowledgements

Thanks to the developers of Impacket for their invaluable library.
