This page offers downloadable resources, including traffic capture files, scripts, command outputs, and other materials generated and utilized during the research

| Tool Name       | Link                                                                                                     | Size  | Type  | Command Executed                                | Comments |
|-----------------|---------------------------------------------------------------------------------------------------------|-------|-------|------------------------------------------------|----------|
| `Net`        | [Download](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Capture_Files/net_user_administrator__domain.pcapng) | 47 KB     | Traffic Capture      | `net.exe user administrator /domain`  | Request to local domain |
| `Net`        |  | 26 KB    | Command Output      | `net.exe user administrator /domain`  | Request to local domain |
| `Net`        | [Download](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Capture_Files/net_user__domain.pcapng) | 56  KB    | Traffic Capture       | `net.exe user /domain` | Request to local domain         |
| `Net`        |  | 3 KB    | Command Output      | `net.exe user /domain`  | Request to local domain |
| `Net`       | [Download](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Capture_Files/net_group__domain.pcapng)                           | 47 KB      | Traffic Capture       | `net.exe group /domain`  |  Request to local domain        |
| `Net`       |   | 6 KB      | Command Output   | `net.exe group /domain`  |  Request to local domain        |
| `Net`       | [Download](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Capture_Files/net_group_domain_admins__domain.pcapng)                       | 24 KB      | Traffic Capture       | `net.exe group "domain admins" /domain'`  |  Request to local domain     
| `Net`       |   | 1 KB      | Command Output       | `net.exe group "domain admins" /domain'`  |  Request to local domain     
| `PowerShell` **ADD LINK TO SCRIPT**  |        | 6.8 MB      | Traffic Capture | `powershell_ad.ps1` |  Executed **ADD LINK** script with 42 ActiveDirectory cmdlets  |
| `PowerShell` |        | 6.4 KB      | Script | `powershell_ad.ps1` |  The script contains 42 ActiveDirectory cmdlets which are related to enumeration  |
| `Impacket samrdump.py` |        | 119 KB      | Traffic Capture | `python.exe samrdump.py domain-y/enum:LabAdm1!@zdc1.domain-z.local` |    |

