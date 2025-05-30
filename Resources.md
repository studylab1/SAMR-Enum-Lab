# Resources

This page serves as a central repository for downloadable resources, detailed descriptions, and supporting scripts to aid in SAMR enumeration and analysis efforts. It includes traffic capture files, tool outputs, enumeration scripts, and comprehensive explanations of SAMR operation numbers (OpNums). These resources are intended to complement the information presented on other pages and to facilitate deeper understanding and hands-on exploration.

## Table of Contents
1. [Traffic Captures, Tools Output and Scripts](#traffic-captures-tools-output-and-scripts)
2. [SAMR Operation Numbers Details](#samr-operation-numbers-details)
3. [PowerShell AD Module Cmdlets Details](#powershell-ad-module-cmdlets-details)


## Traffic Captures, Tools Output and Scripts

This page offers downloadable resources, including traffic capture files, scripts, command outputs, and other materials generated and utilized during the research. The traffic capture of communication with xdc1.domain-x.local is not included in the table due to the large size of the files

| Tool Name      | Size   | Type            | Command Executed                          | Comments                          | Link |
|----------------|--------|-----------------|-------------------------------------------|-----------------------------------|------|
| `Net.exe User` | 58 KB  | Traffic Capture | `net.exe user /domain`                    | Request to local domain           | [Download](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/net.exe_user__domain.pcapng) |
| `Net.exe User` | 26 KB  | Command Output  | `net.exe user /domain`                    | Request to local domain           | [Open](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/net.exe_user__domain__output.txt) |
| `Net.exe User` | 49 KB  | Traffic Capture | `net.exe user administrator /domain`      | Request to local domain           | [Download](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/net.exe_user_administrator__domain.pcapng) |
| `Net.exe User` | 3 KB   | Command Output  | `net.exe user administrator /domain`      | Request to local domain           | [Open](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/net.exe_user_administrator__domain__output.txt) |
| `Net.exe Group`| 48 KB  | Traffic Capture | `net.exe group /domain`                   | Request to local domain           | [Download](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/net.exe_group__domain.pcapng) |
| `Net.exe Group`| 5 KB   | Command Output  | `net.exe group /domain`                   | Request to local domain           | [Open](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/net.exe_group__domain__output.txt) |
| `Net.exe Group`| 25 KB  | Traffic Capture | `net.exe group "domain admins" /domain`   | Request to local domain           | [Download](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/net.exe_group__domain_admins__domain.pcapng) |
| `Net.exe Group`| 914 B  | Command Output  | `net.exe group "domain admins" /domain`   | Request to local domain           | [Open](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/net.exe_group__domain_admins_domain__output.txt) |
| `PowerShell`   | 847 KB | Traffic Capture | `powershell_ad.ps1`                       | Executed script with 42 ActiveDirectory cmdlets | [Download](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/powershell.exe_ad.pcapng) |
| `PowerShell`   | 346 KB | Command Output  | `powershell_ad.ps1`                       | Executed script with 42 ActiveDirectory cmdlets | [Open](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/powershell.exe_ad__output.txt) |
| `PowerShell`   | 7 KB   | Script          | `powershell_ad.ps1`                       | The script contains 42 ActiveDirectory cmdlets which are related to enumeration | [Open](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/powershell.exe_ad.ps1) |
| `Impacket samrdump.py`| 49 KB | Traffic Capture | `python.exe samrdump.py domain-y/enum:LabAdm1!@zdc1.domain-z.local` |  | [Download](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/python.exe_impacket_samrdump.py.pcapng) |
| `Impacket samrdump.py`| 11 KB | Command Output  | `python.exe samrdump.py domain-y/enum:LabAdm1!@zdc1.domain-z.local` |  | [Open](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/python.exe_impacket_samrdump.py__output.txt) |
| `Impacket net.py`| 16 KB| Traffic Capture | `python.exe net.py domain-y/enum:LabAdm1!@zdc1.domain-z.local user` |  | [Download](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/python.exe_impacket_net.py_user.pcapng) |
| `Impacket net.py`| 248 B| Command Output  | `python.exe net.py domain-y/enum:LabAdm1!@zdc1.domain-z.local user` |  | [Open](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/python.exe_impacket_net.py_user__output.txt) |
| `Impacket net.py`| 44 KB| Traffic Capture | `python.exe net.py domain-y/enum:LabAdm1!@zdc1.domain-z.local user -name Administrator` |  | [Download](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/python.exe_impacket_net.py_user_admin.pcapng) |
| `Impacket net.py`| 1 KB | Command Output  | `python.exe net.py domain-y/enum:LabAdm1!@zdc1.domain-z.local user -name Administrator` |  | [Open](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/python.exe_impacket_net.py_user_admin__output.txt) |
| `Impacket net.py`| 17 KB| Traffic Capture | `python.exe net.py domain-y/enum:LabAdm1!@zdc1.domain-z.local group` |  | [Download](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/python.exe_impacket_net.py_group.pcapng) |
| `Impacket net.py`| 785 B| Command Output  | `python.exe net.py domain-y/enum:LabAdm1!@zdc1.domain-z.local group` |  | [Open](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/python.exe_impacket_net.py_group__output.txt) |
| `Impacket net.py`| 19 KB| Traffic Capture | `python.exe net.py domain-y/enum:LabAdm1!@zdc1.domain-z.local group -name "Domain Admins"` |  | [Download](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/python.exe_impacket_net.py_group_admins.pcapng) |
| `Impacket net.py`| 111 B| Command Output  | `python.exe net.py domain-y/enum:LabAdm1!@zdc1.domain-z.local group -name "Domain Admins"` |  | [Open](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/python.exe_impacket_net.py_group_admins__output.txt) |
| `Impacket net.py`| 17 KB| Traffic Capture | `python.exe net.py domain-y/enum:LabAdm1!@zdc1.domain-z.local localgroup` |  | [Download](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/python.exe_impacket_net.py_localgroup.pcapng) |
| `Impacket net.py`| 924 B| Command Output  | `python.exe net.py domain-y/enum:LabAdm1!@zdc1.domain-z.local localgroup` |  | [Open](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/python.exe_impacket_net.py_localgroup__output.txt) |
| `Impacket net.py`| 23 KB| Traffic Capture | `python.exe net.py domain-y/enum:LabAdm1!@zdc1.domain-z.local localgroup -name Administrators` |  | [Download](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/python.exe_impacket_net.py_localgroup_admins.pcapng) |
| `Impacket net.py`| 136 B| Command Output  | `python.exe net.py domain-y/enum:LabAdm1!@zdc1.domain-z.local localgroup -name Administrators` |  | [Open](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/python.exe_impacket_net.py_localgroup_admins__output.txt) |
| `Impacket net.py`| 16 KB| Traffic Capture | `python.exe net.py domain-y/enum:LabAdm1!@zdc1.domain-z.local computer` |  | [Download](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/python.exe_impacket_net.py_computer.pcapng) |
| `Impacket net.py`| 193 B| Command Output  | `python.exe net.py domain-y/enum:LabAdm1!@zdc1.domain-z.local computer` |  | [Open](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/python.exe_impacket_net.py_computer__output.txt) |
| `CrackMapExec`   | 72 KB| Traffic Capture | `crackmapexec smb zdc1.domain-z.local -d domain-y.local -u enum -p "LabAdm1!" --users` |  | [Download](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/python.exe_crackmapexec_users.pcapng) |
| `CrackMapExec`   | 2 KB | Command Output  | `crackmapexec smb zdc1.domain-z.local -d domain-y.local -u enum -p "LabAdm1!" --users` |  | [Open](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/python.exe_crackmapexec_users__output.txt) |
| `CrackMapExec`   | 24 KB| Traffic Capture | `crackmapexec smb zdc1.domain-z.local -d domain-y.local -u enum -p "LabAdm1!" --groups` | No SAMR data due to error "unsupported hash type MD4" | [Download](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/python.exe_crackmapexec_groups.pcapng) |
| `CrackMapExec`   | 922 B| Command Output  | `crackmapexec smb zdc1.domain-z.local -d domain-y.local -u enum -p "LabAdm1!" --groups` | No SAMR data due to error "unsupported hash type MD4" | [Open](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/python.exe_crackmapexec_groups__output.txt) |
| `CrackMapExec`   | 57 KB| Traffic Capture | `crackmapexec smb zdc1.domain-z.local -d domain-y.local -u enum -p "LabAdm1!" --local-groups` |  | [Download](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/python.exe_crackmapexec_local-groups.pcapng) |
| `CrackMapExec`   | 4 KB | Command Output  | `crackmapexec smb zdc1.domain-z.local -d domain-y.local -u enum -p "LabAdm1!" --local-groups` |  | [Open](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/python.exe_crackmapexec_local-groups__output.txt) |
| `CrackMapExec`   | 17 KB| Traffic Capture | `crackmapexec smb zdc1.domain-z.local -d domain-y.local -u enum -p "LabAdm1!" --computers` | No SAMR data | [Download](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/python.exe_crackmapexec_computers.pcapng) |
| `CrackMapExec`   | 235 B| Command Output  | `crackmapexec smb zdc1.domain-z.local -d domain-y.local -u enum -p "LabAdm1!" --computers` | No SAMR data | [Open](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/python.exe_crackmapexec_computers__output.txt) |
| `CrackMapExec`   | 35 KB| Traffic Capture | `crackmapexec smb zdc1.domain-z.local -d domain-y.local -u enum -p "LabAdm1!" --pass-pol` | Password policies | [Download](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/python.exe_crackmapexec_pass-pol.pcapng) |
| `CrackMapExec`   | 2 KB | Command Output  | `crackmapexec smb zdc1.domain-z.local -d domain-y.local -u enum -p "LabAdm1!" --pass-pol` | Password policies | [Open](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/python.exe_crackmapexec_pass-pol__output.txt) |
| `CrackMapExec`   | 17 KB| Traffic Capture | `crackmapexec smb zdc1.domain-z.local -d domain-y.local -u enum -p "LabAdm1!" --lsa` | No SAMR data | [Download](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/python.exe_crackmapexec_lsa.pcapng) |
| `CrackMapExec`   | 236 B| Command Output  | `crackmapexec smb zdc1.domain-z.local -d domain-y.local -u enum -p "LabAdm1!" --lsa` | No SAMR data | [Open](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/python.exe_crackmapexec_lsa__output.txt) |
| `rpcclient`      | 16 KB| Traffic Capture | `rpcclient -U "domain-y.local\\enum%LabAdm1!" 192.168.12.11 -c "enumdomusers"` |  | [Download](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/rpcclient_enumdomusers.pcapng) |
| `rpcclient`      | 256 B| Command Output  | `rpcclient -U "domain-y.local\\enum%LabAdm1!" 192.168.12.11 -c "enumdomusers"` |  | [Open](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/rpcclient_enumdomusers__output.txt) |
| `rpcclient`      | 16 KB| Traffic Capture | `rpcclient -U "domain-y.local\\enum%LabAdm1!" 192.168.12.11 -c "enumdomgroups"` |  | [Download](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/rpcclient_enumdomgroups.pcapng) |
| `rpcclient`      | 998 B| Command Output  | `rpcclient -U "domain-y.local\\enum%LabAdm1!" 192.168.12.11 -c "enumdomgroups"` |  | [Open](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/rpcclient_enumdomgroups__output.txt) |
| `rpcclient`      | 12 KB| Traffic Capture | `rpcclient -U "domain-y.local\\enum%LabAdm1!" 192.168.12.11 -c "enumdomgroups domain"` |  | [Download](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/rpcclient_enumdomgroups_domain.pcapng) |
| `rpcclient`      | 35  B| Command Output  | `rpcclient -U "domain-y.local\\enum%LabAdm1!" 192.168.12.11 -c "enumdomgroups domain"` |  | [Open](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/rpcclient_enumdomgroups_domain__output.txt) |
| `rpcclient`      | 13 KB| Traffic Capture | `rpcclient -U "domain-y.local\\enum%LabAdm1!" 192.168.12.11 -c "enumdomgroups builtin"` |  | [Download](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/rpcclient_enumdomgroups_builtin.pcapng) |
| `rpcclient`      | 35 B | Command Output  | `rpcclient -U "domain-y.local\\enum%LabAdm1!" 192.168.12.11 -c "enumdomgroups builtin"` |  | [Open](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/rpcclient_enumdomgroups_builtin__output.txt) |
| `rpcclient`      | 14 KB| Traffic Capture | `rpcclient -U "domain-y.local\\enum%LabAdm1!" 192.168.12.11 -c "enumalsgroups domain"` |  | [Download](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/rpcclient_enumalsgroups_domain.pcapng) |
| `rpcclient`      | 271 B| Command Output  | `rpcclient -U "domain-y.local\\enum%LabAdm1!" 192.168.12.11 -c "enumalsgroups domain"` |  | [Open](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/rpcclient_enumalsgroups_domain__output.txt) |
| `rpcclient`      | 15 KB| Traffic Capture | `rpcclient -U "domain-y.local\\enum%LabAdm1!" 192.168.12.11 -c "enumalsgroups builtin"` |  | [Download](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/rpcclient_enumalsgroups_builtin.pcapng) |
| `rpcclient`      | 1 KB | Command Output  | `rpcclient -U "domain-y.local\\enum%LabAdm1!" 192.168.12.11 -c "enumalsgroups builtin"` |  | [Open](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/rpcclient_enumalsgroups_builtin__output.txt) |
| `rpcclient`      | 15 KB| Traffic Capture | `rpcclient -U "domain-y.local\\enum%LabAdm1!" 192.168.12.11 -c "queryaliasmem domain 4194"` |  | [Download](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/rpcclient_queryaliasmem_domain.pcapng) |
| `rpcclient`      | 54 B | Command Output  | `rpcclient -U "domain-y.local\\enum%LabAdm1!" 192.168.12.11 -c "queryaliasmem domain 4194"` |  | [Open](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/rpcclient_queryaliasmem_domain__output.txt) |
| `rpcclient`      | 15 KB| Traffic Capture | `rpcclient -U "domain-y.local\\enum%LabAdm1!" 192.168.12.11 -c "queryaliasmem builtin 544"` |  | [Download](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/rpcclient_queryaliasmem_builtin.pcapng) |
| `rpcclient`      | 160 B| Command Output  | `rpcclient -U "domain-y.local\\enum%LabAdm1!" 192.168.12.11 -c "queryaliasmem builtin 544"` |  | [Open](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/rpcclient_queryaliasmem_builtin__output.txt) |
| `rpcclient`      | 16 KB| Traffic Capture | `rpcclient -U "domain-y.local\\enum%LabAdm1!" 192.168.12.11 -c "queryuser 500"` | Administrator | [Download](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/rpcclient_queryuser.pcapng) |
| `rpcclient`      | 796 B| Command Output  | `rpcclient -U "domain-y.local\\enum%LabAdm1!" 192.168.12.11 -c "queryuser 500"` | Administrator | [Open](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/rpcclient_queryuser__output.txt) |
| `rpcclient`      | 3 KB | Command Output  | `rpcclient -U "domain-y.local\\enum%LabAdm1!" 192.168.12.11 -c "queryuser 0x106a"` |  | [Open](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/rpcclient_queryuser_0x106a__output.txt) |
| `rpcclient`      | 794 B| Command Output  | `rpcclient -U "domain-y.local\\enum%LabAdm1!" 192.168.12.11 -c "queryuser 0x106b"` |  | [Open](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/rpcclient_queryuser_0x106b__output.txt) |
| `rpcclient`      | 767 B| Command Output  | `rpcclient -U "domain-y.local\\enum%LabAdm1!" 192.168.12.11 -c "queryuser 0x106c"` |  | [Open](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/rpcclient_queryuser_0x106c__output.txt) |
| `rpcclient`      | 785 B| Command Output  | `rpcclient -U "domain-y.local\\enum%LabAdm1!" 192.168.12.11 -c "queryuser 0x106e"` |  | [Open](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/rpcclient_queryuser_0x106e__output.txt) |
| `rpcclient`      | 17 KB| Traffic Capture | `rpcclient -U "domain-y.local\\enum%LabAdm1!" 192.168.12.11 -c "querygroup 4212"` |  | [Download](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/rpcclient_querygroup.pcapng) |
| `rpcclient`      | 1 KB | Command Output  | `rpcclient -U "domain-y.local\\enum%LabAdm1!" 192.168.12.11 -c "querygroup 4212"` |  | [Open](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/rpcclient_querygroup__output.txt) |
| `rpcclient`      | 15 KB| Traffic Capture | `rpcclient -U "domain-y.local\\enum%LabAdm1!" 192.168.12.11 -c "queryusergroups 500"` | Administrator | [Download](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/rpcclient_queryusergroups.pcapng) |
| `rpcclient`      | 150 B| Command Output  | `rpcclient -U "domain-y.local\\enum%LabAdm1!" 192.168.12.11 -c "queryusergroups 500"` | Administrator | [Open](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/rpcclient_queryusergroups__output.txt) |
| `rpcclient`      | 14 KB| Traffic Capture | `rpcclient -U "domain-y.local\\enum%LabAdm1!" 192.168.12.11 -c "queryuseraliases builtin S-1-5-21-2189324197-3478012550-1180063049-500"` |  | [Download](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/rpcclient_queryuseraliases_builtin.pcapng) |
| `rpcclient`      | 19 B | Command Output  | `rpcclient -U "domain-y.local\\enum%LabAdm1!" 192.168.12.11 -c "queryuseraliases builtin S-1-5-21-2189324197-3478012550-1180063049-500"` |  | [Open](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/rpcclient_queryuseraliases_builtin__output.txt) |
| `rpcclient`      | 14 KB| Traffic Capture | `rpcclient -U "domain-y.local\\enum%LabAdm1!" 192.168.12.11 -c "queryuseraliases domain S-1-5-21-2189324197-3478012550-1180063049-4202"` |  | [Download](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/rpcclient_queryuseraliases_domain.pcapng) |
| `rpcclient`      | 21 B | Command Output  | `rpcclient -U "domain-y.local\\enum%LabAdm1!" 192.168.12.11 -c "queryuseraliases domain S-1-5-21-2189324197-3478012550-1180063049-4202"` |  | [Open](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/rpcclient_queryuseraliases_domain__output.txt) |
| `rpcclient`      | 15 KB| Traffic Capture | `rpcclient -U "domain-y.local\\enum%LabAdm1!" 192.168.12.11 -c "querygroupmem 512"` | Domain Admins | [Download](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/rpcclient_querygroupmem.pcapng) |
| `rpcclient`      | 25 B | Command Output  | `rpcclient -U "domain-y.local\\enum%LabAdm1!" 192.168.12.11 -c "querygroupmem 512"` | Domain Admins | [Open](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/rpcclient_querygroupmem__output.txt) |
| `rpcclient`      | 29 KB| Command Output  | `rpcclient -U "domain-y.local\\enum%LabAdm1!" 192.168.12.11 -c "queryaliasinfo builtin 544" -d 10` | An error occurred | [Open](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/rpcclient_queryaliasinfo_builtin__output.txt) |
| `rpcclient`      | 17 KB| Traffic Capture | `rpcclient -U "domain-y.local\\enum%LabAdm1!" 192.168.12.11 -c "querydispinfo"` |  | [Download](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/rpcclient_querydispinfo.pcapng) |
| `rpcclient`      | 2 KB | Command Output  | `rpcclient -U "domain-y.local\\enum%LabAdm1!" 192.168.12.11 -c "querydispinfo"` |  | [Open](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/rpcclient_querydispinfo__output.txt) |
| `rpcclient`      | 17 KB| Traffic Capture | `rpcclient -U "domain-y.local\\enum%LabAdm1!" 192.168.12.11 -c "querydispinfo2"` |  | [Download](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/rpcclient_querydispinfo2.pcapng) |
| `rpcclient`      | 2 KB | Command Output  | `rpcclient -U "domain-y.local\\enum%LabAdm1!" 192.168.12.11 -c "querydispinfo2"` |  | [Open](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/rpcclient_querydispinfo2__output.txt) |
| `rpcclient`      | 18 KB| Traffic Capture | `rpcclient -U "domain-y.local\\enum%LabAdm1!" 192.168.12.11 -c "querydispinfo3"` |  | [Download](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/rpcclient_querydispinfo3.pcapng) |
| `rpcclient`      | 2 KB | Command Output  | `rpcclient -U "domain-y.local\\enum%LabAdm1!" 192.168.12.11 -c "querydispinfo3"` |  | [Open](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/rpcclient_querydispinfo3__output.txt) |
| `rpcclient`      | 14 KB| Traffic Capture | `rpcclient -U "domain-y.local\\enum%LabAdm1!" 192.168.12.11 -c "querydominfo"` |  | [Download](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/rpcclient_querydominfo.pcapng) |
| `rpcclient`      | 189 B| Command Output  | `rpcclient -U "domain-y.local\\enum%LabAdm1!" 192.168.12.11 -c "querydominfo"` |  | [Open](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/rpcclient_querydominfo__output.txt) |
| `rpcclient`      | 9 KB | Traffic Capture | `rpcclient -U "domain-y.local\\enum%LabAdm1!" 192.168.12.11 -c "getdompwinfo"` |  | [Download](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/rpcclient_getdompwinfo.pcapng) |
| `rpcclient`      | 81 B | Command Output  | `rpcclient -U "domain-y.local\\enum%LabAdm1!" 192.168.12.11 -c "getdompwinfo"` |  | [Open](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/rpcclient_getdompwinfo__output.txt) |
| `rpcclient`      | 13 KB| Traffic Capture | `rpcclient -U "domain-y.local\\enum%LabAdm1!" 192.168.12.11 -c "samlookupnames domain Administrator"` |  | [Download](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/rpcclient_samlookupnames_domain.pcapng) |
| `rpcclient`      | 31 B | Command Output  | `rpcclient -U "domain-y.local\\enum%LabAdm1!" 192.168.12.11 -c "samlookupnames domain Administrator"` |  | [Open](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/rpcclient_samlookupnames_domain__output.txt) |
| `rpcclient`      | 14 KB| Traffic Capture | `rpcclient -U "domain-y.local\\enum%LabAdm1!" 192.168.12.11 -c "samlookupnames builtin Users"` |  | [Download](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/rpcclient_samlookupnames_builtin.pcapng) |
| `rpcclient`      | 23 B | Command Output  | `rpcclient -U "domain-y.local\\enum%LabAdm1!" 192.168.12.11 -c "samlookupnames builtin Users"` |  | [Open](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/rpcclient_samlookupnames_builtin__output.txt) |
| `rpcclient`      | 13 KB| Traffic Capture | `rpcclient -U "domain-y.local\\enum%LabAdm1!" 192.168.12.11 -c "samlookuprids domain 512"` | Domain Admins | [Download](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/rpcclient_samlookuprids_domain.pcapng) |
| `rpcclient`      | 30 B | Command Output  | `rpcclient -U "domain-y.local\\enum%LabAdm1!" 192.168.12.11 -c "samlookuprids domain 512"` | Domain Admins | [Open](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/rpcclient_samlookuprids_domain__output.txt) |
| `rpcclient`      | 13 KB| Traffic Capture | `rpcclient -U "domain-y.local\\enum%LabAdm1!" 192.168.12.11 -c "samlookuprids builtin 544"` | Administrators | [Download](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/rpcclient_samlookuprids_builtin.pcapng) |
| `rpcclient`      | 31 B | Command Output  | `rpcclient -U "domain-y.local\\enum%LabAdm1!" 192.168.12.11 -c "samlookuprids builtin 544"` | Administrators | [Open](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/rpcclient_samlookuprids_builtin__output.txt) |
| `rpcclient`      | 14 KB| Traffic Capture | `rpcclient -U "domain-y.local\\enum%LabAdm1!" 192.168.12.11 -c "samquerysecobj"` |  | [Download](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/rpcclient_samquerysecobj.pcapng) |
| `rpcclient`      | 423 B| Command Output  | `rpcclient -U "domain-y.local\\enum%LabAdm1!" 192.168.12.11 -c "samquerysecobj"` |  | [Open](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/rpcclient_samquerysecobj__output.txt) |
| `rpcclient`      | 13 KB| Traffic Capture | `rpcclient -U "domain-y.local\\enum%LabAdm1!" 192.168.12.11 -c "lookupdomain domain-z.local"` |  | [Download](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/rpcclient_lookupdomain.pcapng) |
| `rpcclient`      | 103 B| Command Output  | `rpcclient -U "domain-y.local\\enum%LabAdm1!" 192.168.12.11 -c "lookupdomain domain-z.local"` |  | [Open](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/rpcclient_lookupdomain__output.txt) |
| `rpcclient`      | 14 KB| Traffic Capture | `rpcclient -U "domain-y.local\\enum%LabAdm1!" 192.168.12.11 -c "getdispinfoidx Administrator 1"` |  | [Download](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/rpcclient_getdispinfoidx.pcapng) |
| `rpcclient`      | 24 B | Command Output  | `rpcclient -U "domain-y.local\\enum%LabAdm1!" 192.168.12.11 -c "getdispinfoidx Administrator 1"` |  | [Open](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/rpcclient_getdispinfoidx__output.txt) |
| `rpcclient`      | 12 KB| Traffic Capture | `rpcclient -U "domain-y.local\\enum%LabAdm1!" 192.168.12.11 -c "enumdomains"` |  | [Download](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/rpcclient_enumdomains.pcapng) |
| `rpcclient`      | 52 B | Command Output  | `rpcclient -U "domain-y.local\\enum%LabAdm1!" 192.168.12.11 -c "enumdomains"` |  | [Open](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/rpcclient_enumdomains__output.txt) |
| `rpcclient`      | 15 KB| Traffic Capture | `rpcclient -U "domain-y.local\\enum%LabAdm1!" 192.168.12.11 -c "getusrdompwinfo 500"` | Administrator | [Download](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/rpcclient_getusrdompwinfo.pcapng) |
| `rpcclient`      | 417 B| Command Output  | `rpcclient -U "domain-y.local\\enum%LabAdm1!" 192.168.12.11 -c "getusrdompwinfo 500"` | Administrator | [Open](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/rpcclient_getusrdompwinfo__output.txt) |
| `Metasploit`     | 26 KB| Traffic Capture | `auxiliary/scanner/smb/smb_enumusers` module |      | [Download](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/metasploit_smb_enumusers.pcapng) |
| `Metasploit`     | 2 KB | Command Output  | `auxiliary/scanner/smb/smb_enumusers` module |      | [Open](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/metasploit_smb_enumusers__output.txt) |
| `Metasploit`     | 16 KB| Traffic Capture | `auxiliary/admin/dcerpc/samr_account ` module | LOOKUP_ACCOUNT user  | [Download](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/metasploit_samr_account__user.pcapng) |
| `Metasploit`     | 3 KB | Command Output  | `auxiliary/admin/dcerpc/samr_account ` module | LOOKUP_ACCOUNT user  | [Open](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/metasploit_samr_account__user__output.txt) |
| `Metasploit`     | 16 KB| Traffic Capture | `auxiliary/admin/dcerpc/samr_account ` module | LOOKUP_ACCOUNT computer  | [Download](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/metasploit_samr_account__computer.pcapng) |
| `Metasploit`     | 3 KB | Command Output  | `auxiliary/admin/dcerpc/samr_account ` module | LOOKUP_ACCOUNT computer  | [Open](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/metasploit_samr_account__computer__output.txt) |
| `SharpHound`     | 2 MB | Traffic Capture  | `SharpHound.exe -c All  --domaincontroller zdc1.domain-z.local` | | [Download](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/sharphound_domain_z.pcapng) |
| `SharpHound`     | 4 KB | Command Output   | `SharpHound.exe -c All  --domaincontroller zdc1.domain-z.local` | | [Open](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/sharphound_domain_z__output.txt) |
| `SharpHound`     | 23 KB | Command Export   | `SharpHound.exe -c All  --domaincontroller zdc1.domain-z.local` | Computers (JSON) | [Open](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/sharphound_domain-z__computers_export.json) |
| `SharpHound`     | 334 KB | Command Export   | `SharpHound.exe -c All  --domaincontroller zdc1.domain-z.local` | Containers (JSON)| [Open](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/sharphound_domain-z__containers_export.json) |
| `SharpHound`     | 5 KB | Command Export   | `SharpHound.exe -c All  --domaincontroller zdc1.domain-z.local` | Domains (JSON)| [Open](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/sharphound_domain-z__domains_export.json) |
| `SharpHound`     | 4 KB | Command Export   | `SharpHound.exe -c All  --domaincontroller zdc1.domain-z.local` | GPOs (JSON) | [Open](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/sharphound_domain-z__gpos_export.json) |
| `SharpHound`     | 196 KB | Command Export   | `SharpHound.exe -c All  --domaincontroller zdc1.domain-z.local` | Groups (JSON) | [Open](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/sharphound_domain-z__groups_export.json) |
| `SharpHound`     | 7 KB | Command Export   | `SharpHound.exe -c All  --domaincontroller zdc1.domain-z.local` | OUs (JSON)| [Open](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/sharphound_domain-z__ous_export.json) |
| `SharpHound`     | 36 KB | Command Export   | `SharpHound.exe -c All  --domaincontroller zdc1.domain-z.local` | Users (JSON)| [Open](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/sharphound_domain-z__users_export.json) |
| `SharpHound`     | 10 MB | Command Export  | `SharpHound.exe -c All  --domaincontroller xdc1.domain-x.local` | Archive | [Download](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/sharphound_domain-x__export.zip) |
| `nmap`           | 8 KB | Traffic Capture | `nmap -p 445 --script smb-enum* 192.168.10.11 -d` | An error occurred | [Download](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/nmap.pcapng) |
| `nmap`           | 6 KB | Command Output  | `nmap -p 445 --script smb-enum* 192.168.10.11 -d` | An error occurred | [Open](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/nmap__output.txt) |
| `samr-enum`      | 50 KB | Traffic Capture | `python samr-enum.py target=ydc1.domain-y.local username=enum-x password=LabAdm1! opnums=true enumerate=users` |  | [Download](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/samr-enum.py_users.pcapng) |
| `samr-enum`      | 15 KB | Command Output  | `python samr-enum.py target=ydc1.domain-y.local username=enum-x password=LabAdm1! opnums=true enumerate=users` |  | [Open](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/samr-enum.py_users.txt) |
| `samr-enum`      | 20 KB | Traffic Capture | `python samr-enum.py target=ydc1.domain-y.local username=enum-x password=LabAdm1! opnums=true enumerate=computers` |  | [Download](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/samr-enum.py_computers.pcapng) |
| `samr-enum`      | 1 KB  | Command Output  | `python samr-enum.py target=ydc1.domain-y.local username=enum-x password=LabAdm1! opnums=true enumerate=computers` |  | [Open](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/samr-enum.py_computers.txt) |
| `samr-enum`      | 25 KB | Traffic Capture | `python samr-enum.py target=ydc1.domain-y.local username=enum-x password=LabAdm1! opnums=true enumerate=local-groups` |  | [Download](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/samr-enum.py_local_groups.pcapng) |
| `samr-enum`      | 2 KB  | Command Output  | `python samr-enum.py target=ydc1.domain-y.local username=enum-x password=LabAdm1! opnums=true enumerate=local-groups` |  | [Open](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/samr-enum.py_local_groups.txt) |
| `samr-enum`      | 26 KB | Traffic Capture | `python samr-enum.py target=ydc1.domain-y.local username=enum-x password=LabAdm1! opnums=true enumerate=domain-groups` |  | [Download](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/samr-enum.py_domain_groups.pcapng) |
| `samr-enum`      | 6 KB  | Command Output  | `python samr-enum.py target=ydc1.domain-y.local username=enum-x password=LabAdm1! opnums=true enumerate=domain-groups` |  | [Open](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/samr-enum.py_domain_groups.txt) |
| `samr-enum`      | 30 KB | Traffic Capture | `python samr-enum.py target=ydc1.domain-y.local username=enum-x password=LabAdm1! opnums=true enumerate=local-group-details  group=Administrators` |  | [Download](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/samr-enum.py_local_group_details.pcapng) |
| `samr-enum`      | 2 KB  | Command Output  | `python samr-enum.py target=ydc1.domain-y.local username=enum-x password=LabAdm1! opnums=true enumerate=local-group-details  group=Administrators` |  | [Open](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/samr-enum.py_local_group_details.txt) |
| `samr-enum`      | 24 KB | Traffic Capture | `python samr-enum.py target=ydc1.domain-y.local username=enum-x password=LabAdm1! opnums=true enumerate=domain-group-details  group=Domain Admins` |  | [Download](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/samr-enum.py_domain_group_details.pcapng) |
| `samr-enum`      | 2 KB  | Command Output  | `python samr-enum.py target=ydc1.domain-y.local username=enum-x password=LabAdm1! opnums=true enumerate=domain-group-details  group=Domain Admins` |  | [Open](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/samr-enum.py_domain_group_details.txt) |
| `samr-enum`      | 126 KB | Traffic Capture| `python samr-enum.py target=ydc1.domain-y.local username=enum-x password=LabAdm1! opnums=true enumerate=user-memberships-localgroups user=Administrator` |  | [Download](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/samr-enum.py_user_memberships_localgroups.pcapng) |
| `samr-enum`      | 5 KB  | Command Output  | `python samr-enum.py target=ydc1.domain-y.local username=enum-x password=LabAdm1! opnums=true enumerate=user-memberships-localgroups user=Administrator` |  | [Open](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/samr-enum.py_user_memberships_localgroups.txt) |
| `samr-enum`      | 23 KB | Traffic Capture | `python samr-enum.py target=ydc1.domain-y.local username=enum-x password=LabAdm1! opnums=true enumerate=user-memberships-domaingroups user=Administrator` |  | [Download](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/samr-enum.py_user_memberships_domaingroups.pcapng) |
| `samr-enum`      | 2 KB  | Command Output  | `python samr-enum.py target=ydc1.domain-y.local username=enum-x password=LabAdm1! opnums=true enumerate=user-memberships-domaingroups user=Administrator` |  | [Open](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/samr-enum.py_user_memberships_domaingroups.txt) |
| `samr-enum`      | 22 KB | Traffic Capture | `python samr-enum.py target=ydc1.domain-y.local username=enum-x password=LabAdm1! opnums=true enumerate=account-details user=Administrator acl` |  | [Download](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/samr-enum.py_account_details_v1.2.0.pcapng) |
| `samr-enum`      | 2 KB  | Command Output  | `python samr-enum.py target=ydc1.domain-y.local username=enum-x password=LabAdm1! opnums=true enumerate=account-details user=Administrator acl` |  | [Open](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/samr-enum.py_account_details_v.1.2.0.txt) |
| `samr-enum`      | 2.5 MB| Traffic Capture | `python samr-enum.py target=ydc1.domain-y.local username=enum-x password=LabAdm1! opnums=true enumerate=display-info type=users` |  | [Download](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/samr-enum.py_display_info_users.pcapng) |
| `samr-enum`      | 168 KB| Command Output  | `python samr-enum.py target=ydc1.domain-y.local username=enum-x password=LabAdm1! opnums=true enumerate=display-info type=users` |  | [Open](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/samr-enum.py_display_info_users.txt) |
| `samr-enum`      | 64 KB | Traffic Capture | `python samr-enum.py target=ydc1.domain-y.local username=enum-x password=LabAdm1! opnums=true enumerate=display-info type=computers` |  | [Download](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/samr-enum.py_display_info_computers.pcapng) |
| `samr-enum`      | 5 KB  | Command Output  | `python samr-enum.py target=ydc1.domain-y.local username=enum-x password=LabAdm1! opnums=true enumerate=display-info type=computers` |  | [Open](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/samr-enum.py_display_info_computers.txt) |
| `samr-enum`      | 155 KB| Traffic Capture | `python samr-enum.py target=ydc1.domain-y.local username=enum-x password=LabAdm1! opnums=true enumerate=display-info type=local-groups` |  | [Download](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/samr-enum.py_display_info_local_groups.pcapng) |
| `samr-enum`      | 12 KB | Command Output  | `python samr-enum.py target=ydc1.domain-y.local username=enum-x password=LabAdm1! opnums=true enumerate=display-info type=local-groups` |  | [Open](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/samr-enum.py_display_info_local_groups.txt) |
| `samr-enum`      | 883 KB| Traffic Capture | `python samr-enum.py target=ydc1.domain-y.local username=enum-x password=LabAdm1! opnums=true enumerate=display-info type=domain-groups` |  | [Download](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/samr-enum.py_display_info_domain_groups.pcapng) |
| `samr-enum`      | 38 KB | Command Output  | `python samr-enum.py target=ydc1.domain-y.local username=enum-x password=LabAdm1! opnums=true enumerate=display-info type=domain-groups` |  | [Open](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/samr-enum.py_display_info_domain_groups.txt) |
| `samr-enum`      | 75 KB | Traffic Capture | `python samr-enum.py target=ydc1.domain-y.local username=enum-x password=LabAdm1! opnums=true enumerate=summary` |  | [Download](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/samr-enum.py_summary.pcapng) |
| `samr-enum`      | 2 KB  | Command Output  | `python samr-enum.py target=ydc1.domain-y.local username=enum-x password=LabAdm1! opnums=true enumerate=summary` |  | [Open](https://github.com/studylab1/SAMR-Enum-Lab/raw/refs/heads/main/Resources/samr-enum.py_summary.txt) |

## SAMR Operation Numbers Details

The table below provides an overview of SAMR operation numbers (OpNums) relevant to enumeration. Each OpNum corresponds to a specific operation that can be executed using the SAMR protocol. The table includes the following details for each OpNum:
- OpNum: The unique identifier for the operation.
- Name: The official name of the operation.
- Data Type in Response: The format of the data returned in response to the operation.
- Description: A brief explanation of the operation’s functionality and purpose.

| **OpNum** | **Name**                       | **Data Type in Response**             | **Description**                                                                                   |
|-----------|--------------------------------|----------------------------------------|---------------------------------------------------------------------------------------------------|
| 0         | `SamrConnect`                 | Handle                                | Establishes an initial connection to the SAM server, allowing subsequent operations to be performed. |
| 1         | `SamrCloseHandle`             | N/A                                   | Closes an open handle to a SAM object, releasing the associated resources.                        |
| 3         | `SamrQuerySecurityObject`     | Security Descriptor                   | Retrieves security information for a specified SAM object, such as permissions and access control details. |
| 5         | `SamrLookupDomainInSamServer` | SID                                   | Resolves a domain name to its corresponding SID within the SAM server.                            |
| 6         | `SamrEnumerateDomainsInSamServer` | List of Strings                       | Lists all domains managed by the SAM server.                                                  |
| 7         | `SamrOpenDomain`              | Handle                                | Opens a handle to a specific domain for further operations.                                       |
| 8         | `SamrQueryInformationDomain`  | Varies (based on Information Level)   | Retrieves specific information about a domain, such as security policies or account statistics.   |
| 11        | `SamrEnumerateGroupsInDomain` | List of Strings and Integers          | Retrieves a list of group names (strings) and their RIDs (relative identifiers, integers).        |
| 13        | `SamrEnumerateUsersInDomain`  | List of Strings and Integers          | Retrieves user account names (strings) and their RIDs (relative identifiers, integers).           |
| 15        | `SamrEnumerateAliasesInDomain`| List of Strings and Integers          | Lists alias groups (local groups) within a domain along with their RIDs.                         |
| 16        | `SamrGetAliasMembership`      | List of SIDs                          | Shows alias memberships for a specific user or SID.                                              |
| 17        | `SamrLookupNamesInDomain`     | List of SIDs                          | Converts account names into SIDs within a domain.                                                |
| 18        | `SamrLookupIdsInDomain`       | List of Strings                       | Maps SIDs back to account names.                                                                 |
| 19        | `SamrOpenGroup`               | Handle                                | Opens a handle to a specific group for further operations.                                       |
| 20        | `SamrQueryInformationGroup`   | Varies (based on Information Level)   | Retrieves information about a specific group in a domain.                                        |
| 25        | `SamrGetMembersInGroup`       | List of Integers                      | Retrieves the list of members' RIDs for a given group.                                           |
| 27        | `SamrOpenAlias`               | Handle                                | Opens a handle to a specific alias (local group) for further operations.                         |
| 28        | `SamrQueryInformationAlias`   | Varies (based on Information Level)   | Retrieves detailed information about an alias (local group), such as its description and member statistics, depending on the requested information level.| 
| 33        | `SamrGetMembersInAlias`       | List of SIDs                          | Retrieves a list of members for a specified alias (local group).                                 |
| 34        | `SamrOpenUser`                | Handle                                | Opens a handle to a specific user account for further operations.                                |
| 36        | `SamrQueryInformationUser`    | Varies (based on Information Level)   | Retrieves detailed information on a specific user account.                                       |
| 39        | `SamrGetGroupsForUser`        | List of Integers                      | Lists all group memberships for a specified user.                                                |
| 40        | `SamrQueryDisplayInformation` | Paginated List of Strings             | Provides display information (e.g., names) for a set of domain accounts, such as users or groups.|
| 41        | `SamrGetDisplayEnumerationIndex` | Integer                            | Retrieves the display index for paginated enumerations.                                          |
| 44        | `SamrGetUserDomainPasswordInformation`| Structure                     | Retrieves select password policy information for a user without requiring a domain handle.       |
| 46        | `SamrQueryInformationDomain2` | List of Strings and Integers          | Retrieves display information (e.g., names, account descriptions) for domain accounts. This operation is similar to SamrQueryDisplayInformation, but allows for extended querying. |
| 47        | `SamrQueryInformationUser2`   | Varies (based on Information Level)   | Provides additional detailed information about a user account, similar to `SamrQueryInformationUser`.|
| 48        | `SamrQueryDisplayInformation2`| Paginated List of Strings             | Retrieves display information for domain accounts (e.g., users, groups) in a paginated format.    |
| 49        | `SamrGetDisplayEnumerationIndex2` | Integer                           | Retrieves the display index for paginated enumerations in scenarios requiring extended enumeration. |
| 51        | `SamrQueryDisplayInformation3`| Paginated and Filtered List of Strings| Enables detailed and filtered queries for large-scale user, group, or machine account enumeration.|
| 56        | `SamrGetDomainPasswordInformation` | Structure                        | Retrieves password policy information for the domain.                                           |
| 57        | `SamrConnect2`                | Handle                                | Establishes a connection to the SAM server, specifically optimized for certain environments or use cases. |
| 62        | `SamrConnect4`                | Handle                                | Establishes a connection to the SAM server using extended security negotiation parameters, offering additional features compared to SamrConnect. |
| 64        | `SamrConnect5`                | Handle                                | Establishes a connection to the SAM server for domain enumeration and lookup.                   |
| 65        | `SamrRidToSid`                | SID                                   | Converts a relative identifier (RID) to a security identifier (SID) within the domain.          |
| 74        | `SamrValidateComputerAccountReuseAttempt` | Integer                   | Validates whether a computer account reuse attempt complies with domain policies, returning a status code that indicates if reuse is permitted. |
| 77        | `SamrAccountIsDelegatedManagedServiceAccount` | Integer               | Determines if a computer account is a Delegated Managed Service Account (gMSA), returning a flag indicating its managed service status. |

## PowerShell AD Module Cmdlets Details

The following is the list of PowerShell AD module cmdlets and their parameters used during testing. These commands targeted the domain controller zdc1.domain-z.local in a foreign forest using cross-forest authentication with explicitly defined credentials. The parameters for each command were selected to evaluate the cmdlets’ behavior.

Traffic analysis revealed that the cmdlets relied on the Microsoft .NET Naming Service (MS-NNS) and Microsoft .NET Message Framing Protocol (MS-NMF) for their operations, rather than SAMR requests.

1. **Get-ADAccountAuthorizationGroup**
   - `-Identity "administrator"`
   - `-Server "zdc1.domain-z.local"`
   - `-Credential $Cred`

2. **Get-ADAccountResultantPasswordReplicationPolicy**
   - `-Identity "administrator"`
   - `-DomainController "zdc1.domain-z.local"`
   - `-Credential $Cred`

3. **Get-ADAuthenticationPolicy**
   - `-Filter *`
   - `-Server "zdc1.domain-z.local"`
   - `-Credential $Cred`

4. **Get-ADAuthenticationPolicySilo**
   - `-Filter *`
   - `-Server "zdc1.domain-z.local"`
   - `-Credential $Cred`

5. **Get-ADCentralAccessPolicy**
   - `-Filter *`
   - `-Server "zdc1.domain-z.local"`
   - `-Credential $Cred`

6. **Get-ADCentralAccessRule**
   - `-Filter *`
   - `-Server "zdc1.domain-z.local"`
   - `-Credential $Cred`

7. **Get-ADClaimTransformPolicy**
   - `-Filter *`
   - `-Server "zdc1.domain-z.local"`
   - `-Credential $Cred`

8. **Get-ADClaimType**
   - `-Filter *`
   - `-Server "zdc1.domain-z.local"`
   - `-Credential $Cred`

9. **Get-ADComputerServiceAccount**
   - `-Identity "MySvcAcct"`
   - `-Server "zdc1.domain-z.local"`
   - `-Credential $Cred`

10. **Get-ADDefaultDomainPasswordPolicy**
    - `-Server "zdc1.domain-z.local"`
    - `-Credential $Cred`

11. **Get-ADDomainControllerPasswordReplicationPolicy**
    - `-Identity "zdc1.domain-z.local"`
    - `-Credential $Cred`

12. **Get-ADDomainControllerPasswordReplicationPolicyUsage**
    - `-Identity "zdc1.domain-z.local"`
    - `-Credential $Cred`

13. **Get-ADFineGrainedPasswordPolicy**
    - `-Filter *`
    - `-Server "zdc1.domain-z.local"`
    - `-Credential $Cred`

14. **Get-ADFineGrainedPasswordPolicySubject**
    - `-Identity "ExistingPolicyName"`
    - `-Server "zdc1.domain-z.local"`
    - `-Credential $Cred`

15. **Get-ADObject**
    - `-Filter *`
    - `-Server "zdc1.domain-z.local"`
    - `-Credential $Cred`

16. **Get-ADOptionalFeature**
    - `-Filter *`
    - `-Server "zdc1.domain-z.local"`
    - `-Credential $Cred`

17. **Get-ADOrganizationalUnit**
    - `-Filter *`
    - `-Server "zdc1.domain-z.local"`
    - `-Credential $Cred`

18. **Get-ADPrincipalGroupMembership**
    - `-Identity "administrator"`
    - `-Server "zdc1.domain-z.local"`
    - `-Credential $Cred`

19. **Get-ADReplicationAttributeMetadata**
    - `-Object "CN=Administrator,CN=Users,DC=domain-z,DC=local"`
    - `-Server "zdc1.domain-z.local"`
    - `-Credential $Cred`

20. **Get-ADReplicationConnection**
    - `-Filter *`
    - `-Server "zdc1.domain-z.local"`
    - `-Credential $Cred`

21. **Get-ADReplicationFailure**
    - `-Target "zdc1.domain-z.local"`
    - `-Credential $Cred`

22. **Get-ADReplicationPartnerMetadata**
    - `-Target "zdc1.domain-z.local"`
    - `-Credential $Cred`

23. **Get-ADReplicationQueueOperation**
    - `-Server "zdc1.domain-z.local"`
    - `-Credential $Cred`

24. **Get-ADReplicationSite**
    - `-Filter *`
    - `-Server "zdc1.domain-z.local"`
    - `-Credential $Cred`

25. **Get-ADReplicationSiteLink**
    - `-Filter *`
    - `-Server "zdc1.domain-z.local"`
    - `-Credential $Cred`

26. **Get-ADReplicationSiteLinkBridge**
    - `-Filter *`
    - `-Server "zdc1.domain-z.local"`
    - `-Credential $Cred`

27. **Get-ADReplicationSubnet**
    - `-Filter *`
    - `-Server "zdc1.domain-z.local"`
    - `-Credential $Cred`

28. **Get-ADResourceProperty**
    - `-Filter *`
    - `-Server "zdc1.domain-z.local"`
    - `-Credential $Cred`

29. **Get-ADResourcePropertyList**
    - `-Filter *`
    - `-Server "zdc1.domain-z.local"`
    - `-Credential $Cred`

30. **Get-ADResourcePropertyValueType**
    - `-Filter *`
    - `-Server "zdc1.domain-z.local"`
    - `-Credential $Cred`

31. **Get-ADRootDSE**
    - `-Server "zdc1.domain-z.local"`
    - `-Credential $Cred`

32. **Get-ADServiceAccount**
    - `-Identity "MySvcAcct"`
    - `-Server "zdc1.domain-z.local"`
    - `-Credential $Cred`

33. **Get-ADTrust**
    - `-Filter *`
    - `-Server "zdc1.domain-z.local"`
    - `-Credential $Cred`

34. **Get-ADUserResultantPasswordPolicy**
    - `-Identity "administrator"`
    - `-Server "zdc1.domain-z.local"`
    - `-Credential $Cred`

35. **Sync-ADObject**
    - `-Object "CN=Administrator,CN=Users,DC=domain-z,DC=local"`
    - `-Server "zdc1.domain-z.local"`
    - `-Credential $Cred`

36. **Search-ADAccount**
    - `-AccountDisabled`
    - `-Server "zdc1.domain-z.local"`
    - `-Credential $Cred`

37. **Get-ADUser**
    - `-Filter *`
    - `-Server "zdc1.domain-z.local"`
    - `-Credential $Cred`

38. **Get-ADGroup**
    - `-Filter *`
    - `-Server "zdc1.domain-z.local"`
    - `-Credential $Cred`

39. **Get-ADComputer**
    - `-Filter *`
    - `-Server "zdc1.domain-z.local"`
    - `-Credential $Cred`

40. **Get-ADDomain**
    - `-Server "zdc1.domain-z.local"`
    - `-Credential $Cred`

41. **Get-ADDomainController**
    - `-Filter *`
    - `-Server "zdc1.domain-z.local"`
    - `-Credential $Cred`

42. **Get-ADGroupMember**
    - `-Identity "Domain Admins"`
    - `-Server "zdc1.domain-z.local"`
    - `-Credential $Cred`
