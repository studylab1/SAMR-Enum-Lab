# Impacket "samrdump.py" Tool Evaluation

**samrdump.py** is part of the Impacket library, a suite of tools for interacting with network protocols. It is designed for enumerating SAMR protocol information, allowing detailed analysis of SAMR operations by connecting to remote domain controllers.

For this evaluation, the tool was executed with the following parameters:  
`python.exe samrdump.py domain-y/enum:LabAdm1!@zdc1.domain-z.local`

The network traffic captured during execution was encrypted. To decrypt the capture in Wireshark, the NT password `LabAdm1!` must be provided under:  
**Preferences > Protocols > NTLMSSP > NT Password**  
**"LINK TO ADD"**
---

## SAMR Request Specification Compliance in Detail

This evaluation analyzed compliance with the SAMR protocol's "Desired Access" field, focusing on access permissions requested during operations. The "Desired Access" field in the SAMR header specifies permissions requested for each operation.

### Methodology

The analysis followed the sequence of operations observed in the network traffic. Duplicate entries with identical permissions were omitted for clarity. Non-compliant entries are explicitly highlighted.

---

### "samrdump.py" (to cross-forest domain controller)

The `samrdump.py` tool was executed against a cross-forest domain controller (`zdc1`), with all SAMR requests originating from the client. The following operation details were analyzed:

| **SAMR Operation**               | **Wireshark Label** | **OpNum** | **Requested Access Rights (Hex)** | **Rights Description**                                                                                   | **Required for Operation?** | **Compliance with Requested Access** |
|-----------------------------------|---------------------|-----------|------------------------------------|----------------------------------------------------------------------------------------------------------|-----------------------------|---------------------------------------|

---

