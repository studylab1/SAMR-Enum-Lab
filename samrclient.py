#!/usr/bin/env python3

from impacket.dcerpc.v5 import transport, samr

def main():
    # Hardcoded server and credentials
    target_host = "ydc1.domain-y.local"
    domain      = "domain-y.local"  # or possibly "" if it's a local domain
    username    = "enum"
    password    = "LabAdm1!"

    # 1) Build the named-pipe transport string, e.g. ncacn_np:host[\pipe\samr]
    binding_str = fr"ncacn_np:{target_host}[\pipe\samr]"
    rpctransport = transport.DCERPCTransportFactory(binding_str)

    # 2) Provide the credentials (NTLM or Kerberos)
    rpctransport.set_credentials(username, password, domain=domain)

    # 3) Connect to \pipe\samr over SMB
    dce = rpctransport.get_dce_rpc()
    print("[*] Connecting to DCE RPC on SMB pipe...")
    dce.connect()

    # 4) Bind to the SAMR interface
    print("[*] Binding to SAMR (MSRPC_UUID_SAMR)...")
    dce.bind(samr.MSRPC_UUID_SAMR)

    # 5) Call hSamrConnect (Impacket picks the right SamrConnectX under the hood)
    print("[*] Calling hSamrConnect...")
    serverHandle = samr.hSamrConnect(
        dce,
        serverName=target_host,
        desiredAccess=samr.MAXIMUM_ALLOWED
    )

    # The returned handle is used for further SAMR calls (e.g. SamrOpenDomain, SamrEnumerateUsers, etc.)
    print("[+] hSamrConnect succeeded!")
    print(f"    ServerHandle: {serverHandle['ServerHandle']}")
    print(f"    NTSTATUS: 0x{serverHandle['ErrorCode']:X}")

    # 6) Cleanup
    dce.disconnect()

if __name__ == "__main__":
    main()
