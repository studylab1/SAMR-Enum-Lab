#!/usr/bin/env python3

from impacket.dcerpc.v5 import transport, samr
from impacket.dcerpc.v5.dtypes import RPC_SID
from impacket.dcerpc.v5.ndr import NDRCALL


def main():
    # Hardcoded server and credentials
    target_host = "ydc1.domain-y.local"
    domain = "domain-y.local"  # Adjust if needed
    username = "enum"
    password = "LabAdm1!"

    # 1) Build the RPC transport for \pipe\samr over SMB
    binding_str = fr"ncacn_np:{target_host}[\pipe\samr]"
    rpc_transport = transport.DCERPCTransportFactory(binding_str)
    rpc_transport.set_credentials(username, password, domain=domain)

    # Connect + Bind to SAMR
    dce = rpc_transport.get_dce_rpc()
    print("[*] Connecting to DCE RPC on SMB pipe...")
    dce.connect()

    print("[*] Binding to SAMR (MSRPC_UUID_SAMR)...")
    dce.bind(samr.MSRPC_UUID_SAMR)

    # 2) SamrConnect -> ServerHandle
    print("[*] SamrConnect...")
    serverHandle = samr.hSamrConnect(
        dce,
        serverName=target_host,
        desiredAccess=samr.MAXIMUM_ALLOWED
    )
    serverHandle = serverHandle['ServerHandle']
    print("[+] SamrConnect succeeded, got ServerHandle.")

    # 3) Enumerate domains in this SAM server:
    print("[*] Enumerating domains via SamrEnumerateDomainsInSamServer...")
    enumDomainsResp = samr.hSamrEnumerateDomainsInSamServer(
        dce,
        serverHandle,
        enumerationContext=0,
        preferedMaximumLength=8192
    )
    domains = enumDomainsResp['Buffer']['Buffer']  # array of SAMPR_RID_ENUMERATION
    if not domains:
        print("[-] No domains found on this server?  Exiting.")
        return

    # For simplicity, just pick the first domain
    domainName = domains[0]['Name']
    print(f"[+] Found domain: {domainName}")

    # 4) Look up that domain to get the SID:
    print("[*] SamrLookupDomainInSamServer for domain SID...")
    lookupResp = samr.hSamrLookupDomainInSamServer(dce, serverHandle, domainName)
    domainSid = lookupResp['DomainId']

    # domainSidObj is already an NDR SID object
    domainSidObj = lookupResp['DomainId']
    sidString = domainSidObj.formatCanonical()  # convert SID to "S-1-..." string
    print(f"[+] Domain SID: {sidString}")


    # 5) Open the domain -> DomainHandle
    print("[*] SamrOpenDomain...")
    openDomResp = samr.hSamrOpenDomain(dce, serverHandle, samr.DOMAIN_LIST_ACCOUNTS | samr.DOMAIN_LOOKUP, domainSid)
    domainHandle = openDomResp['DomainHandle']
    print("[+] Domain opened successfully.")

    # 6) Enumerate groups in the domain (OpNum=11 under the hood)
    print("[*] SamrEnumerateGroupsInDomain for domain groups...")
    enumGroupsResp = samr.hSamrEnumerateGroupsInDomain(
        dce,
        domainHandle,
        enumerationContext=0
    )

    if enumGroupsResp['Buffer']['Buffer']:
        print("[+] Groups in domain:")
        for groupEntry in enumGroupsResp['Buffer']['Buffer']:
            groupName = groupEntry['Name']
            groupRID = groupEntry['RelativeId']
            print(f"    - {groupName} (RID={groupRID})")
    else:
        print("[-] No groups found in domain (unlikely).")

    # 7) Cleanup
    print("[*] Closing handles and disconnecting.")
    samr.hSamrCloseHandle(dce, domainHandle)
    samr.hSamrCloseHandle(dce, serverHandle)
    dce.disconnect()


if __name__ == "__main__":
    main()
