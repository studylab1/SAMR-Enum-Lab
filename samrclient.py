#!/usr/bin/env python3

import sys
import time
from datetime import datetime

from impacket.dcerpc.v5 import transport, samr

def parse_named_args(argv):
    """
    Very simple parser for key=value style arguments.
    Example usage:
      python samrclient.py operation=groups server=ydc1.domain-y.local username=enum password=LabAdm1! domain=domain-y.local debug=true
    """
    args = {}
    for item in argv[1:]:
        if '=' in item:
            key, val = item.split('=', 1)
            args[key.strip().lower()] = val.strip()
    return args

def log_debug(debug, message):
    """Print message only if debug=True."""
    if debug:
        print(message)

def samr_connect(server, username, password, domain, debug):
    """
    Connects to \\pipe\\samr using Impacket, returns (dce, serverHandle).
    Uses desiredAccess=0x00000031 as specified.
    """
    binding_str = rf"ncacn_np:{server}[\pipe\samr]"
    log_debug(debug, f"[debug] Using binding string: {binding_str}")

    rpc_transport = transport.DCERPCTransportFactory(binding_str)
    rpc_transport.set_credentials(username, password, domain=domain)

    dce = rpc_transport.get_dce_rpc()
    log_debug(debug, f"[debug] Connecting to {server} via SMB...")
    dce.connect()
    log_debug(debug, "[debug] Binding to SAMR interface (MSRPC_UUID_SAMR)...")
    dce.bind(samr.MSRPC_UUID_SAMR)

    log_debug(debug, "[debug] Calling SamrConnect...")
    connectResp = samr.hSamrConnect(
        dce,
        serverName=server,
        desiredAccess=0x00000031
    )
    if debug:
        print("[debug] SamrConnect response dump:")
        print(connectResp.dump())

    serverHandle = connectResp['ServerHandle']
    ntStatus     = connectResp['ErrorCode']
    if ntStatus != 0:
        raise Exception(f"SamrConnect failed (NTSTATUS=0x{ntStatus:X})")

    log_debug(debug, "[debug] SamrConnect succeeded.")
    return dce, serverHandle

def get_domain_handle(dce, serverHandle, debug):
    """
    Enumerate the first domain, then OpenDomain.
    Returns (domainHandle, domainName, sidString).
    """
    log_debug(debug, "[debug] SamrEnumerateDomainsInSamServer -> enumerating domains...")
    enumDomainsResp = samr.hSamrEnumerateDomainsInSamServer(dce, serverHandle, enumerationContext=0)
    if debug:
        print("[debug] SamrEnumerateDomainsInSamServer response dump:")
        print(enumDomainsResp.dump())

    domains = enumDomainsResp['Buffer']['Buffer']
    if not domains:
        raise Exception("No domains found on server.")

    # For simplicity, pick the first domain returned if multiple
    domainName = domains[0]['Name']
    log_debug(debug, f"[debug] Found domain: {domainName}")

    # Lookup domain SID
    lookupResp = samr.hSamrLookupDomainInSamServer(dce, serverHandle, domainName)
    if debug:
        print("[debug] SamrLookupDomainInSamServer response dump:")
        print(lookupResp.dump())

    domainSidObj = lookupResp['DomainId']
    sidString = domainSidObj.formatCanonical()
    log_debug(debug, f"[debug] Domain SID: {sidString}")

    # Open the domain
    log_debug(debug, "[debug] SamrOpenDomain -> opening domain handle...")
    openDomResp = samr.hSamrOpenDomain(
        dce,
        serverHandle,
        samr.DOMAIN_LOOKUP | samr.DOMAIN_LIST_ACCOUNTS,
        domainSidObj
    )
    if debug:
        print("[debug] SamrOpenDomain response dump:")
        print(openDomResp.dump())

    domainHandle = openDomResp['DomainHandle']
    ntStatus = openDomResp['ErrorCode']
    if ntStatus != 0:
        raise Exception(f"SamrOpenDomain failed (NTSTATUS=0x{ntStatus:X})")

    log_debug(debug, "[debug] Domain opened successfully.")
    return domainHandle, domainName, sidString

def enumerate_groups_in_domain(dce, domainHandle, debug):
    """Enumerates domain groups. Returns a list of (groupName, rid)."""
    log_debug(debug, "[debug] SamrEnumerateGroupsInDomain -> enumerating groups...")
    enumGroupsResp = samr.hSamrEnumerateGroupsInDomain(dce, domainHandle, enumerationContext=0)
    if debug:
        print("[debug] SamrEnumerateGroupsInDomain response dump:")
        print(enumGroupsResp.dump())

    ntStatus = enumGroupsResp['ErrorCode']
    if ntStatus not in (0, 0x105):  # 0x105 = STATUS_MORE_ENTRIES
        raise Exception(f"SamrEnumerateGroupsInDomain ErrorCode=0x{ntStatus:X}")

    groups = enumGroupsResp['Buffer']['Buffer'] or []
    return [(g['Name'], g['RelativeId']) for g in groups]

def enumerate_users_in_domain(dce, domainHandle, debug):
    """Enumerates domain users. Returns a list of (userName, rid)."""
    log_debug(debug, "[debug] SamrEnumerateUsersInDomain -> enumerating users...")
    enumUsersResp = samr.hSamrEnumerateUsersInDomain(dce, domainHandle, enumerationContext=0, userAccountControl=0)
    if debug:
        print("[debug] SamrEnumerateUsersInDomain response dump:")
        print(enumUsersResp.dump())

    ntStatus = enumUsersResp['ErrorCode']
    if ntStatus not in (0, 0x105):  # 0x105 = STATUS_MORE_ENTRIES
        raise Exception(f"SamrEnumerateUsersInDomain ErrorCode=0x{ntStatus:X}")

    users = enumUsersResp['Buffer']['Buffer'] or []
    return [(u['Name'], u['RelativeId']) for u in users]

def list_group_members(dce, domainHandle, groupName, debug):
    """
    Looks up 'groupName' by SamrLookupNamesInDomain, which returns arrays 'RelativeIds' & 'Use' (NOT 'TranslatedSids').
    If it's an alias => SamrOpenAlias + SamrGetMembersInAlias
    If it's a domain group => SamrOpenGroup + SamrGetMembersInGroup
    Returns a list of (memberRidOrSidData, attributes).
    """
    log_debug(debug, f"[debug] SamrLookupNamesInDomain -> looking up group: {groupName}")
    lookupResp = samr.hSamrLookupNamesInDomain(dce, domainHandle, [groupName])
    if debug:
        print("[debug-lookupResp] SamrLookupNamesInDomain response dump:")
        print(lookupResp.dump())

    ntStatus = lookupResp['ErrorCode']
    if ntStatus != 0:
        raise Exception(f"SamrLookupNamesInDomain failed (NTSTATUS=0x{ntStatus:X})")

    # Instead of TranslatedSids, Impacket returns 'RelativeIds' & 'Use'
    rids = lookupResp['RelativeIds']['Element']
    uses = lookupResp['Use']['Element']

    if len(rids) < 1 or len(uses) < 1:
        raise Exception(f"No mapped result for '{groupName}'")

    groupRid = rids[0]
    sidUse   = uses[0]
    log_debug(debug, f"[debug] groupRid={groupRid}, sidUse={sidUse}")

    if sidUse == samr.SID_NAME_ALIAS:
        # local group (alias)
        log_debug(debug, "[debug] SamrOpenAlias -> local group/alias")
        openAliasResp = samr.hSamrOpenAlias(dce, domainHandle, samr.ALIAS_LIST_MEMBERS, groupRid)
        if debug:
            print("[debug] SamrOpenAlias response dump:")
            print(openAliasResp.dump())

        if openAliasResp['ErrorCode'] != 0:
            raise Exception(f"SamrOpenAlias failed (NTSTATUS=0x{openAliasResp['ErrorCode']:X})")

        aliasHandle = openAliasResp['AliasHandle']
        log_debug(debug, "[debug] SamrGetMembersInAlias -> retrieving members for alias...")
        membersResp = samr.hSamrGetMembersInAlias(dce, aliasHandle)
        if debug:
            print("[debug] SamrGetMembersInAlias response dump:")
            print(membersResp.dump())

        if membersResp['ErrorCode'] != 0:
            raise Exception(f"SamrGetMembersInAlias failed (0x{membersResp['ErrorCode']:X}).")

        members = membersResp['Members']['Sids']
        samr.hSamrCloseHandle(dce, aliasHandle)
        results = []
        for m in members:
            sidData = m['SidPointer']['Data']   # bytes
            sidAttr = m['SidAttributes']        # int
            # Convert bytes to a safer string or hex, so we won't cause "non-string" errors
            results.append((sidData.hex(), sidAttr))
        return results

    elif sidUse == samr.SID_NAME_DOM_GRP or sidUse == samr.SID_NAME_WKN_GRP:
        # domain group
        log_debug(debug, "[debug] SamrOpenGroup -> domain group")
        openGroupResp = samr.hSamrOpenGroup(dce, domainHandle, samr.GROUP_LIST_MEMBERS, groupRid)
        if debug:
            print("[debug] SamrOpenGroup response dump:")
            print(openGroupResp.dump())

        if openGroupResp['ErrorCode'] != 0:
            raise Exception(f"SamrOpenGroup failed (NTSTATUS=0x{openGroupResp['ErrorCode']:X})")

        groupHandle = openGroupResp['GroupHandle']
        log_debug(debug, "[debug] SamrGetMembersInGroup -> retrieving members for domain group...")
        membersResp = samr.hSamrGetMembersInGroup(dce, groupHandle)
        if debug:
            print("[debug] SamrGetMembersInGroup response dump:")
            print(membersResp.dump())

        if membersResp['ErrorCode'] != 0:
            raise Exception(f"SamrGetMembersInGroup failed (0x{membersResp['ErrorCode']:X}).")

        members = membersResp['Members']['Members']
        samr.hSamrCloseHandle(dce, groupHandle)

        # Each member is { 'RelativeId': rid, 'Attributes': ... }
        return [(m['RelativeId'], m['Attributes']) for m in members]

    else:
        raise Exception(f"Object '{groupName}' is not recognized as a domain or alias group (SID type={sidUse}).")

def main():
    # Parse named args
    args = parse_named_args(sys.argv)
    operation   = args.get('operation', 'groups').lower()
    server      = args.get('server', '')
    username    = args.get('username', '')
    password    = args.get('password', '')
    domain      = args.get('domain', '')
    groupName   = args.get('group', '')
    debug       = args.get('debug', 'false').lower() == 'true'

    if not server or not username or not password:
        print("Usage example:\n"
              "  python samrclient.py operation=groups server=ydc1.domain-y.local username=enum password=LabAdm1! [domain=domain-y.local] [group=MyGroup] [debug=true]\n"
              "Operations: groups, users, group-members\n"
              "If operation=group-members, pass group=<GroupName> as well.\n"
              "debug=true will show more details.")
        sys.exit(1)

    start_time = time.time()
    start_timestamp = datetime.now()

    print(f"Execution started at: {start_timestamp}")

    opnums_called = []
    access_mask = "0x00000031"
    dce = None
    serverHandle = None
    domainHandle = None
    domainSidString = ""
    enumerated_objects = []
    execution_status = "success"

    try:
        # 1) Connect
        opnums_called.append("SamrConnect")
        dce, serverHandle = samr_connect(server, username, password, domain, debug)

        # 2) Domain handle
        opnums_called.extend(["SamrEnumerateDomainsInSamServer", "SamrLookupDomainInSamServer", "SamrOpenDomain"])
        domainHandle, domainName, domainSidString = get_domain_handle(dce, serverHandle, debug)

        # 3) Operation
        if operation == 'groups':
            opnums_called.append("SamrEnumerateGroupsInDomain")
            enumerated_objects = enumerate_groups_in_domain(dce, domainHandle, debug)

        elif operation == 'users':
            opnums_called.append("SamrEnumerateUsersInDomain")
            enumerated_objects = enumerate_users_in_domain(dce, domainHandle, debug)

        elif operation == 'group-members':
            if not groupName:
                raise Exception("group=<GroupName> is required for operation=group-members.")
            opnums_called.append("SamrLookupNamesInDomain")
            enumerated_objects = list_group_members(dce, domainHandle, groupName, debug)

        else:
            raise Exception(f"Unknown operation '{operation}'. Supported: groups, users, group-members.")

    except Exception as e:
        # Use repr(e) in case e contains raw bytes
        execution_status = f"error: {repr(e)}"
    finally:
        # Cleanup
        if domainHandle:
            try:
                samr.hSamrCloseHandle(dce, domainHandle)
            except:
                pass
        if serverHandle:
            try:
                samr.hSamrCloseHandle(dce, serverHandle)
            except:
                pass
        if dce:
            try:
                dce.disconnect()
            except:
                pass

    end_time = time.time()
    duration = end_time - start_time

    print(f"Execution time: {duration:.2f} seconds")
    print(f"Destination server: {server}")
    print(f"Domain SID: {domainSidString or 'N/A'}")
    print(f"Account: {username}")
    print(f"Operation: {operation}")
    print(f"OpNums called: {', '.join(opnums_called)}")
    print(f"Access Mask used: {access_mask}")
    print(f"Execution status: {execution_status}")

    obj_count = len(enumerated_objects) if execution_status == "success" else 0
    print(f"Number of objects: {obj_count}")
    print("====")
    if obj_count > 0:
        # enumerated_objects might contain tuples of ints or hex strings
        for obj in enumerated_objects:
            print(obj)

if __name__ == "__main__":
    main()
