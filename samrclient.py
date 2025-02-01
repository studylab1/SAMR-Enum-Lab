#!/usr/bin/env python3

import sys
import time
from datetime import datetime
from impacket.dcerpc.v5 import transport, samr

# SID_NAME_USE local definitions
SID_NAME_USER = 1
SID_NAME_GROUP = 2
SID_NAME_DOMAIN = 3
SID_NAME_ALIAS = 4
SID_NAME_WKN_GRP = 5

###########################################################
# SAMR FUNCTION -> OPNUM MAPPING
# References from MS-SAMR specification
# (in decimal). Adjust if your Impacket build differs.
###########################################################
SAMR_FUNCTION_OPNUMS = {
    'SamrConnect': 0,
    'SamrCloseHandle': 1,
    'SamrEnumerateDomainsInSamServer': 6,
    'SamrLookupDomainInSamServer': 5,
    'SamrOpenDomain': 7,
    'SamrEnumerateGroupsInDomain': 11,
    'SamrEnumerateUsersInDomain': 13,
    'SamrEnumerateAliasesInDomain': 15,
    'SamrLookupNamesInDomain': 17,
    'SamrLookupIdsInDomain': 18,
    'SamrOpenGroup': 19,
    'SamrGetMembersInGroup': 25,
    'SamrOpenAlias': 27,
    'SamrGetMembersInAlias': 33,
}

def add_opnum_call(opnums_list, func_name):
    """
    Appends 'func_name (OpNum N)' to opnums_list
    if we have a known mapping, else just func_name.
    """
    opnum = SAMR_FUNCTION_OPNUMS.get(func_name)
    if opnum is not None:
        opnums_list.append(f"{func_name} (OpNum {opnum})")
    else:
        opnums_list.append(func_name)

def parse_named_args(argv):
    args = {}
    for item in argv[1:]:
        if '=' in item:
            key, val = item.split('=', 1)
            args[key.strip().lower()] = val.strip()
    return args

def log_debug(debug, message):
    if debug:
        print(message)

def extract_ndr_value(ndr_object):
    return ndr_object.fields['Data'] if hasattr(ndr_object, 'fields') else ndr_object

def safe_str(value):
    if isinstance(value, bytes):
        return value.decode('utf-16-le', errors='replace')
    return str(value)

def export_data(filename, fmt, data):
    if not filename or not data:
        return
    supported_formats = ['txt', 'csv', 'json']
    if fmt not in supported_formats:
        print(f"Error: Unsupported format '{fmt}'. Supported: {supported_formats}")
        return
    try:
        with open(filename, 'w') as f:
            if fmt == 'csv':
                import csv
                writer = csv.writer(f)
                writer.writerow(['Username', 'RID'])
                for item in data:
                    if isinstance(item, tuple) and len(item) >= 2:
                        writer.writerow([item[0], item[1]])
            elif fmt == 'json':
                import json
                json_data = []
                for item in data:
                    if isinstance(item, tuple) and len(item) >= 2:
                        json_data.append({'Username': item[0], 'RID': item[1]})
                json.dump(json_data, f, indent=2)
            elif fmt == 'txt':
                max_username_length = max(len(str(item[0])) for item in data) if data else 20
                header = f"{'Username':<{max_username_length}} RID"
                separator = "-" * (max_username_length + 5)
                f.write(f"{header}\n{separator}\n")
                for item in data:
                    if isinstance(item, tuple) and len(item) >= 2:
                        f.write(f"{item[0]:<{max_username_length}} {item[1]}\n")
        print(f"Data exported to {filename} ({fmt.upper()})")
    except Exception as e:
        print(f"Export failed: {str(e)}")

def samr_connect(server, username, password, domain, debug):
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
    connectResp = samr.hSamrConnect(dce, serverName=server, desiredAccess=0x00000031)
    if debug:
        print("[debug] SamrConnect response dump:")
        print(connectResp.dump())
    serverHandle = connectResp['ServerHandle']
    if connectResp['ErrorCode'] != 0:
        raise Exception(f"SamrConnect failed (NTSTATUS=0x{connectResp['ErrorCode']:X})")
    log_debug(debug, "[debug] SamrConnect succeeded.")
    return dce, serverHandle

def get_domain_handle(dce, serverHandle, debug):
    log_debug(debug, "[debug] SamrEnumerateDomainsInSamServer -> enumerating domains...")
    enumDomainsResp = samr.hSamrEnumerateDomainsInSamServer(dce, serverHandle)
    if debug:
        print("[debug] SamrEnumerateDomainsInSamServer response dump:")
        print(enumDomainsResp.dump())
    domains = enumDomainsResp['Buffer']['Buffer']
    if not domains:
        raise Exception("No domains found on server.")
    domainName = safe_str(domains[0]['Name'])
    log_debug(debug, f"[debug] Found domain: {domainName}")
    lookupResp = samr.hSamrLookupDomainInSamServer(dce, serverHandle, domainName)
    if debug:
        print("[debug] SamrLookupDomainInSamServer response dump:")
        print(lookupResp.dump())
    domainSidObj = lookupResp['DomainId']
    sidString = domainSidObj.formatCanonical()
    log_debug(debug, f"[debug] Domain SID: {sidString}")
    log_debug(debug, "[debug] SamrOpenDomain -> opening domain handle...")
    openDomResp = samr.hSamrOpenDomain(dce, serverHandle,
                                       samr.DOMAIN_LOOKUP | samr.DOMAIN_LIST_ACCOUNTS,
                                       domainSidObj)
    if debug:
        print("[debug] SamrOpenDomain response dump:")
        print(openDomResp.dump())
    domainHandle = openDomResp['DomainHandle']
    if openDomResp['ErrorCode'] != 0:
        raise Exception(f"SamrOpenDomain failed (NTSTATUS=0x{openDomResp['ErrorCode']:X})")
    log_debug(debug, "[debug] Domain opened successfully.")
    return domainHandle, domainName, sidString

def enumerate_groups_in_domain(dce, domainHandle, debug):
    log_debug(debug, "[debug] SamrEnumerateGroupsInDomain -> enumerating groups...")
    enumGroupsResp = samr.hSamrEnumerateGroupsInDomain(dce, domainHandle)
    if debug:
        print("[debug] SamrEnumerateGroupsInDomain response dump:")
        print(enumGroupsResp.dump())
    groups = enumGroupsResp['Buffer']['Buffer'] or []

    # We also attempt to enumerate aliases
    # so add this OpNum to the calls list for "groups" scanning
    # We'll let the calling code handle appending to opnums_called
    # but let's return a small note about it
    did_aliases = False

    try:
        enumAliasesResp = samr.hSamrEnumerateAliasesInDomain(dce, domainHandle)
        aliases = [(safe_str(a['Name']), a['RelativeId']) for a in enumAliasesResp['Buffer']['Buffer']]
        did_aliases = True
    except Exception as e:
        if debug:
            print(f"[debug] Alias enumeration error: {str(e)}")
        aliases = []

    return [(safe_str(g['Name']), g['RelativeId']) for g in groups] + aliases, did_aliases

def enumerate_users_in_domain(dce, domainHandle, debug):
    log_debug(debug, "[debug] SamrEnumerateUsersInDomain -> enumerating users...")
    users = []
    resumeHandle = 0  # We'll store 'EnumerationContext' here
    max_retries = 3
    retry_count = 0

    while True:
        try:
            # Fetch one "batch" of users
            enumUsersResp = samr.hSamrEnumerateUsersInDomain(
                dce,
                domainHandle,
                enumerationContext=resumeHandle,
                userAccountControl=samr.USER_NORMAL_ACCOUNT
            )
            retry_count = 0  # reset retries on success

        except samr.DCERPCSessionError as e:
            if e.get_error_code() == 0x00000105:  # STATUS_MORE_ENTRIES
                # If Impacket raises an exception with partial data, fetch it
                enumUsersResp = e.get_packet()
                retry_count = 0
            elif e.get_error_code() == 0xC000009A:  # STATUS_INSUFFICIENT_RESOURCES
                log_debug(debug, "[debug] Server busy, retrying after delay...")
                time.sleep(2)
                retry_count += 1
                if retry_count > max_retries:
                    raise Exception("Server resource limit reached after retries")
                continue
            else:
                raise

        # Process the chunk
        userChunk = enumUsersResp['Buffer']['Buffer'] or []
        for userEntry in userChunk:
            username = safe_str(userEntry['Name'])
            rid = userEntry['RelativeId']
            users.append((username, rid))

        # The key is named 'EnumerationContext', not 'ResumeHandle'
        resumeHandle = enumUsersResp['EnumerationContext']

        # If the server did not return STATUS_MORE_ENTRIES (0x105), we're done
        if enumUsersResp['ErrorCode'] != 0x00000105:
            break

        time.sleep(0.1)

    return users

def list_group_members(dce, domainHandle, groupName, debug):
    log_debug(debug, f"[debug] SamrLookupNamesInDomain -> looking up group: {groupName}")
    lookupResp = samr.hSamrLookupNamesInDomain(dce, domainHandle, [groupName])
    if debug:
        print("[debug-lookupResp] SamrLookupNamesInDomain response dump:")
        print(lookupResp.dump())
    rids = lookupResp['RelativeIds']['Element']
    uses = lookupResp['Use']['Element']
    if not rids or not uses:
        raise Exception(f"No mapped result for '{groupName}'")
    groupRid = extract_ndr_value(rids[0])
    sidUse = extract_ndr_value(uses[0])
    results = []
    additional_ops = ["SamrLookupNamesInDomain"]

    if sidUse == SID_NAME_ALIAS:
        log_debug(debug, "[debug] SamrOpenAlias -> local group/alias")
        additional_ops.append("SamrOpenAlias")
        openAliasResp = samr.hSamrOpenAlias(dce, domainHandle, samr.ALIAS_LIST_MEMBERS, groupRid)
        if debug:
            print("[debug] SamrOpenAlias response dump:")
            print(openAliasResp.dump())

        aliasHandle = openAliasResp['AliasHandle']
        additional_ops.append("SamrGetMembersInAlias")
        membersResp = samr.hSamrGetMembersInAlias(dce, aliasHandle)
        if debug:
            print("[debug] SamrGetMembersInAlias response dump:")
            print(membersResp.dump())

        members = membersResp['Members']['Sids']
        samr.hSamrCloseHandle(dce, aliasHandle)
        additional_ops.append("SamrCloseHandle")  # closed alias handle

        results = [(m['SidPointer']['Data'].hex(), m['SidAttributes']) for m in members]

    elif sidUse in (SID_NAME_GROUP, SID_NAME_WKN_GRP):
        log_debug(debug, "[debug] SamrOpenGroup -> domain group")
        additional_ops.append("SamrOpenGroup")
        openGroupResp = samr.hSamrOpenGroup(dce, domainHandle, samr.GROUP_LIST_MEMBERS, groupRid)
        if debug:
            print("[debug] SamrOpenGroup response dump:")
            print(openGroupResp.dump())

        groupHandle = openGroupResp['GroupHandle']
        additional_ops.append("SamrGetMembersInGroup")
        membersResp = samr.hSamrGetMembersInGroup(dce, groupHandle)
        if debug:
            print("[debug] SamrGetMembersInGroup response dump:")
            print(membersResp.dump())

        rids_list = [extract_ndr_value(rid) for rid in membersResp['Members']['Members']]
        samr.hSamrCloseHandle(dce, groupHandle)
        additional_ops.append("SamrCloseHandle")  # closed group handle

        additional_ops.append("SamrLookupIdsInDomain")
        lookupResp = samr.hSamrLookupIdsInDomain(dce, domainHandle, rids_list)
        names = [safe_str(name['Data']) for name in lookupResp['Names']['Element']]
        results = [(names[i], rid) for i, rid in enumerate(rids_list)]
    else:
        raise Exception(f"Unsupported SID type: {sidUse}")

    return results, additional_ops

def main():
    args = parse_named_args(sys.argv)
    enumeration = args.get('enumerate', 'groups').lower()
    server = args.get('server', '')
    username = args.get('username', '')
    password = args.get('password', '')
    domain = args.get('domain', '')
    groupName = args.get('group', '')
    debug = args.get('debug', 'false').lower() == 'true'
    export_file = args.get('export', '')
    export_format = args.get('format', 'txt').lower()

    if not server or not username or not password:
        print("Usage:\n  python samrclient.py enumerate=groups server=ydc1.domain-y.local"
              " username=enum password=LabAdm1! [domain=domain-y.local] [group=MyGroup]"
              " [debug=true] [export=output.txt] [format=txt|csv|json]")
        sys.exit(1)

    start_time = time.time()
    start_timestamp = datetime.now()
    print(f"Execution started at: {start_timestamp}")

    opnums_called = []
    dce = serverHandle = domainHandle = None
    domainSidString = ""
    enumerated_objects = []
    execution_status = "success"

    try:
        # SamrConnect
        dce, serverHandle = samr_connect(server, username, password, domain, debug)
        add_opnum_call(opnums_called, "SamrConnect")

        # SamrEnumerateDomainsInSamServer, SamrLookupDomainInSamServer, SamrOpenDomain
        domainHandle, domainName, domainSidString = get_domain_handle(dce, serverHandle, debug)
        add_opnum_call(opnums_called, "SamrEnumerateDomainsInSamServer")
        add_opnum_call(opnums_called, "SamrLookupDomainInSamServer")
        add_opnum_call(opnums_called, "SamrOpenDomain")

        if enumeration == 'groups':
            # SamrEnumerateGroupsInDomain
            groups_result, did_aliases = enumerate_groups_in_domain(dce, domainHandle, debug)
            add_opnum_call(opnums_called, "SamrEnumerateGroupsInDomain")
            if did_aliases:
                # SamrEnumerateAliasesInDomain also was called
                add_opnum_call(opnums_called, "SamrEnumerateAliasesInDomain")
            enumerated_objects = groups_result

        elif enumeration == 'users':
            # SamrEnumerateUsersInDomain
            enumerated_objects = enumerate_users_in_domain(dce, domainHandle, debug)
            add_opnum_call(opnums_called, "SamrEnumerateUsersInDomain")

        elif enumeration == 'group-members':
            if not groupName:
                raise Exception("group parameter required for group-members enumeration")
            # This returns the result plus additional_ops (list of calls made)
            enumerated_objects, additional_ops = list_group_members(dce, domainHandle, groupName, debug)
            for op_name in additional_ops:
                add_opnum_call(opnums_called, op_name)

        else:
            raise Exception(f"Unknown enumeration: {enumeration}")

    except Exception as e:
        execution_status = f"error: {repr(e)}"
    finally:
        # SamrCloseHandle calls
        for handle in [domainHandle, serverHandle]:
            if handle:
                try:
                    samr.hSamrCloseHandle(dce, handle)
                    add_opnum_call(opnums_called, "SamrCloseHandle")
                except:
                    pass
        if dce:
            dce.disconnect()

    duration = time.time() - start_time
    print(f"\nExecution time: {duration:.2f} seconds")
    print(f"Destination server: {server}")
    print(f"Domain SID: {domainSidString}")
    print(f"Account: {username}")
    print(f"Enumerate: {enumeration}")
    print(f"OpNums called: {', '.join(opnums_called)}")
    print(f"Execution status: {execution_status}")
    print(f"Number of objects: {len(enumerated_objects) if execution_status == 'success' else 0}")
    print("====")

    if enumerated_objects and execution_status == "success":
        max_username_length = max(len(str(obj[0])) for obj in enumerated_objects) if enumerated_objects else 20
        print(f"{'Username':<{max_username_length}} RID")
        print("-" * (max_username_length + 5))
        for obj in enumerated_objects:
            if isinstance(obj, tuple) and len(obj) >= 2:
                print(f"{obj[0]:<{max_username_length}} {obj[1]}")

    if export_file and execution_status == "success" and enumerated_objects:
        export_data(export_file, export_format, enumerated_objects)

if __name__ == "__main__":
    main()
