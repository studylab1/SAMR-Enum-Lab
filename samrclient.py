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
    openDomResp = samr.hSamrOpenDomain(dce, serverHandle, samr.DOMAIN_LOOKUP | samr.DOMAIN_LIST_ACCOUNTS, domainSidObj)
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
    try:
        enumAliasesResp = samr.hSamrEnumerateAliasesInDomain(dce, domainHandle)
        aliases = [(safe_str(a['Name']), a['RelativeId']) for a in enumAliasesResp['Buffer']['Buffer']]
    except Exception as e:
        if debug: print(f"[debug] Alias enumeration error: {str(e)}")
        aliases = []
    return [(safe_str(g['Name']), g['RelativeId']) for g in groups] + aliases

def enumerate_users_in_domain(dce, domainHandle, debug):
    log_debug(debug, "[debug] SamrEnumerateUsersInDomain -> enumerating users...")
    enumUsersResp = samr.hSamrEnumerateUsersInDomain(dce, domainHandle)
    if debug:
        print("[debug] SamrEnumerateUsersInDomain response dump:")
        print(enumUsersResp.dump())
    users = enumUsersResp['Buffer']['Buffer'] or []
    return [(safe_str(u['Name']), u['RelativeId']) for u in users]

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
    if sidUse == SID_NAME_ALIAS:
        log_debug(debug, "[debug] SamrOpenAlias -> local group/alias")
        openAliasResp = samr.hSamrOpenAlias(dce, domainHandle, samr.ALIAS_LIST_MEMBERS, groupRid)
        if debug:
            print("[debug] SamrOpenAlias response dump:")
            print(openAliasResp.dump())
        aliasHandle = openAliasResp['AliasHandle']
        membersResp = samr.hSamrGetMembersInAlias(dce, aliasHandle)
        if debug:
            print("[debug] SamrGetMembersInAlias response dump:")
            print(membersResp.dump())
        members = membersResp['Members']['Sids']
        samr.hSamrCloseHandle(dce, aliasHandle)
        results = [(m['SidPointer']['Data'].hex(), m['SidAttributes']) for m in members]
    elif sidUse in (SID_NAME_GROUP, SID_NAME_WKN_GRP):
        log_debug(debug, "[debug] SamrOpenGroup -> domain group")
        openGroupResp = samr.hSamrOpenGroup(dce, domainHandle, samr.GROUP_LIST_MEMBERS, groupRid)
        if debug:
            print("[debug] SamrOpenGroup response dump:")
            print(openGroupResp.dump())
        groupHandle = openGroupResp['GroupHandle']
        membersResp = samr.hSamrGetMembersInGroup(dce, groupHandle)
        if debug:
            print("[debug] SamrGetMembersInGroup response dump:")
            print(membersResp.dump())
        rids_list = [extract_ndr_value(rid) for rid in membersResp['Members']['Members']]
        samr.hSamrCloseHandle(dce, groupHandle)
        lookupResp = samr.hSamrLookupIdsInDomain(dce, domainHandle, rids_list)
        names = [safe_str(name['Data']) for name in lookupResp['Names']['Element']]
        results = [(names[i], rid) for i, rid in enumerate(rids_list)]
    else:
        raise Exception(f"Unsupported SID type: {sidUse}")
    return results, ["SamrLookupNamesInDomain", "SamrOpenGroup", "SamrGetMembersInGroup", "SamrLookupIdsInDomain"]

def main():
    args = parse_named_args(sys.argv)
    enumerate = args.get('enumerate', 'groups').lower()
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
        dce, serverHandle = samr_connect(server, username, password, domain, debug)
        opnums_called.append("SamrConnect")
        domainHandle, domainName, domainSidString = get_domain_handle(dce, serverHandle, debug)
        opnums_called.extend(["SamrEnumerateDomainsInSamServer", "SamrLookupDomainInSamServer", "SamrOpenDomain"])

        if enumerate == 'groups':
            enumerated_objects = enumerate_groups_in_domain(dce, domainHandle, debug)
            opnums_called.append("SamrEnumerateGroupsInDomain")
        elif enumerate == 'users':
            enumerated_objects = enumerate_users_in_domain(dce, domainHandle, debug)
            opnums_called.append("SamrEnumerateUsersInDomain")
        elif enumerate == 'group-members':
            if not groupName:
                raise Exception("group parameter required for group-members enumeration")
            enumerated_objects, additional_ops = list_group_members(dce, domainHandle, groupName, debug)
            opnums_called.extend(additional_ops)
        else:
            raise Exception(f"Unknown enumeration: {enumerate}")

    except Exception as e:
        execution_status = f"error: {repr(e)}"
    finally:
        for handle in [domainHandle, serverHandle]:
            if handle:
                try: samr.hSamrCloseHandle(dce, handle)
                except: pass
        if dce: dce.disconnect()

    duration = time.time() - start_time
    print(f"\nExecution time: {duration:.2f} seconds")
    print(f"Destination server: {server}")
    print(f"Domain SID: {domainSidString}")
    print(f"Account: {username}")
    print(f"Enumerate: {enumerate}")
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
