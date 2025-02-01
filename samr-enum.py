#!/usr/bin/env python3
"""
samr-enum.py
A Python tool to enumerate domain accounts and groups via the Microsoft
SAMR interface (using Impacket). Supports enumerating domain users,
groups, and group members, optionally exporting the results in various
formats (TXT, CSV, JSON).

Usage Examples:
  python samr-enum.py enumerate=users server=dc1.company.local username=someuser password=somepass
  python samr-enum.py enumerate=groups server=dc1.company.local username=someuser password=somepass
  python samr-enum.py enumerate=group-members server=dc1.company.local username=someuser password=somepass group="Domain Admins"

Now also supports:
  - auth=kerberos  (defaults to NTLM)
  - prompting for password if 'password=' is empty (hidden entry)
  
Use 'help=true' or run "python samr-enum.py help" for a short help message.
"""

import sys
import time
import getpass
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
# Official reference from MS-SAMR specification (decimal).
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

###########################################################
# SAMR FUNCTION -> ACCESS MASK
# We only track calls that actually specify a desiredAccess
# in your code. Others show no Access Mask.
###########################################################
SAMR_FUNCTION_ACCESS = {
    'SamrConnect':     0x00000031,  # desiredAccess=0x31
    'SamrOpenDomain':  0x00000300,  # DOMAIN_LOOKUP | DOMAIN_LIST_ACCOUNTS
    'SamrOpenGroup':   0x00000010,  # GROUP_LIST_MEMBERS
    'SamrOpenAlias':   0x00000004,  # ALIAS_LIST_MEMBERS
}


def add_opnum_call(opnums_list, func_name):
    """
    Append the given SAMR function name, its OpNum, and (if relevant) the Access Mask
    to the tracking list, with the Access Mask inside the parentheses.
    """
    opnum = SAMR_FUNCTION_OPNUMS.get(func_name)
    access_val = SAMR_FUNCTION_ACCESS.get(func_name)

    if opnum is not None and access_val is not None:
        # Both an OpNum and an Access Mask
        opnums_list.append(f"{func_name} (OpNum {opnum}, Access Mask: 0x{access_val:08X})")
    elif opnum is not None:
        # Only an OpNum
        opnums_list.append(f"{func_name} (OpNum {opnum})")
    else:
        # Neither OpNum nor Access Mask is known
        opnums_list.append(func_name)


def parse_named_args(argv):
    """
    Parse named arguments of the form key=value from the command line.

    :param argv: sys.argv or similar list of command-line tokens
    :return: dict mapping lowercase key -> string value
    Example: python samr-enum.py server=server1 user=admin password=pass123
    """
    args = {}
    for item in argv[1:]:
        if '=' in item:
            key, val = item.split('=', 1)
            args[key.strip().lower()] = val.strip()
    return args


def print_help():
    """
    Print a short help/description about the script usage,
    then exit.
    """
    print("samr-enum.py - A tool to enumerate domain users and groups via SAMR.")
    print("Example usage:")
    print("  python samr-enum.py enumerate=users server=dc1.company.local username=someuser password=somepass")
    print("Optional arguments:")
    print("  domain=<DOMAIN>      The domain for the user credentials (for NTLM or Kerberos)")
    print("  group=<GroupName>    Required only if enumerate=group-members")
    print("  debug=true           Show debug details of the SAMR calls")
    print("  export=<filename>    Export the data (default format=txt, can do format=csv,json)")
    print("  auth=kerberos        Use Kerberos instead of NTLM (default=NTLM)")
    print("If 'password=' is empty, the program will prompt you securely.")
    sys.exit(0)


def log_debug(debug, message):
    """
    Print debugging messages if debug is True.

    :param debug: Boolean indicating whether to print debug info
    :param message: The message to print
    """
    if debug:
        print(message)


def extract_ndr_value(ndr_object):
    """
    Extract the integer value from an impacket NDR object (e.g. NDRULONG).
    Returns the input if it doesn't have 'fields' / 'Data'.

    :param ndr_object: Impacket NDR object or plain int
    :return: The integer or the original value
    """
    return ndr_object.fields['Data'] if hasattr(ndr_object, 'fields') else ndr_object


def safe_str(value):
    """
    Convert the given value to a string, decoding UTF-16-LE bytes if needed.

    :param value: Possibly a bytes object (UTF-16-LE) or already a string
    :return: Proper Python string
    """
    if isinstance(value, bytes):
        return value.decode('utf-16-le', errors='replace')
    return str(value)


def export_data(filename, fmt, data):
    """
    Export enumerated data (list of (username, rid) tuples) into a file.

    :param filename: The output filename
    :param fmt: One of 'txt', 'csv', or 'json'
    :param data: The list of (username, rid) pairs to write
    """
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


def samr_connect(server, username, password, domain, debug, auth_mode):
    """
    Connect to \\pipe\\samr on the remote server and return (dce, serverHandle).
    If auth_mode=='kerberos', sets Kerberos = True in the transport.

    desiredAccess=0x00000031 for SamrConnect

    :param server: Hostname or IP of the remote server
    :param username: The username for authentication
    :param password: The password for authentication (could be empty, then user is prompted)
    :param domain: The domain of the user (can be blank if not needed)
    :param debug: Boolean indicating debug output
    :param auth_mode: "kerberos" or "ntlm" (default)
    :return: (dce, serverHandle)
    """
    binding_str = rf"ncacn_np:{server}[\pipe\samr]"
    log_debug(debug, f"[debug] Using binding string: {binding_str}")
    rpc_transport = transport.DCERPCTransportFactory(binding_str)

    # If auth=kerberos, set Kerberos usage on the transport
    if auth_mode.lower() == 'kerberos':
        log_debug(debug, "[debug] Setting Kerberos auth on the transport.")
        rpc_transport.set_kerberos(True)
    else:
        log_debug(debug, "[debug] Using NTLM (default).")

    rpc_transport.set_credentials(username, password, domain=domain)

    dce = rpc_transport.get_dce_rpc()
    log_debug(debug, f"[debug] Connecting to {server} via SMB (auth={auth_mode})...")
    dce.connect()

    log_debug(debug, "[debug] Binding to SAMR interface (MSRPC_UUID_SAMR)...")
    dce.bind(samr.MSRPC_UUID_SAMR)

    log_debug(debug, "[debug] Calling SamrConnect...")
    connectResp = samr.hSamrConnect(dce, serverName=server, desiredAccess=0x00000031)

    if debug:
        print("[debug] SamrConnect response dump:")
        print(connectResp.dump())

    if connectResp['ErrorCode'] != 0:
        raise Exception(f"SamrConnect failed (NTSTATUS=0x{connectResp['ErrorCode']:X})")

    serverHandle = connectResp['ServerHandle']
    log_debug(debug, "[debug] SamrConnect succeeded.")
    return dce, serverHandle


def get_domain_handle(dce, serverHandle, debug):
    """
    Enumerate the first domain from SamrEnumerateDomainsInSamServer,
    look up the domain SID, and open the domain handle.
    SamrOpenDomain uses desiredAccess=0x00000300
    (DOMAIN_LOOKUP | DOMAIN_LIST_ACCOUNTS).

    :param dce: The DCE/RPC connection object
    :param serverHandle: The handle to the SAMR server
    :param debug: Boolean indicating debug output
    :return: (domainHandle, domainName, sidString)
    """
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
    openDomResp = samr.hSamrOpenDomain(
        dce,
        serverHandle,
        samr.DOMAIN_LOOKUP | samr.DOMAIN_LIST_ACCOUNTS,
        domainSidObj
    )
    if debug:
        print("[debug] SamrOpenDomain response dump:")
        print(openDomResp.dump())

    if openDomResp['ErrorCode'] != 0:
        raise Exception(f"SamrOpenDomain failed (NTSTATUS=0x{openDomResp['ErrorCode']:X})")

    domainHandle = openDomResp['DomainHandle']
    log_debug(debug, "[debug] Domain opened successfully.")
    return domainHandle, domainName, sidString


def enumerate_groups_in_domain(dce, domainHandle, debug):
    """
    Enumerate domain groups plus attempt to enumerate domain aliases.

    :param dce: The DCE/RPC connection
    :param domainHandle: Handle to the opened domain
    :param debug: Boolean indicating debug output
    :return: (list_of_groups_plus_aliases, did_aliases_bool)
    """
    log_debug(debug, "[debug] SamrEnumerateGroupsInDomain -> enumerating groups...")
    enumGroupsResp = samr.hSamrEnumerateGroupsInDomain(dce, domainHandle)
    if debug:
        print("[debug] SamrEnumerateGroupsInDomain response dump:")
        print(enumGroupsResp.dump())

    groups = enumGroupsResp['Buffer']['Buffer'] or []
    did_aliases = False

    try:
        enumAliasesResp = samr.hSamrEnumerateAliasesInDomain(dce, domainHandle)
        aliases = [(safe_str(a['Name']), a['RelativeId'])
                   for a in enumAliasesResp['Buffer']['Buffer']]
        did_aliases = True
    except Exception as e:
        if debug:
            print(f"[debug] Alias enumeration error: {str(e)}")
        aliases = []

    group_tuples = [(safe_str(g['Name']), g['RelativeId']) for g in groups]
    return group_tuples + aliases, did_aliases


def enumerate_users_in_domain(dce, domainHandle, debug):
    """
    Enumerate all domain users by repeatedly calling SamrEnumerateUsersInDomain
    until the server no longer returns STATUS_MORE_ENTRIES.

    :param dce: The DCE/RPC connection
    :param domainHandle: The opened domain handle
    :param debug: Boolean for debug prints
    :return: A list of (username, rid) tuples
    """
    log_debug(debug, "[debug] SamrEnumerateUsersInDomain -> enumerating users...")
    users = []
    resumeHandle = 0
    max_retries = 3
    retry_count = 0

    while True:
        try:
            enumUsersResp = samr.hSamrEnumerateUsersInDomain(
                dce,
                domainHandle,
                enumerationContext=resumeHandle,
                userAccountControl=samr.USER_NORMAL_ACCOUNT
            )
            retry_count = 0

        except samr.DCERPCSessionError as e:
            if e.get_error_code() == 0x00000105:  # STATUS_MORE_ENTRIES
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

        chunk = enumUsersResp['Buffer']['Buffer'] or []
        for userEntry in chunk:
            username = safe_str(userEntry['Name'])
            rid = userEntry['RelativeId']
            users.append((username, rid))

        resumeHandle = enumUsersResp['EnumerationContext']
        if enumUsersResp['ErrorCode'] != 0x00000105:
            break
        time.sleep(0.1)

    return users


def list_group_members(dce, domainHandle, groupName, debug):
    """
    Enumerate members of a group (alias or domain group).
    If domain group, also map RIDs to account names.

    For alias: SamrOpenAlias uses Access=0x00000004
    For domain group: SamrOpenGroup uses Access=0x00000010

    :param dce: The DCE/RPC connection
    :param domainHandle: The opened domain handle
    :param groupName: Name of the group
    :param debug: Boolean for debug prints
    :return: (list_of_members, additional_ops_list)
    """
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

    if sidUse == samr.SID_NAME_ALIAS:
        log_debug(debug, "[debug] SamrOpenAlias -> local group/alias")
        additional_ops.append("SamrOpenAlias")
        openAliasResp = samr.hSamrOpenAlias(dce, domainHandle,
                                            samr.ALIAS_LIST_MEMBERS, groupRid)
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

    elif sidUse in (samr.SID_NAME_GROUP, samr.SID_NAME_WKN_GRP):
        log_debug(debug, "[debug] SamrOpenGroup -> domain group")
        additional_ops.append("SamrOpenGroup")
        openGroupResp = samr.hSamrOpenGroup(dce, domainHandle,
                                            samr.GROUP_LIST_MEMBERS, groupRid)
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
    """
    Main entry point for the SAMR enumeration script.
    Parses arguments, performs the requested enumeration,
    prints the results, and optionally exports them.
    """
    # Basic "help" check
    if len(sys.argv) > 1:
        # e.g. "python samr-enum.py help" or "python samr-enum.py help=whatever"
        first_arg = sys.argv[1].lower()
        if first_arg == "help" or "help" in first_arg:
            print_help()

    # If no args given, print usage
    if len(sys.argv) == 1:
        print("Usage:\n  python samr-enum.py enumerate=groups server=dc1.domain-a.local"
              " username=user123 password=Password123 [domain=domain-b.local] [group=MyGroup]"
              " [debug=true] [export=output.txt [format=txt|csv|json]] [auth=kerberos]")
        sys.exit(1)

    args = parse_named_args(sys.argv)
    if args.get('help', 'false').lower() == 'true':
        print_help()

    enumeration = args.get('enumerate', 'groups').lower()
    server = args.get('server', '')
    username = args.get('username', '')
    password = args.get('password', '')  # might be empty -> prompt
    domain = args.get('domain', '')
    groupName = args.get('group', '')
    debug = args.get('debug', 'false').lower() == 'true'
    export_file = args.get('export', '')
    export_format = args.get('format', 'txt').lower()
    auth_mode = args.get('auth', 'ntlm').lower()  # "kerberos" or "ntlm" default

    # If password is empty, prompt user. getpass hides the input on CLI
    if password == '':
        password = getpass.getpass(prompt="Enter password (hidden): ")

    # If required parameters are missing, show usage
    if not server or not username:
        print("Usage:\n  python samr-enum.py enumerate=groups server=dc1.domain-a.local"
              " username=user123 password=Password123 [domain=domain-b.local] [group=MyGroup]"
              " [debug=true] [export=output.txt [format=txt|csv|json]] [auth=kerberos]")
        sys.exit(1)

    start_time = time.time()
    start_timestamp = datetime.now()
    print(f"Execution started at: {start_timestamp}")

    opnums_called = []
    dce = None
    serverHandle = None
    domainHandle = None
    domainSidString = ""
    enumerated_objects = []
    execution_status = "success"

    try:
        # SamrConnect (with possible Kerberos, password prompt, etc.)
        dce, serverHandle = samr_connect(server, username, password,
                                         domain, debug, auth_mode)
        add_opnum_call(opnums_called, "SamrConnect")

        # SamrEnumerateDomainsInSamServer, SamrLookupDomainInSamServer, SamrOpenDomain
        domainHandle, domainName, domainSidString = get_domain_handle(dce,
                                                                      serverHandle,
                                                                      debug)
        add_opnum_call(opnums_called, "SamrEnumerateDomainsInSamServer")
        add_opnum_call(opnums_called, "SamrLookupDomainInSamServer")
        add_opnum_call(opnums_called, "SamrOpenDomain")

        # Figure out which operation is requested
        if enumeration == 'groups':
            # SamrEnumerateGroupsInDomain
            groups_result, did_aliases = enumerate_groups_in_domain(dce,
                                                                    domainHandle,
                                                                    debug)
            add_opnum_call(opnums_called, "SamrEnumerateGroupsInDomain")
            if did_aliases:
                add_opnum_call(opnums_called, "SamrEnumerateAliasesInDomain")
            enumerated_objects = groups_result

        elif enumeration == 'users':
            enumerated_objects = enumerate_users_in_domain(dce, domainHandle, debug)
            add_opnum_call(opnums_called, "SamrEnumerateUsersInDomain")

        elif enumeration == 'group-members':
            if not groupName:
                raise Exception("group parameter required for group-members enumeration.")
            enumerated_objects, additional_ops = list_group_members(
                dce,
                domainHandle,
                groupName,
                debug
            )
            for op_name in additional_ops:
                add_opnum_call(opnums_called, op_name)

        else:
            raise Exception(f"Unknown enumeration: {enumeration}")

    except Exception as e:
        execution_status = f"error: {repr(e)}"

    finally:
        # SamrCloseHandle calls (no explicit Access Mask)
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
    print(f"Authentication: {auth_mode.upper()}")
    print(f"OpNums called: {', '.join(opnums_called)}")
    print(f"Execution status: {execution_status}")
    print(f"Number of objects: {len(enumerated_objects) if execution_status == 'success' else 0}")
    print("====")

    if enumerated_objects and execution_status == "success":
        max_username_length = max(len(str(obj[0])) for obj in enumerated_objects) \
            if enumerated_objects else 20
        print(f"{'Username':<{max_username_length}} RID")
        print("-" * (max_username_length + 5))
        for obj in enumerated_objects:
            if isinstance(obj, tuple) and len(obj) >= 2:
                print(f"{obj[0]:<{max_username_length}} {obj[1]}")

    # Optionally export data
    if export_file and execution_status == "success" and enumerated_objects:
        export_data(export_file, export_format, enumerated_objects)


if __name__ == "__main__":
    main()
