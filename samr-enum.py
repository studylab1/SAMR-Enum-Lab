#!/usr/bin/env python3
"""
samr-enum.py - A SAMR Enumeration Tool using Impacket
Copyright (c) 2025. Licensed under the MIT License.

This Python tool leverages the Microsoft SAMR protocol to enumerate domain
users, groups, computers, password policies, and other account-related information
from a target system. It supports both NTLM (default) and Kerberos authentication,
and can optionally export results in various formats (TXT, CSV, JSON).

Features:
  - Enumerate domain users, local groups, domain groups, and more.
  - Display detailed debug output for SAMR calls.
  - Securely prompt for a password if none is provided.
  - Export enumeration results in multiple formats.
  - Supports NTLM (default) and Kerberos authentication.

Usage:
    samr-enum.py <OPTIONS> <ENUMERATION PARAMETER> [ENUMERATION PARAMETER OPTIONS]

Required OPTIONS:
  target            Target system (IP address or hostname).
  username          Username used for authentication on the remote server.
  password          Password for authentication. If empty (i.e., password=), the tool will securely prompt for it.
  enumerate         The enumeration type. See the ENUMERATION PARAMETERS section below.

Optional OPTIONS:
  domain            Domain of the user for authentication (required if using Kerberos).
  auth              Authentication protocol. Acceptable values: 'ntlm' (default) or 'kerberos'.
  debug             Display debug details of the SAMR calls. Acceptable values: 'true' or 'false' (default: 'false').
  export            Export the data. Acceptable values: 'txt' (default), 'csv', or 'json'.
    format          Acceptable values are 'txt', 'csv' or 'json', with the default being 'txt'.
  opnums            Set to 'true' to display SAMR OpNums in output (default: 'false').
  help              Print help page.

ENUMERATION PARAMETERS:
  The following parameters control what to enumerate. Provide one of these (omitting the "enumerate=" prefix)
  along with any required options:

    users
         List all user accounts.

    computers
         List all computer accounts.

    local-groups
         List all local groups.

    domain-groups
         List all domain groups.

    local-group-members group=<GROUP>
         List all members of a local group. (Parameter option: group)

    domain-group-members group=<GROUP>
         List all members of a domain group. (Parameter option: group)

    user-memberships-localgroups
         List all local groups that a user is a member of. (Parameter option: user)

    user-memberships-domaingroups
         List all domain groups that a user is a member of. (Parameter option: user)

    account-details user=<USERNAME/RID>
         Display account details for a specific user (by username or RID). (Parameter option: user)

    local-group-details group=<GROUP>
         Display local/builtin group details. (Parameter option: group)

    domain-group-details group=<GROUP>
         Display domain group details. (Parameter option: group)




    display-info
         List all objects with additional descriptive fields. (Parameter option: 'type' with values 'users', 'domain-groups', 'local-groups', 'computers')

    account-details user=<USERNAME/RID>
         Display account details for a specific user (by username or RID). (Parameter option: user)

    password-policy
         Display the password policy.

    lockout-policy
         Display the account lockout policy.

    summary
        Display a summary report for the domain. The summary includes:
           - Domain Information (name, SID, etc.)
           - Total number of user accounts
           - Total number of computer accounts
           - Total number of domain groups
           - Total number of local groups (aliases)
           - Password policy details
           - Lockout policy details

Usage Examples:
  python samr-enum.py target=192.168.1.1 username=micky password=mouse123 enumerate=users
  python samr-enum.py target=192.168.1.1 username=micky password=mouse123 enumerate=computers
  python samr-enum.py target=dc1.domain-a.local username=micky password=mouse123 enumerate=local-groups export=export.csv format=csv
  python samr-enum.py target=dc1.domain-a.local username=micky password=mouse123 enumerate=domain-groups opnums=true
  python samr-enum.py target=192.168.1.1 username=micky password=mouse123 enumerate=local-group-members group="Administrators"
  python samr-enum.py target=192.168.1.1 username=micky password=mouse123 enumerate=domain-group-members group="Domain Admins"
  python samr-enum.py target=192.168.1.1 username=micky password=mouse123 enumerate=user-memberships-localgroups user=Administrator
  python samr-enum.py target=192.168.1.1 username=micky password=mouse123 enumerate=user-memberships-domaingroups user=Administrator
  python samr-enum.py target=192.168.1.1 username=micky password=mouse123 enumerate=account-details user=Administrator
  python samr-enum.py target=192.168.1.1 username=micky password=mouse123 enumerate=local-group-details group="Administrators"
  python samr-enum.py target=192.168.1.1 username=micky password=mouse123 enumerate=domain-group-details group="Domain Admins"


  python samr-enum.py target=192.168.1.1 username=micky password=mouse123 enumerate=account-details user=john-doe debug=true
  python samr-enum.py target=dc1.domain-a.com username=micky password= auth=kerberos domain=domain-y.local enumerate=password-policy
  python samr-enum.py target=dc1.domain-a.com username=micky password=mouse123 enumerate=lockout-policy
  python samr-enum.py target=192.168.1.1 username=micky password=mouse123 enumerate=user-memberships-domaingroups user=Administrator
  python samr-enum.py target=192.168.1.1 username=micky password=mouse123 enumerate=display-info type=users
  python samr-enum.py target=192.168.1.1 username=micky password=mouse123 enumerate=display-info type=domain-groups
  python samr-enum.py target=192.168.1.1 username=micky password=mouse123 enumerate=summary

For help, run:
    samr-enum.py help

Additional Notes:
  - This tool requires the Impacket libraries.
  - Ensure you have the appropriate privileges to perform enumeration tasks.
  - Report bugs or contribute to the project at the official repository: https://github.com/studylab1/SAMR-Enum-Lab
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
    'SamrOpenUser': 34,
    'SamrGetGroupsForUser': 39,
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
    'SamrQueryInformationUser': 36,
    'SamrQueryInformationDomain2': 46,
    'SamrQueryInformationUser2': 47,
}

###########################################################
# SAMR FUNCTION -> ACCESS MASK
# We only track calls that actually specify a desiredAccess
# in your code. Others show no Access Mask.
###########################################################
SAMR_FUNCTION_ACCESS = {
    'SamrOpenUser': 0x0002011b,  # USER_LIST_GROUPS
    'SamrConnect': 0x00000031,  # desiredAccess=0x31
    'SamrOpenDomain': 0x00000300,  # DOMAIN_LOOKUP | DOMAIN_LIST_ACCOUNTS
    'SamrOpenGroup': 0x00000010,  # GROUP_LIST_MEMBERS
    'SamrOpenAlias': 0x00000004,  # ALIAS_LIST_MEMBERS
}


def add_opnum_call(opnums_list, func_name, actual_access=None):
    """
    Append the given SAMR function name, its OpNum, and (if relevant) the Access Mask
    to the tracking list, with the Access Mask inside the parentheses.
    """
    opnum = SAMR_FUNCTION_OPNUMS.get(func_name)
    if opnum is not None:
        if actual_access is not None:
            # Show the *actual* Access Mask if provided
            opnums_list.append(f"{func_name} (OpNum {opnum}, Access Mask: 0x{actual_access:08X})")
        else:
            # Fall back to the old dictionary-based Access Mask
            access_val = SAMR_FUNCTION_ACCESS.get(func_name)
            if access_val is not None:
                opnums_list.append(f"{func_name} (OpNum {opnum}, Access Mask: 0x{access_val:08X})")
            else:
                opnums_list.append(f"{func_name} (OpNum {opnum})")
    else:
        # Neither OpNum nor Access is known
        opnums_list.append(func_name)


def format_time(filetime_64):
    """
    Convert a 64-bit Windows FILETIME (100-ns intervals since 1601-01-01)
    into a human-readable string. Returns 'Never' if 0 or 0x7FFFFFFFFFFFFFFF.
    """
    if filetime_64 == 0 or filetime_64 == 0x7FFFFFFFFFFFFFFF:
        return 'Never'
    try:
        # FILETIME is in 100-nanosecond increments, offset from 1601-01-01
        # Convert to seconds from 1970-01-01 by subtracting the Windows->Unix epoch offset
        seconds = filetime_64 / 10000000.0 - 11644473600
        dt = datetime.utcfromtimestamp(seconds)
        return dt.strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        return 'Invalid timestamp'


def to_int_uac(uac_value):
    """
    Safely convert a UserAccountControl (NDRULONG or int) into a Python integer.
    """
    if not uac_value:
        return 0
    # If it's already a plain Python int, return it as-is.
    if isinstance(uac_value, int):
        return uac_value
    # If it's an NDR object with a 'fields' dict, we can extract the 'Data'.
    if hasattr(uac_value, 'fields') and 'Data' in uac_value.fields:
        return uac_value.fields['Data']
    # If it's bytes (unlikely for UAC but let's be safe), convert from little-endian.
    if isinstance(uac_value, bytes):
        return int.from_bytes(uac_value, byteorder='little')
    return 0


def decode_filetime(value):
    """
    Convert an Impacket OLD_LARGE_INTEGER (with HighPart/LowPart) into
    a 64-bit Windows FILETIME integer.
    Returns 0 if value is None or missing fields.
    """
    if not value or not hasattr(value, 'fields'):
        return 0

    # Extract the NDR values from HighPart and LowPart
    high_part_ndr = value.fields['HighPart']
    low_part_ndr = value.fields['LowPart']

    high_part_int = extract_ndr_value(high_part_ndr)  # becomes plain int
    low_part_int = extract_ndr_value(low_part_ndr)    # becomes plain int

    # Combine them into a 64-bit integer
    return (high_part_int << 32) | (low_part_int & 0xFFFFFFFF)


def parse_named_args(argv):
    """
    Parse named arguments of the form key=value from the command line.

    :param argv: sys.argv or similar list of command-line tokens
    :return: dict mapping lowercase key -> string value
    Example: python samr-enum.py target=server1 user=admin password=pass123
    """
    args = {}
    for item in argv[1:]:
        if '=' in item:
            key, val = item.split('=', 1)
            args[key.strip().lower()] = val.strip()
    return args


def print_help():
    """
    Print a short help/description about the script usage, then exit.
    """

    help_text = r"""
    samr-enum.py - A tool for enumerating domain users, groups, computers, password policies, and other information via SAMR protocol.

    Usage: samr-enum.py <OPTIONS> <ENUMERATION PARAMETER> [ENUMERATION PARAMETER OPTIONS]

    This tool performs various enumerations on a target system.

    Required OPTIONS:
      target            Target system (IP address or hostname).
      username          Username which will be used to authenticate on remote server.
      password          if an empty value is provided (i.e., password= with nothing following), the tool will securely prompt the user for a password.
      enumerate         The enumeration type. Details are in 'Enumeration Parameters' section below.

    Optional OPTIONS:
      domain            Domain of the user to authenticate. It is required if Kerberos authentication is used.
      auth              Authentication protocol. Acceptable values are 'ntlm' or 'kerberos', with the default being 'ntlm'.
      debug             Display debug details of the SAMR calls. Acceptable values are 'true' or 'false', with the default being 'false'.
      export            Export data to a specified file.
        format          Acceptable values are 'txt', 'csv' or 'json', with the default being 'txt'.
      opnums            Set to 'true' to display SAMR OpNums called (default: 'false').
      help              Print this page.


    ENUMERATION PARAMETERS:
      The following parameters control what to enumerate. Simply supply one of these (omitting the "enumerate=" prefix)
      along with any required options.

        users
             List all user accounts.

        local-groups
             List all local groups.

        computers
             List all computer accounts.

        domain-groups
             List all domain groups.

        local-group-members group=<GROUP>
             List all members of the local group. PARAMETER OPTION = 'group'

        domain-group-members group=<GROUP>
             List all members of the domain group. PARAMETER OPTION = 'group'

        user-memberships-domaingroups
             List all domain groups that a user is a member of. PARAMETER OPTION = 'user'

        user-memberships-localgroups
             List all local groups that a user is a member of. PARAMETER OPTION = 'user'

        display-info
            List all objects with additional descriptive fields. PARAMETER OPTION = 'type'. The type parameter accepts the following values: users, domain-groups, local-groups, and computers.

        account-details user=<USERNAME/RID>
             Display account details for a specific user (by username or RID). PARAMETER OPTION = 'user'

        domain-group-details group=<GROUP>
            Display domain group details. (Parameter option: group)

        local-group-details group=<GROUP>
            Display local/builtin group details. (Parameter option: group)

        password-policy
             Display the password policy.

        lockout-policy
             Display the account lockout policy.

        summary
            Display a summary report for the domain. The summary includes:
               - Domain Information (name, SID, etc.)
               - Total number of user accounts
               - Total number of computer accounts
               - Total number of domain groups
               - Total number of local groups (aliases)
               - Password policy details
               - Lockout policy details

    Usage Examples:
      samr-enum.py target=192.168.1.1 username=micky password=mouse123 enumerate=users
      samr-enum.py target=dc1.domain-a.com username=micky password=mouse123 enumerate=domain-groups
      samr-enum.py target=dc1.domain-a.com username=micky password=mouse123 enumerate=domain-group-members group="Domain Admins"
      samr-enum.py target=dc1.domain-a.com username=micky password=mouse123 enumerate=local-group-members group="Administrators"
      samr-enum.py target=dc1.domain-a.com username=micky password=mouse123 enumerate=account-details user=john-doe debug=true
      samr-enum.py target=dc1.domain-a.com username=micky password= domain=domain-y.local auth=kerberos enumerate=password-policy
      samr-enum.py target=dc1.domain-a.com username=micky password=mouse123 enumerate=users export=export.txt format=txt opnums=true
      samr-enum.py target=dc1.domain-a.com username=micky password=mouse123 enumerate=user-memberships-domaingroups user=Administrator
      samr-enum.py target=dc1.domain-a.com username=micky password=mouse123 enumerate=display-info type=users
      samr-enum.py target=dc1.domain-a.com username=micky password=mouse123 enumerate=display-info type=domain-groups
      samr-enum.py target=dc1.domain-a.com username=micky password=mouse123 enumerate=domain-group-details group="Domain Admins"
      samr-enum.py target=dc1.domain-a.com username=micky password=mouse123 enumerate=summary

    """
    print(help_text)
    sys.exit(1)


def yes_no(value):
    """
    Convert a boolean value into 'Yes' or 'No'.
    If the value is not strictly True or False, just return str(value).
    """
    if value is True:
        return "Yes"
    elif value is False:
        return "No"
    return str(value)


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
    Safely extract an integer from an Impacket NDR object (e.g. NDRULONG).
    If possible, this returns a plain Python int.
    """
    if isinstance(ndr_object, int):
        return ndr_object
    try:
        # Try to convert using the object's __int__ method.
        return int(ndr_object)
    except Exception:
        if hasattr(ndr_object, 'fields') and 'Data' in ndr_object.fields:
            return ndr_object.fields['Data']
    return ndr_object


def safe_str(value):
    """
    Convert a value to a Unicode string safely.
    If the value is an RPC_UNICODE_STRING, extract and decode its Buffer.
    """
    # If already a Python string, return it directly.
    if isinstance(value, str):
        return value
    # If the object has a getData() method, use it.
    if hasattr(value, 'getData') and callable(value.getData):
        try:
            data = value.getData()
            if isinstance(data, str):
                return data
            return str(data)
        except Exception:
            pass
    # If the class name indicates an RPC_UNICODE_STRING, decode the Buffer.
    if hasattr(value, '__class__') and value.__class__.__name__ == 'RPC_UNICODE_STRING':
        try:
            return value.fields['Buffer'].decode('utf-16-le', errors='replace').rstrip('\x00')
        except Exception:
            return repr(value)
    # Fallback conversion.
    try:
        return str(value)
    except Exception:
        return repr(value)


def decode_group_attributes(attr):
    """
    Decode a group attributes bitmask into a comma-separated string of attribute names.
    """
    flags = []
    if attr & 0x00000001:
        flags.append("SE_GROUP_MANDATORY")
    if attr & 0x00000002:
        flags.append("SE_GROUP_ENABLED_BY_DEFAULT")
    if attr & 0x00000004:
        flags.append("SE_GROUP_ENABLED")
    if attr & 0x00000008:
        flags.append("SE_GROUP_OWNER")
    if attr & 0x00000010:
        flags.append("SE_GROUP_USE_FOR_DENY_ONLY")
    return ", ".join(flags)


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
                try:
                    with open(filename, 'w', newline='') as f:
                        writer = csv.writer(f, delimiter=';')

                        if not data:
                            writer.writerow(["No data"])
                            return

                        # 1) If first item is a dict with "computer_name"
                        if isinstance(data[0], dict) and 'computer_name' in data[0]:
                            writer.writerow(['Name', 'RID'])
                            for item in data:
                                name_val = item.get('computer_name', '').rstrip('$')
                                rid_val = item.get('rid', 'N/A')
                                writer.writerow([name_val, rid_val])
                        # 2) If first item is a dict with "username"
                        elif isinstance(data[0], dict) and 'username' in data[0]:
                            writer.writerow(['Username', 'RID'])
                            for item in data:
                                writer.writerow([item.get('username', 'N/A'), item.get('rid', 'N/A')])
                        # 3) If first item is a dict with 'members' key (for group-details)
                        elif isinstance(data[0], dict) and 'members' in data[0]:
                            members = data[0].get('members', [])
                            writer.writerow(['RID', 'Username'])
                            for member in members:
                                writer.writerow([member[0], member[1]])
                        # 4) If first item is a tuple => treat it as (username, rid)
                        elif isinstance(data[0], tuple) and len(data[0]) >= 2:
                            writer.writerow(['Username', 'RID'])
                            for item in data:
                                writer.writerow([item[0], item[1]])
                        else:
                            writer.writerow(['Unknown', 'N/A'])
                except Exception as e:
                    print(f"Export failed: {str(e)}")

            elif fmt == 'json':
                import json
                json_data = []
                for item in data:
                    # Special handling for local-group-details output
                    if isinstance(item, dict) and 'alias_name' in item:
                        # For local-group-details, output only the members list
                        for member in item.get('members', []):
                            json_data.append({"RID": member[0], "Username": member[1]})
                    elif isinstance(item, tuple) and len(item) >= 2:
                        first_field = item[0]
                        rid_value = item[1]
                        if isinstance(first_field, str) and first_field.endswith('$'):
                            json_data.append({'Name': first_field.rstrip('$'), 'RID': rid_value})
                        else:
                            json_data.append({'Username': first_field, 'RID': rid_value})
                    elif isinstance(item, dict):
                        if 'computer_name' in item:
                            json_data.append({'Name': item['computer_name'].rstrip('$'), 'RID': item.get('rid')})
                        elif 'username' in item:
                            json_data.append({'Username': item['username'], 'RID': item.get('rid')})
                        else:
                            json_data.append(item)
                json.dump(json_data, f, indent=2)

            elif fmt == 'txt':
                # For TXT export, do not include dashed lines.
                if isinstance(data[0], dict):
                    if 'computer_name' in data[0]:
                        col_header = "Name"
                        max_length = max(
                            len(str(item.get('computer_name', '')).rstrip('$')) for item in data) if data else 20
                    elif 'username' in data[0]:
                        col_header = "Username"
                        max_length = max(len(str(item.get('username', ''))) for item in data) if data else 20
                    elif 'members' in data[0]:
                        # For group-details export, export the members table only
                        members = data[0].get('members', [])
                        if members:
                            max_length = max(len(str(item[0])) for item in members) if members else 20
                            header = f"{'RID':<{max_length}} Username"
                            f.write(header + "\n")
                            f.write("-" * (max_length + 9) + "\n")
                            for item in members:
                                f.write(f"{str(item[0]):<{max_length}} {item[1]}\n")
                        else:
                            f.write("No members\n")
                        return
                    else:
                        col_header = "Unknown"
                        max_length = 20
                    header = f"{col_header:<{max_length}} RID"
                    f.write(header + "\n")
                    for item in data:
                        if 'computer_name' in item:
                            name = str(item['computer_name']).rstrip('$')
                            f.write(f"{name:<{max_length}} {item.get('rid', 'N/A')}\n")
                        elif 'username' in item:
                            f.write(f"{item['username']:<{max_length}} {item.get('rid', 'N/A')}\n")
                elif isinstance(data[0], tuple) and len(data[0]) >= 2:
                    max_length = max(len(str(item[0])) for item in data) if data else 20
                    header = f"{'Username':<{max_length}} RID"
                    f.write(header + "\n")
                    for item in data:
                        f.write(f"{item[0]:<{max_length}} {item[1]}\n")

        print(f"Data exported to {filename} ({fmt.upper()})")
    except Exception as e:
        print(f"Export failed: {str(e)}")


def samr_connect(target, username, password, domain, debug, auth_mode):
    """
    Connect to \\pipe\\samr on the remote target and return (dce, serverHandle).
    If auth_mode=='kerberos', sets Kerberos = True in the transport.

    desiredAccess=0x00000031 for SamrConnect

    :param target: Hostname or IP of the remote target
    :param username: The username for authentication
    :param password: The password for authentication (could be empty, then user is prompted)
    :param domain: The domain of the user (can be blank if not needed)
    :param debug: Boolean indicating debug output
    :param auth_mode: "kerberos" or "ntlm" (default)
    :return: (dce, serverHandle)
    """
    binding_str = rf"ncacn_np:{target}[\pipe\samr]"
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
    log_debug(debug, f"[debug] Connecting to {target} via SMB (auth={auth_mode})...")
    dce.connect()

    log_debug(debug, "[debug] Binding to SAMR interface (MSRPC_UUID_SAMR)...")
    dce.bind(samr.MSRPC_UUID_SAMR)

    log_debug(debug, "[debug] Calling SamrConnect...")
    connectResp = samr.hSamrConnect(dce, serverName=target, desiredAccess=0x00000031)

    if debug:
        print("[debug] SamrConnect response dump:")
        print(connectResp.dump())

    if connectResp['ErrorCode'] != 0:
        raise Exception(f"SamrConnect failed (NTSTATUS=0x{connectResp['ErrorCode']:X})")

    serverHandle = connectResp['ServerHandle']
    log_debug(debug, "[debug] SamrConnect succeeded.")
    return dce, serverHandle


def get_domain_handle(dce, serverHandle, debug, opnums_called):
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
    add_opnum_call(opnums_called, "SamrEnumerateDomainsInSamServer")
    if debug:
        print("[debug] SamrEnumerateDomainsInSamServer response dump:")
        print(enumDomainsResp.dump())

    domains = enumDomainsResp['Buffer']['Buffer']
    if not domains:
        raise Exception("No domains found on target.")

    domainName = safe_str(domains[0]['Name'])
    log_debug(debug, f"[debug] Found domain: {domainName}")

    lookupResp = samr.hSamrLookupDomainInSamServer(dce, serverHandle, domainName)
    add_opnum_call(opnums_called, "SamrLookupDomainInSamServer")
    if debug:
        print("[debug] SamrLookupDomainInSamServer response dump:")
        print(lookupResp.dump())

    domainSidObj = lookupResp['DomainId']
    sidString = domainSidObj.formatCanonical()
    log_debug(debug, f"[debug] Domain SID: {sidString}")

    log_debug(debug, "[debug] SamrOpenDomain -> opening domain handle...")
    desired_access = samr.DOMAIN_LOOKUP | samr.DOMAIN_LIST_ACCOUNTS | samr.DOMAIN_READ_PASSWORD_PARAMETERS
    openDomResp = samr.hSamrOpenDomain(
        dce,
        serverHandle,
        samr.DOMAIN_LOOKUP | samr.DOMAIN_LIST_ACCOUNTS | samr.DOMAIN_READ_PASSWORD_PARAMETERS,
        domainSidObj
    )
    add_opnum_call(opnums_called, "SamrOpenDomain", desired_access)
    if debug:
        print("[debug] SamrOpenDomain response dump:")
        print(openDomResp.dump())

    if openDomResp['ErrorCode'] != 0:
        raise Exception(f"SamrOpenDomain failed (NTSTATUS=0x{openDomResp['ErrorCode']:X})")

    domainHandle = openDomResp['DomainHandle']
    log_debug(debug, "[debug] Domain opened successfully.")
    return domainHandle, domainName, sidString


def get_builtin_domain_handle(dce, serverHandle, debug, opnums_called):
    """
    Enumerate the domain list, find the one named "Builtin", then open it.
    (DOMAIN_LOOKUP | DOMAIN_LIST_ACCOUNTS).

    :param dce: The DCE/RPC connection object
    :param serverHandle: The handle to the SAMR server
    :param debug: Boolean indicating debug output
    :return: (domainHandle, domainName, sidString)
    """
    log_debug(debug, "[debug] SamrEnumerateDomainsInSamServer -> looking for Builtin domain...")
    enumDomainsResp = samr.hSamrEnumerateDomainsInSamServer(dce, serverHandle)
    add_opnum_call(opnums_called, "SamrEnumerateDomainsInSamServer")
    if debug:
        print("[debug] SamrEnumerateDomainsInSamServer response dump:")
        print(enumDomainsResp.dump())

    domains = enumDomainsResp['Buffer']['Buffer']
    if not domains:
        raise Exception("No domains found on target.")

    builtin_domain = None
    for dom in domains:
        d_name = safe_str(dom['Name'])
        if d_name.lower() == 'builtin':
            builtin_domain = d_name
            break

    if not builtin_domain:
        raise Exception("Builtin domain not found on target.")

    lookupResp = samr.hSamrLookupDomainInSamServer(dce, serverHandle, builtin_domain)
    add_opnum_call(opnums_called, "SamrLookupDomainInSamServer")
    if debug:
        print("[debug] SamrLookupDomainInSamServer (Builtin) response dump:")
        print(lookupResp.dump())

    domainSidObj = lookupResp['DomainId']
    sidString = domainSidObj.formatCanonical()
    log_debug(debug, f"[debug] Builtin Domain SID: {sidString}")

    log_debug(debug, "[debug] SamrOpenDomain -> opening Builtin domain handle...")
    desired_access = 0x00000300
    openDomResp = samr.hSamrOpenDomain(dce, serverHandle, desired_access, domainSidObj)
    add_opnum_call(opnums_called, "SamrOpenDomain", desired_access)
    if debug:
        print("[debug] SamrOpenDomain (Builtin) response dump:")
        print(openDomResp.dump())

    if openDomResp['ErrorCode'] != 0:
        raise Exception(f"SamrOpenDomain failed for Builtin domain (NTSTATUS=0x{openDomResp['ErrorCode']:X})")

    domainHandle = openDomResp['DomainHandle']
    log_debug(debug, "[debug] Builtin Domain opened successfully.")
    return domainHandle, builtin_domain, sidString


def enumerate_users(dce, domainHandle, debug):
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


def enumerate_computers(dce, domainHandle, debug):
    """
    Enumerate all domain computers (workstations AND domain controllers) by
    using both USER_WORKSTATION_TRUST_ACCOUNT and USER_SERVER_TRUST_ACCOUNT flags.
    """
    log_debug(debug, "[debug] SamrEnumerateUsersInDomain -> enumerating computers...")
    computers = []
    resumeHandle = 0
    max_retries = 3
    retry_count = 0

    # Combined flags for both workstation and server trust accounts
    ACCOUNT_FILTER = samr.USER_WORKSTATION_TRUST_ACCOUNT | samr.USER_SERVER_TRUST_ACCOUNT

    while True:
        try:
            enumUsersResp = samr.hSamrEnumerateUsersInDomain(
                dce,
                domainHandle,
                enumerationContext=resumeHandle,
                userAccountControl=ACCOUNT_FILTER
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
        for accountEntry in chunk:  # Changed variable name for clarity
            computername = safe_str(accountEntry['Name'])
            rid = accountEntry['RelativeId']
            computers.append((computername, rid))

        resumeHandle = enumUsersResp['EnumerationContext']
        if enumUsersResp['ErrorCode'] != 0x00000105:
            break
        time.sleep(0.1)

    return computers


def enumerate_domain_groups(dce, domainHandle, debug):
    """
    Enumerate domain groups.

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
    group_tuples = [(safe_str(g['Name']), g['RelativeId']) for g in groups]
    return group_tuples, False


def list_local_group_members(dce, serverHandle, domainHandle, groupName, debug, opnums_called):
    """Enumerate members of local groups (aliases) with SIDs"""
    log_debug(debug, f"[debug] Local group lookup: {groupName}")
    additional_ops = ["SamrLookupNamesInDomain"]
    results = []

    # First try Builtin domain for local groups
    builtinHandle, _, _ = get_builtin_domain_handle(dce, serverHandle, debug, opnums_called)
    lookupResp = samr.hSamrLookupNamesInDomain(dce, builtinHandle, [groupName])
    add_opnum_call(opnums_called, "SamrLookupNamesInDomain")

    if debug:
        print("[debug] SamrLookupNamesInDomain response:")
        print(lookupResp.dump())

    rids = lookupResp['RelativeIds']['Element']
    uses = lookupResp['Use']['Element']

    if not rids or extract_ndr_value(uses[0]) != SID_NAME_ALIAS:
        raise Exception("Not a valid local group")

    groupRid = extract_ndr_value(rids[0])

    # Open local alias
    additional_ops.append("SamrOpenAlias")
    aliasHandle = samr.hSamrOpenAlias(
        dce, builtinHandle, samr.ALIAS_LIST_MEMBERS, groupRid
    )['AliasHandle']
    add_opnum_call(opnums_called, "SamrOpenAlias")
    # Get members
    additional_ops.append("SamrGetMembersInAlias")
    membersResp = samr.hSamrGetMembersInAlias(dce, aliasHandle)
    add_opnum_call(opnums_called, "SamrGetMembersInAlias")

    # Enumerate domains to resolve SIDs
    additional_ops.append("SamrEnumerateDomainsInSamServer")
    enumDomainsResp = samr.hSamrEnumerateDomainsInSamServer(dce, serverHandle)
    domains = []
    for domain in enumDomainsResp['Buffer']['Buffer']:
        add_opnum_call(opnums_called, "SamrEnumerateDomainsInSamServer")
        domain_name = safe_str(domain['Name'])
        additional_ops.append("SamrLookupDomainInSamServer")
        lookup_resp = samr.hSamrLookupDomainInSamServer(dce, serverHandle, domain_name)
        add_opnum_call(opnums_called, "SamrLookupDomainInSamServer")
        domains.append((domain_name, lookup_resp['DomainId']))

    # Process each member SID
    for sid in membersResp['Members']['Sids']:
        sid_str = sid['SidPointer'].formatCanonical()
        parts = sid_str.split('-')
        rid = parts[-1]
        domain_sid_part = '-'.join(parts[:-1])
        resolved = False

        # Find matching domain
        for domain_name, domain_sid in domains:
            if domain_sid.formatCanonical() == domain_sid_part:
                try:
                    additional_ops.append("SamrOpenDomain")
                    dom_handle = samr.hSamrOpenDomain(
                        dce, serverHandle,
                        samr.DOMAIN_LOOKUP | samr.DOMAIN_LIST_ACCOUNTS,
                        domain_sid
                    )['DomainHandle']
                    add_opnum_call(opnums_called, "SamrOpenDomain")
                    additional_ops.append("SamrLookupIdsInDomain")
                    lookup = samr.hSamrLookupIdsInDomain(dce, dom_handle, [int(rid)])
                    add_opnum_call(opnums_called, "SamrLookupIdsInDomain")
                    if lookup['Names']['Element']:
                        username = safe_str(lookup['Names']['Element'][0]['Data'])
                        results.append((username, rid))
                        resolved = True

                    additional_ops.append("SamrCloseHandle")
                    samr.hSamrCloseHandle(dce, dom_handle)
                    add_opnum_call(opnums_called, "SamrCloseHandle")
                except Exception as e:
                    log_debug(debug, f"[debug] SID resolution failed: {str(e)}")
                break  # Exit domain loop after processing matching domain

        if not resolved:
            results.append((sid_str, 'SID'))  # Maintain original output format

    samr.hSamrCloseHandle(dce, aliasHandle)
    additional_ops.append("SamrCloseHandle")

    return results, additional_ops


def list_domain_group_members(dce, serverHandle, domainHandle, groupName, debug, opnums_called):
    """Enumerate members of domain groups with name resolution"""
    log_debug(debug, f"[debug] Domain group lookup: {groupName}")
    additional_ops = ["SamrLookupNamesInDomain"]

    # Lookup group in primary domain
    lookupResp = samr.hSamrLookupNamesInDomain(dce, domainHandle, [groupName])
    add_opnum_call(opnums_called, "SamrLookupNamesInDomain")

    if debug:
        print("[debug] SamrLookupNamesInDomain response:")
        print(lookupResp.dump())

    rids = lookupResp['RelativeIds']['Element']
    uses = lookupResp['Use']['Element']

    if not rids or extract_ndr_value(uses[0]) not in (SID_NAME_GROUP, SID_NAME_WKN_GRP):
        raise Exception("Not a valid domain group")

    groupRid = extract_ndr_value(rids[0])

    # Open domain group
    add_opnum_call(opnums_called, "SamrOpenGroup")
    groupHandle = samr.hSamrOpenGroup(
        dce, domainHandle, samr.GROUP_LIST_MEMBERS, groupRid
    )['GroupHandle']

    # Get members - CORRECTED SECTION
    add_opnum_call(opnums_called, "SamrGetMembersInGroup")
    membersResp = samr.hSamrGetMembersInGroup(dce, groupHandle)

    # Proper RID extraction matching working user enumeration
    rids_list = []
    for ridEntry in membersResp['Members']['Members']:
        if isinstance(ridEntry, int):
            rids_list.append(ridEntry)
        elif hasattr(ridEntry, 'fields'):
            ridVal = extract_ndr_value(ridEntry)
            rids_list.append(ridVal)
        else:
            ridVal = extract_ndr_value(ridEntry['RelativeId'])
            rids_list.append(ridVal)

    # Resolve RIDs to names
    add_opnum_call(opnums_called, "SamrLookupIdsInDomain")
    lookupResp2 = samr.hSamrLookupIdsInDomain(dce, domainHandle, rids_list)
    names = [safe_str(name['Data']) for name in lookupResp2['Names']['Element']]
    results = list(zip(names, rids_list))

    samr.hSamrCloseHandle(dce, groupHandle)
    additional_ops.append("SamrCloseHandle")

    return results, additional_ops


def list_user_local_memberships(dce, serverHandle, username, domain_sid, debug, opnums_called):
    """Check Builtin domain aliases for user SID membership"""
    # Get user RID from primary domain
    domainHandle, _, _ = get_domain_handle(dce, serverHandle, debug, opnums_called)
    try:
        log_debug(debug, f"[debug] Looking up user '{username}' in primary domain...")
        lookupResp = samr.hSamrLookupNamesInDomain(dce, domainHandle, [username])
        add_opnum_call(opnums_called, "SamrLookupNamesInDomain")

        rids = lookupResp['RelativeIds']['Element']
        uses = lookupResp['Use']['Element']
        if not rids or extract_ndr_value(uses[0]) != SID_NAME_USER:
            raise Exception(f"User '{username}' not found in primary domain")

        user_rid = extract_ndr_value(rids[0])
        user_sid = f"{domain_sid}-{user_rid}"

    finally:
        samr.hSamrCloseHandle(dce, domainHandle)
        add_opnum_call(opnums_called, "SamrCloseHandle")

    # Check Builtin domain aliases
    builtinHandle, _, _ = get_builtin_domain_handle(dce, serverHandle, debug, opnums_called)
    local_memberships = []
    try:
        enumAliasesResp = samr.hSamrEnumerateAliasesInDomain(dce, builtinHandle)
        add_opnum_call(opnums_called, "SamrEnumerateAliasesInDomain")

        for alias in enumAliasesResp['Buffer']['Buffer']:

            # For each alias, call SamrOpenAlias
            add_opnum_call(opnums_called, "SamrOpenAlias")
            aliasHandle = samr.hSamrOpenAlias(
                dce, builtinHandle, samr.ALIAS_LIST_MEMBERS, alias['RelativeId']
            )['AliasHandle']
            try:
                # Then SamrGetMembersInAlias
                add_opnum_call(opnums_called, "SamrGetMembersInAlias")
                membersResp = samr.hSamrGetMembersInAlias(dce, aliasHandle)

                # Check if the user SID is among those members
                if any(sid['SidPointer'].formatCanonical() == user_sid
                       for sid in membersResp['Members']['Sids']):
                    local_memberships.append(
                        (safe_str(alias['Name']), alias['RelativeId'])
                    )
            finally:
                # Always log SamrCloseHandle for each alias handle
                add_opnum_call(opnums_called, "SamrCloseHandle")
                samr.hSamrCloseHandle(dce, aliasHandle)

    finally:
        # Close the Builtin domain handle as well
        samr.hSamrCloseHandle(dce, builtinHandle)
        add_opnum_call(opnums_called, "SamrCloseHandle")

    return local_memberships


def list_user_domain_memberships(dce, domainHandle, username, domain_sid, debug, opnums_called):
    """Enumerate domain groups a user belongs to using SamrGetGroupsForUser"""
    log_debug(debug, f"[debug] Looking up user '{username}' in domain...")
    lookupResp = samr.hSamrLookupNamesInDomain(dce, domainHandle, [username])
    add_opnum_call(opnums_called, "SamrLookupNamesInDomain")

    rids = lookupResp['RelativeIds']['Element']
    uses = lookupResp['Use']['Element']
    if not rids or extract_ndr_value(uses[0]) != SID_NAME_USER:
        raise Exception(f"User '{username}' not found")

    user_rid = extract_ndr_value(rids[0])
    log_debug(debug, f"[debug] User RID: {user_rid}")

    userHandle = samr.hSamrOpenUser(dce, domainHandle, samr.USER_LIST_GROUPS, user_rid)['UserHandle']
    add_opnum_call(opnums_called, "SamrOpenUser")

    groupsResp = samr.hSamrGetGroupsForUser(dce, userHandle)
    add_opnum_call(opnums_called, "SamrGetGroupsForUser")

    group_rids = [g['RelativeId'] for g in groupsResp['Groups']['Groups']]
    samr.hSamrCloseHandle(dce, userHandle)
    add_opnum_call(opnums_called, "SamrCloseHandle")

    if not groupsResp['Groups']['Groups']:
        return []
    group_rids = [g['RelativeId'] for g in groupsResp['Groups']['Groups']]
    lookupGroupsResp = samr.hSamrLookupIdsInDomain(dce, domainHandle, group_rids)
    add_opnum_call(opnums_called, "SamrLookupIdsInDomain")
    groups_list = groupsResp['Groups']['Groups']
    return [
        (safe_str(lookup_name['Data']), g['RelativeId'], g['Attributes'])
        for g, lookup_name in zip(groups_list, lookupGroupsResp['Names']['Element'])
    ]


def get_user_details(dce, domainHandle, user_input, debug, opnums_called):
    """Retrieve detailed user information from SAMR using direct dictionary indexing."""
    # First, perform the lookup for the user (by RID or username)
    try:
        if user_input.isdigit():
            rid = int(user_input)
            log_debug(debug, f"[debug] Looking up RID {rid}...")
            lookup_resp = samr.hSamrLookupIdsInDomain(dce, domainHandle, [rid])
            add_opnum_call(opnums_called, "SamrLookupIdsInDomain")
            if not lookup_resp['Names']['Element']:
                raise Exception(f"No user found with RID {rid}")
            username = safe_str(lookup_resp['Names']['Element'][0]['Data'])
        else:
            username = user_input
            log_debug(debug, f"[debug] Looking up username '{username}'...")
            lookup_resp = samr.hSamrLookupNamesInDomain(dce, domainHandle, [username])
            add_opnum_call(opnums_called, "SamrLookupNamesInDomain")
            rids = lookup_resp['RelativeIds']['Element']
            if not rids:
                raise Exception(f"User '{username}' not found")
            rid = extract_ndr_value(rids[0])
    except Exception as e:
        raise Exception(f"User lookup failed: {str(e)}")

    log_debug(debug, f"[debug] Looking up user '{username}'...")
    lookupResp = samr.hSamrLookupNamesInDomain(dce, domainHandle, [username])
    add_opnum_call(opnums_called, "SamrLookupNamesInDomain")
    rids = lookupResp['RelativeIds']['Element']
    uses = lookupResp['Use']['Element']
    if not rids or extract_ndr_value(uses[0]) != SID_NAME_USER:
        raise Exception(f"User '{username}' not found")

    user_rid = extract_ndr_value(rids[0])
    userHandle = samr.hSamrOpenUser(dce, domainHandle, 0x0002011b, user_rid)['UserHandle']
    add_opnum_call(opnums_called, "SamrOpenUser")

    # Query user information and retrieve the 'All' dictionary
    try:
        add_opnum_call(opnums_called, "SamrQueryInformationUser2")
        response = samr.hSamrQueryInformationUser2(
            dce,
            userHandle,
            samr.USER_INFORMATION_CLASS.UserAllInformation
        )
        all_info = response['Buffer']['All']
    except Exception as e:
        log_debug(debug, f"[debug] UserAllInformation failed: {str(e)}, trying GeneralInformation2")
        response = samr.hSamrQueryInformationUser2(
            dce,
            userHandle,
            samr.USER_INFORMATION_CLASS.UserGeneralInformation
        )
        all_info = response['Buffer']['General']

    # Helper to decode numeric values if returned as bytes
    def decode_int(val):
        if isinstance(val, bytes):
            return int.from_bytes(val, byteorder='little')
        return val

    # Process UserAccountControl for flag evaluation

    uac_ndr = all_info['UserAccountControl']
    uac_int = extract_ndr_value(uac_ndr)

    uac_value = response['Buffer']['All']['UserAccountControl']
    uac_int = int(uac_value)

    if uac_int & 0x00004000:
        print("ACB_NOT_DELEGATED is set")
        delegated = False
    else:
        delegated = True

    if uac_int & 0x00010000:
        print("ACB_DONT_REQUIRE_PREAUTH is set")
        pre_auth = False
    else:
        pre_auth = True


    # Process PasswordExpired field
    pw_exp = all_info['PasswordExpired']
    pw_exp_int = decode_int(pw_exp)
    password_expired_bool = bool(pw_exp_int)
    last_logon_ft = decode_filetime(all_info['LastLogon'])
    last_logoff_ft = decode_filetime(all_info['LastLogoff'])
    pwd_last_set_ft = decode_filetime(all_info['PasswordLastSet'])
    acct_expires_ft = decode_filetime(all_info['AccountExpires'])
    pwd_can_change_ft = decode_filetime(all_info['PasswordCanChange'])
    pwd_must_change_ft = decode_filetime(all_info['PasswordMustChange'])
    account_disabled = bool(uac_int & samr.USER_ACCOUNT_DISABLED)
    smartcard_required = bool(uac_int & samr.USER_SMARTCARD_REQUIRED)
    password_never_expires = bool(uac_int & samr.USER_DONT_EXPIRE_PASSWORD)

    return {
        'rid': user_rid,
        'username': safe_str(all_info['UserName']),
        'full_name': safe_str(all_info['FullName']),
        'description': safe_str(all_info['AdminComment']),
        'last_logon': last_logon_ft,
        'last_logoff': last_logoff_ft,
        'logon_count': safe_str(all_info['LogonCount']),
        'password_last_set': pwd_last_set_ft,
        'password_can_change': pwd_can_change_ft,
        'password_force_change': pwd_must_change_ft,
        'password_expired': password_expired_bool,
        'password_never_expires': password_never_expires,
        'password_bad_count': safe_str(all_info['BadPasswordCount']),
        'account_expires': acct_expires_ft,
        'account_disabled': account_disabled,
        'home_directory': safe_str(all_info['HomeDirectory']),
        'home_drive': safe_str(all_info['HomeDirectoryDrive']),
        'script_path': safe_str(all_info['ScriptPath']),
        'profile_path': safe_str(all_info['ProfilePath']),
        'workstations': safe_str(all_info['WorkStations']),
        'usercomment': safe_str(all_info['UserComment']),
        'primary_gid': safe_str(all_info['PrimaryGroupId']),
        'user_account_control': safe_str(all_info['UserAccountControl']),
        'which_fields': safe_str(all_info['WhichFields']),
        'logon_hours': safe_str(all_info['LogonHours']),
        'country_code': safe_str(all_info['CountryCode']),
        'code_page': safe_str(all_info['CodePage']),
        'delegated': delegated,
        'pre_auth': pre_auth,
        'smartcard_required': smartcard_required,
    }


def get_local_group_details(dce, builtinHandle, alias_name, debug, opnums_called, primaryDomainHandle, primaryDomainSid):
    """
    Retrieve detailed information about a local alias (group) from the Builtin domain.
    This function looks up the alias by its name using the Builtin domain handle,
    opens the alias with ALIAS_LIST_MEMBERS access, retrieves its member list,
    resolves the member SIDs to usernames using the primary domain handle,
    and returns a dictionary with keys 'alias_name', 'rid', 'member_count', 'members',
    and 'primary_domain_sid'.
    """
    # Lookup the alias by name using the Builtin domain handle
    lookupResp = samr.hSamrLookupNamesInDomain(dce, builtinHandle, [alias_name])
    add_opnum_call(opnums_called, "SamrLookupNamesInDomain")
    rids = lookupResp['RelativeIds']['Element']
    uses = lookupResp['Use']['Element']
    if not rids or extract_ndr_value(uses[0]) != SID_NAME_ALIAS:
        raise Exception(f"Alias '{alias_name}' not found or not a valid alias.")
    alias_rid = extract_ndr_value(rids[0])

    # Open the alias with ALIAS_LIST_MEMBERS access
    aliasHandle = samr.hSamrOpenAlias(dce, builtinHandle, samr.ALIAS_LIST_MEMBERS, alias_rid)['AliasHandle']
    add_opnum_call(opnums_called, "SamrOpenAlias")

    # Retrieve the members
    membersResp = samr.hSamrGetMembersInAlias(dce, aliasHandle)
    add_opnum_call(opnums_called, "SamrGetMembersInAlias")
    member_count = len(membersResp['Members']['Sids'])

    # Resolve each member SID using the primary domain handle
    members = []
    for sid in membersResp['Members']['Sids']:
        sid_str = sid['SidPointer'].formatCanonical()
        parts = sid_str.split('-')
        # The last part is the RID
        rid = parts[-1]
        try:
            add_opnum_call(opnums_called, "SamrLookupIdsInDomain")
            lookupResp2 = samr.hSamrLookupIdsInDomain(dce, primaryDomainHandle, [int(rid)])
            if lookupResp2['Names']['Element']:
                username = safe_str(lookupResp2['Names']['Element'][0]['Data'])
                members.append((int(rid), username))
            else:
                members.append((int(rid), 'N/A'))
        except Exception as e:
            log_debug(debug, f"[debug] SID resolution failed for {sid_str}: {str(e)}")
            members.append((int(rid), 'N/A'))

    samr.hSamrCloseHandle(dce, aliasHandle)
    add_opnum_call(opnums_called, "SamrCloseHandle")

    return {
        'alias_name': alias_name,
        'rid': alias_rid,
        'member_count': member_count,
        'members': members,
        'primary_domain_sid': primaryDomainSid
    }


def get_domain_group_details(dce, domainHandle, group_name, debug, opnums_called):
    """
    Retrieve detailed information about a domain group and resolve member usernames.

    This function looks up the group by its name in the given domain,
    opens the group with GROUP_LIST_MEMBERS access, retrieves the member list,
    resolves the member RIDs to usernames with an additional SAMR call,
    and returns a dictionary with the group name, RID, member count, and members list.

    :param dce: DCE/RPC connection object
    :param domainHandle: Handle to the domain obtained via SamrOpenDomain
    :param group_name: The name of the group to look up
    :param debug: Boolean for debug output
    :param opnums_called: List tracking SAMR operations performed
    :return: Dictionary with keys 'group_name', 'rid', 'member_count', and 'members'
    """
    # Lookup the group by name
    lookupResp = samr.hSamrLookupNamesInDomain(dce, domainHandle, [group_name])
    add_opnum_call(opnums_called, "SamrLookupNamesInDomain")
    rids = lookupResp['RelativeIds']['Element']
    uses = lookupResp['Use']['Element']
    if not rids or extract_ndr_value(uses[0]) not in (SID_NAME_GROUP, SID_NAME_WKN_GRP):
        raise Exception(f"Group '{group_name}' not found or not a valid domain group.")
    group_rid = extract_ndr_value(rids[0])

    # Open the group to retrieve members
    groupHandle = samr.hSamrOpenGroup(dce, domainHandle, samr.GROUP_LIST_MEMBERS, group_rid)['GroupHandle']
    add_opnum_call(opnums_called, "SamrOpenGroup")

    membersResp = samr.hSamrGetMembersInGroup(dce, groupHandle)
    add_opnum_call(opnums_called, "SamrGetMembersInGroup")
    member_count = len(membersResp['Members']['Members'])

    # Resolve member RIDs to usernames
    rids_list = []
    for ridEntry in membersResp['Members']['Members']:
        if isinstance(ridEntry, int):
            rids_list.append(ridEntry)
        elif hasattr(ridEntry, 'fields'):
            rids_list.append(extract_ndr_value(ridEntry))
        else:
            rids_list.append(extract_ndr_value(ridEntry['RelativeId']))

    members = []
    if rids_list:
        add_opnum_call(opnums_called, "SamrLookupIdsInDomain")
        lookupResp2 = samr.hSamrLookupIdsInDomain(dce, domainHandle, rids_list)
        names = [safe_str(name['Data']) for name in lookupResp2['Names']['Element']]
        members = list(zip(rids_list, names))

    # Close the group handle
    samr.hSamrCloseHandle(dce, groupHandle)
    add_opnum_call(opnums_called, "SamrCloseHandle")

    return {
        'group_name': group_name,
        'rid': group_rid,
        'member_count': member_count,
        'members': members,
    }


def get_password_policy(dce, domainHandle, debug, opnums_called):
    log_debug(debug, "[debug] Querying domain password policy...")
    add_opnum_call(opnums_called, "SamrQueryInformationDomain2")

    try:
        resp = samr.hSamrQueryInformationDomain2(
            dce,
            domainHandle,
            samr.DOMAIN_INFORMATION_CLASS.DomainPasswordInformation
        )
        password_info = resp['Buffer']['Password']

        resp_lockout = samr.hSamrQueryInformationDomain2(
            dce,
            domainHandle,
            samr.DOMAIN_INFORMATION_CLASS.DomainLockoutInformation
        )
        lockout_info = resp_lockout['Buffer']['Lockout']

        # Convert time intervals with special handling
        def ticks_to_days(ticks_obj):
            """Convert OLD_LARGE_INTEGER to days with Windows special value handling"""
            if not isinstance(ticks_obj, samr.OLD_LARGE_INTEGER):
                return 0

            # Handle "Never expire" special case (HighPart = 0x80000000)
            if ticks_obj['HighPart'] == -2147483648:  # 0x80000000 in signed int32
                return 0

            # Combine HighPart and LowPart into 64-bit integer
            ticks = (ticks_obj['HighPart'] << 32) | (ticks_obj['LowPart'] & 0xFFFFFFFF)

            # Handle negative values (two's complement)
            if ticks_obj['HighPart'] < 0:
                ticks = -((~ticks + 1) & 0xFFFFFFFFFFFFFFFF)

            seconds = abs(ticks) // 10000000  # 100ns -> seconds
            return seconds // 86400  # seconds -> days

        max_age_days = ticks_to_days(password_info['MaxPasswordAge'])
        min_age_days = ticks_to_days(password_info['MinPasswordAge'])

        lockout_threshold = lockout_info['LockoutThreshold']
        lockout_duration = ticks_to_days(lockout_info['LockoutDuration'])
        lockout_window = ticks_to_days(lockout_info['LockoutObservationWindow'])

        # Decode password properties flags
        properties = []
        props = password_info['PasswordProperties']
        if props & samr.DOMAIN_PASSWORD_COMPLEX:
            properties.append("Complexity required")
        if props & samr.DOMAIN_PASSWORD_NO_ANON_CHANGE:
            properties.append("No anonymous changes")
        if props & samr.DOMAIN_PASSWORD_NO_CLEAR_CHANGE:
            properties.append("No clear text password")
        if props & samr.DOMAIN_PASSWORD_STORE_CLEARTEXT:
            properties.append("Store cleartext")

        return {
            'min_length': password_info['MinPasswordLength'],
            'history_length': password_info['PasswordHistoryLength'],
            'max_age_days': max_age_days,
            'min_age_days': min_age_days,
            'properties': properties,
            'lockout_threshold': lockout_threshold,
            'lockout_duration': lockout_duration,
            'lockout_window': lockout_window
        }

    except Exception as e:
        if debug:
            print(f"[debug] Full error: {str(e)}")
        raise


def get_lockout_policy(dce, domainHandle, debug, opnums_called):
    """
    Retrieve the domain lockout policy using SamrQueryInformationDomain2.

    :param dce: DCE/RPC connection object.
    :param domainHandle: Handle to the opened domain.
    :param debug: Boolean indicating debug output.
    :param opnums_called: List to track SAMR functions called.
    :return: Dictionary containing lockout policy details.
    """
    log_debug(debug, "[debug] Querying domain lockout policy...")
    add_opnum_call(opnums_called, "SamrQueryInformationDomain2")

    try:
        resp_lockout = samr.hSamrQueryInformationDomain2(
            dce,
            domainHandle,
            samr.DOMAIN_INFORMATION_CLASS.DomainLockoutInformation
        )
        lockout_info = resp_lockout['Buffer']['Lockout']

        # Convert time intervals with special handling
        def ticks_to_days(ticks_obj):
            """Convert OLD_LARGE_INTEGER to days with Windows special value handling"""
            if not isinstance(ticks_obj, samr.OLD_LARGE_INTEGER):
                return 0

            # Handle "Never expire" special case (HighPart = 0x80000000)
            if ticks_obj['HighPart'] == -2147483648:  # 0x80000000 in signed int32
                return 0

            # Combine HighPart and LowPart into 64-bit integer
            ticks = (ticks_obj['HighPart'] << 32) | (ticks_obj['LowPart'] & 0xFFFFFFFF)

            # Handle negative values (two's complement)
            if ticks_obj['HighPart'] < 0:
                ticks = -((~ticks + 1) & 0xFFFFFFFFFFFFFFFF)

            seconds = abs(ticks) // 10000000  # 100ns -> seconds
            return seconds // 86400  # seconds -> days

        lockout_threshold = lockout_info['LockoutThreshold']
        lockout_duration = ticks_to_days(lockout_info['LockoutDuration'])
        lockout_window = ticks_to_days(lockout_info['LockoutObservationWindow'])

        return {
            'lockout_threshold': lockout_threshold,
            'lockout_duration': lockout_duration,
            'lockout_window': lockout_window
        }

    except Exception as e:
        if debug:
            print(f"[debug] Full error: {str(e)}")
        raise


def get_domain_info(dce, serverHandle, debug, opnums_called):
    """
    Retrieve general domain information using SamrQueryInformationDomain2.
    """

    def ticks_to_days(ticks_obj):
        """Convert OLD_LARGE_INTEGER to days with Windows special value handling."""
        if not isinstance(ticks_obj, samr.OLD_LARGE_INTEGER):
            return 0
        if ticks_obj['HighPart'] == -2147483648:  # 0x80000000
            return 0
        ticks = (ticks_obj['HighPart'] << 32) | (ticks_obj['LowPart'] & 0xFFFFFFFF)
        if ticks_obj['HighPart'] < 0:
            ticks = -((~ticks + 1) & 0xFFFFFFFFFFFFFFFF)
        return (abs(ticks) // 10000000) // 86400

    log_debug(debug, "[debug] Enumerating domains to get domain name...")
    enumDomainsResp = samr.hSamrEnumerateDomainsInSamServer(dce, serverHandle)
    add_opnum_call(opnums_called, "SamrEnumerateDomainsInSamServer")

    domains = enumDomainsResp['Buffer']['Buffer']
    if not domains:
        raise Exception("No domains found on target.")
    domainName = safe_str(domains[0]['Name'])

    log_debug(debug, f"[debug] Looking up domain '{domainName}'...")
    lookupResp = samr.hSamrLookupDomainInSamServer(dce, serverHandle, domainName)
    domainSid = lookupResp['DomainId']
    sidString = domainSid.formatCanonical()

    log_debug(debug, "[debug] Opening domain with MAXIMUM_ALLOWED access...")
    openDomResp = samr.hSamrOpenDomain(dce, serverHandle, 0x02000000, domainSid)
    domainHandle = openDomResp['DomainHandle']

    try:
        resp_general = samr.hSamrQueryInformationDomain2(
            dce,
            domainHandle,
            samr.DOMAIN_INFORMATION_CLASS.DomainGeneralInformation2
        )
        # Impacket returns a flattened structure with a 'fields' dict.
        general_info = resp_general['Buffer']['General2']

        # Query password policy (for max/min password age)
        resp_password = samr.hSamrQueryInformationDomain2(
            dce,
            domainHandle,
            samr.DOMAIN_INFORMATION_CLASS.DomainPasswordInformation
        )
        password_info = resp_password['Buffer']['Password']

        # Safely extract DomainModifiedCount; default to 0 if missing.
        modified_struct = general_info.fields.get('DomainModifiedCount')
        modified_count = modified_struct.fields.get('LowPart', 0) if modified_struct is not None else 0

        return {
            'domain_sid': sidString,
            'domain_name': domainName,
            'oem_information': safe_str(general_info.fields.get('OemInformation', b'')),
            'modified_count': modified_count,
            'force_logoff_days': ticks_to_days(general_info.fields.get('ForceLogoff', 0)),
            'max_password_age_days': ticks_to_days(password_info.fields['MaxPasswordAge']),
            'min_password_age_days': ticks_to_days(password_info.fields['MinPasswordAge']),
            'lockout_threshold': safe_str(extract_ndr_value(general_info.fields.get('LockoutThreshold', 0))),
            'lockout_duration_days': ticks_to_days(general_info.fields['LockoutDuration']),
            'lockout_window_days': ticks_to_days(general_info.fields['LockoutObservationWindow']),
            'server_state': general_info.fields.get('DomainServerState', 0),
            'server_role': {2: "Backup", 3: "Primary"}.get(general_info.fields.get('DomainServerRole', 0), "Unknown"),
            'uas_compatible': general_info.fields.get('UasCompatibilityRequired', False),
            'num_users_total': general_info.fields.get('UserCount', 0),
            'num_global_groups': general_info.fields.get('GroupCount', 0),
            'num_aliases': general_info.fields.get('AliasCount', 0)
        }

    except Exception as e:
        raise Exception("Domain info query failed: " + safe_str(e))
    finally:
        samr.hSamrCloseHandle(dce, domainHandle)
        add_opnum_call(opnums_called, "SamrCloseHandle")


def list_domain_groups_details(dce, domainHandle, group_name, group_rid, debug, opnums_called):
    """
    Retrieve additional details for a domain group.
    For example, count the number of members in the group.
    """
    groupHandle = samr.hSamrOpenGroup(dce, domainHandle, samr.GROUP_LIST_MEMBERS, group_rid)['GroupHandle']
    add_opnum_call(opnums_called, "SamrOpenGroup")
    membersResp = samr.hSamrGetMembersInGroup(dce, groupHandle)
    add_opnum_call(opnums_called, "SamrGetMembersInGroup")
    member_count = len(membersResp['Members']['Members'])
    samr.hSamrCloseHandle(dce, groupHandle)
    add_opnum_call(opnums_called, "SamrCloseHandle")
    return {'group_name': group_name, 'rid': group_rid, 'member_count': member_count}


def list_local_groups_details(dce, domainHandle, group_name, group_rid, debug, opnums_called):
    """
    Retrieve additional details for a local group (alias) from the Builtin domain.
    For example, count the number of members in the alias.
    """
    aliasHandle = samr.hSamrOpenAlias(dce, domainHandle, samr.ALIAS_LIST_MEMBERS, group_rid)['AliasHandle']
    add_opnum_call(opnums_called, "SamrOpenAlias")
    membersResp = samr.hSamrGetMembersInAlias(dce, aliasHandle)
    add_opnum_call(opnums_called, "SamrGetMembersInAlias")
    member_count = len(membersResp['Members']['Sids'])
    samr.hSamrCloseHandle(dce, aliasHandle)
    add_opnum_call(opnums_called, "SamrCloseHandle")
    return {'group_name': group_name, 'rid': group_rid, 'member_count': member_count}


def display_info(dce, serverHandle, info_type, debug, opnums_called):
    """
    Enumerate objects of a given type and display additional descriptive fields.

    Parameters:
      - info_type: one of 'users', 'computers', 'local-groups', or 'domain-groups'.

    Returns a list of dictionaries with detailed information.
    """
    results = []
    if info_type == 'users':
        # Get primary domain handle and enumerate users
        domainHandle, domainName, domainSid = get_domain_handle(dce, serverHandle, debug, opnums_called)
        users = enumerate_users(dce, domainHandle, debug)
        for username, rid in users:
            try:
                details = get_user_details(dce, domainHandle, username, debug, opnums_called)
                results.append(details)
            except Exception as e:
                results.append({'username': username, 'rid': rid, 'error': str(e)})
        # Close the domain handle after use
        samr.hSamrCloseHandle(dce, domainHandle)
        add_opnum_call(opnums_called, "SamrCloseHandle")

    elif info_type == 'domain-groups':
        # Get primary domain handle and enumerate domain groups
        domainHandle, domainName, domainSid = get_domain_handle(dce, serverHandle, debug, opnums_called)
        groups, did_aliases = enumerate_domain_groups(dce, domainHandle, debug)
        for group_name, group_rid in groups:
            try:
                details = list_domain_groups_details(dce, domainHandle, group_name, group_rid, debug, opnums_called)
                results.append(details)
            except Exception as e:
                results.append({'group_name': group_name, 'rid': group_rid, 'error': str(e)})
        samr.hSamrCloseHandle(dce, domainHandle)
        add_opnum_call(opnums_called, "SamrCloseHandle")


    elif info_type == 'local-groups':
        # Use the Builtin domain to enumerate local groups (aliases)
        domainHandle, domainName, domainSid = get_builtin_domain_handle(dce, serverHandle, debug, opnums_called)
        try:
            aliasResp = samr.hSamrEnumerateAliasesInDomain(dce, domainHandle)
            aliases = aliasResp['Buffer']['Buffer'] or []
        except Exception as e:
            aliases = []
        results = []
        group_tuples = [(safe_str(alias['Name']), alias['RelativeId']) for alias in aliases]
        for group_name, group_rid in group_tuples:
            try:
                details = list_local_groups_details(dce, domainHandle, group_name, group_rid, debug, opnums_called)
                results.append(details)
            except Exception as e:
                results.append({'group_name': group_name, 'rid': group_rid, 'error': str(e)})
        samr.hSamrCloseHandle(dce, domainHandle)
        add_opnum_call(opnums_called, "SamrCloseHandle")


    elif info_type == 'computers':
        # Enumerate computers in the primary domain using enumerate_computers
        domainHandle, domainName, domainSid = get_domain_handle(dce, serverHandle, debug, opnums_called)
        # enumerate_computers returns a list of dictionaries with detailed fields
        results = enumerate_computers(dce, domainHandle, debug)
        samr.hSamrCloseHandle(dce, domainHandle)
        add_opnum_call(opnums_called, "SamrCloseHandle")
    else:
        raise Exception(f"Invalid type parameter for display-info: {info_type}")
    return results


def enumerate_computers(dce, domainHandle, debug):
    """
    Enumerate all domain computers (workstations AND domain controllers) by
    using both USER_WORKSTATION_TRUST_ACCOUNT and USER_SERVER_TRUST_ACCOUNT flags.
    Returns a list of dictionaries with all fields returned by the server.
    """
    log_debug(debug, "[debug] SamrEnumerateUsersInDomain -> enumerating computers...")
    computers = []
    resumeHandle = 0
    max_retries = 3
    retry_count = 0

    # Combined flags for both workstation and server trust accounts
    ACCOUNT_FILTER = samr.USER_WORKSTATION_TRUST_ACCOUNT | samr.USER_SERVER_TRUST_ACCOUNT

    while True:
        try:
            enumUsersResp = samr.hSamrEnumerateUsersInDomain(
                dce,
                domainHandle,
                enumerationContext=resumeHandle,
                userAccountControl=ACCOUNT_FILTER
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
        for accountEntry in chunk:
            computername = safe_str(accountEntry['Name'])
            rid = accountEntry['RelativeId']
            # Build a dictionary with basic details...
            computer_dict = {'computer_name': computername, 'rid': rid}
            # If additional fields exist, add them (skipping Name and RelativeId)
            if hasattr(accountEntry, 'fields'):
                for field, value in accountEntry.fields.items():
                    if field not in ['Name', 'RelativeId']:
                        computer_dict[field] = safe_str(value)
            computers.append(computer_dict)

        resumeHandle = enumUsersResp['EnumerationContext']
        if enumUsersResp['ErrorCode'] != 0x00000105:
            break
        time.sleep(0.1)

    return computers


def get_summary(dce, serverHandle, debug, opnums_called):
    """
    Retrieve summary information about the domain:
      - Domain info
      - Total number of users
      - Total number of computers
      - Total number of domain groups
      - Total number of local groups (aliases)
      - Password policy summary
      - Lockout policy summary

    :param dce: DCE/RPC connection object
    :param serverHandle: Handle to the SAMR server
    :param debug: Boolean indicating debug output
    :param opnums_called: List tracking SAMR operations performed
    :return: A dictionary with the summary information
    """
    summary = {}

    # Get domain info (opens/closes its own handle)
    domain_info = get_domain_info(dce, serverHandle, debug, opnums_called)
    summary['domain_info'] = domain_info

    # Open primary domain handle for users, computers, domain groups, and policies
    domainHandle, domainName, domainSid = get_domain_handle(dce, serverHandle, debug, opnums_called)
    try:
        # Enumerate users
        users = enumerate_users(dce, domainHandle, debug)
        summary['total_users'] = len(users)

        # Enumerate computers using the renamed function (enumerate_computers returns a list of dicts)
        computers = enumerate_computers(dce, domainHandle, debug)
        summary['total_computers'] = len(computers)

        # Enumerate domain groups
        domain_groups, _ = enumerate_domain_groups(dce, domainHandle, debug)
        summary['total_domain_groups'] = len(domain_groups)

        # Get password policy
        password_policy = get_password_policy(dce, domainHandle, debug, opnums_called)
        summary['password_policy'] = password_policy

        # Get lockout policy
        lockout_policy = get_lockout_policy(dce, domainHandle, debug, opnums_called)
        summary['lockout_policy'] = lockout_policy
    finally:
        samr.hSamrCloseHandle(dce, domainHandle)
        add_opnum_call(opnums_called, "SamrCloseHandle")

    # Open Builtin domain handle for local groups (aliases)
    builtinHandle, builtinName, builtinSid = get_builtin_domain_handle(dce, serverHandle, debug, opnums_called)
    try:
        try:
            aliasResp = samr.hSamrEnumerateAliasesInDomain(dce, builtinHandle)
            aliases = aliasResp['Buffer']['Buffer'] or []
        except Exception as e:
            aliases = []
        summary['total_local_groups'] = len(aliases)
    finally:
        samr.hSamrCloseHandle(dce, builtinHandle)
        add_opnum_call(opnums_called, "SamrCloseHandle")

    return summary


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
    # If no args given, print usage
    if len(sys.argv) == 1:
        print("Usage:\n  python samr-enum.py target=dc1.domain-a.local"
              " username=user123 password=Password123 enumerate=domain-groups [domain=domain-b.local]"
              " [debug=true] [export=output.txt [format=txt|csv|json]] [auth=kerberos] [opnums=true]")
        sys.exit(1)

    args = parse_named_args(sys.argv)
    if args.get('help', 'false').lower() == 'true':
        print_help()

    enumeration = args.get('enumerate', 'domain-groups').lower()
    target = args.get('target', '')
    username = args.get('username', '')
    password = args.get('password', '')  # might be empty -> prompt
    groupName = args.get('group', '')
    debug = args.get('debug', 'false').lower() == 'true'
    export_file = args.get('export', '')
    export_format = args.get('format', 'txt').lower()
    auth_mode = args.get('auth', 'ntlm').lower()  # "kerberos" or "ntlm" default
    domain = args.get('domain', '')  # mandatory for Kerberos authentication
    opnums_param = args.get('opnums', 'false').lower() == 'true'

    # If password is empty, prompt user. getpass hides the input on CLI
    if password == '':
        password = getpass.getpass(prompt="Enter password (hidden): ")

    # If required parameters are missing, show usage
    if not target or not username:
        print("Usage:\n  python samr-enum.py enumerate=domain-groups target=dc1.domain-a.local"
              " username=user123 password=Password123 [group=MyGroup]"
              " [debug=true] [export=output.txt [format=txt|csv|json]] [domain=domain-b.local [auth=kerberos]] [opnums=true]")
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
    username = args.get('username', '')
    input_username = username

    try:
        dce, serverHandle = samr_connect(target, username, password, domain, debug, auth_mode)
        add_opnum_call(opnums_called, "SamrConnect")

        if enumeration == 'users':
            domainHandle, domainName, domainSidString = get_domain_handle(dce, serverHandle, debug, opnums_called)
            enumerated_objects = enumerate_users(dce, domainHandle, debug)
            add_opnum_call(opnums_called, "SamrEnumerateUsersInDomain")

        elif enumeration == 'computers':
            domainHandle, domainName, domainSidString = get_domain_handle(dce, serverHandle, debug, opnums_called)
            enumerated_objects = enumerate_computers(dce, domainHandle, debug)
            add_opnum_call(opnums_called, "SamrEnumerateUsersInDomain")

        elif enumeration == 'local-groups':
            # Builtin domain
            domainHandle, domainName, domainSidString = get_builtin_domain_handle(dce, serverHandle, debug,
                                                                                  opnums_called)
            # Enumerate local groups (aliases) via SamrEnumerateAliasesInDomain:
            aliasResp = samr.hSamrEnumerateAliasesInDomain(dce, domainHandle)
            add_opnum_call(opnums_called, "SamrEnumerateAliasesInDomain")
            groups_result = [(safe_str(alias['Name']), alias['RelativeId']) for alias in
                             aliasResp['Buffer']['Buffer'] or []]
            enumerated_objects = groups_result

        elif enumeration == 'domain-groups':
            domainHandle, domainName, domainSidString = get_domain_handle(dce,
                                                                          serverHandle,
                                                                          debug, opnums_called)
            groups_result, did_aliases = enumerate_domain_groups(dce,
                                                                    domainHandle,
                                                                    debug)
            add_opnum_call(opnums_called, "SamrEnumerateGroupsInDomain")
            if did_aliases:
                add_opnum_call(opnums_called, "SamrEnumerateAliasesInDomain")
            enumerated_objects = groups_result

        elif enumeration == 'local-group-members':
            # Use Builtin domain by default
            domainHandle, _, domainSidString = get_builtin_domain_handle(dce, serverHandle, debug, opnums_called)
            enumerated_objects, additional_ops = list_local_group_members(dce, serverHandle, domainHandle, groupName,
                                                                          debug, opnums_called)

        elif enumeration == 'domain-group-members':
            domainHandle, _, domainSidString = get_domain_handle(dce, serverHandle, debug, opnums_called)
            enumerated_objects, additional_ops = list_domain_group_members(
                dce, serverHandle, domainHandle, groupName, debug, opnums_called)

        elif enumeration == 'user-memberships-localgroups':
            user = args.get('user', '')
            if not user:
                raise Exception("Missing 'user=' argument")
            # Get primary domain SID for user SID construction
            domainHandle, _, domainSidString = get_domain_handle(dce, serverHandle, debug, opnums_called)
            enumerated_objects = list_user_local_memberships(dce, serverHandle, user, domainSidString, debug,
                                                             opnums_called)

        elif enumeration == 'user-memberships-domaingroups':
            user = args.get('user', '')
            if not user:
                raise Exception("Missing 'user=' argument")
            domainHandle, _, domainSidString = get_domain_handle(dce, serverHandle, debug, opnums_called)
            enumerated_objects = list_user_domain_memberships(dce, domainHandle, user, domainSidString, debug,
                                                              opnums_called)

        elif enumeration == 'account-details':
            user = args.get('user', '')
            if not user:
                raise Exception("Missing 'user=' argument")
            domainHandle, _, domainSidString = get_domain_handle(dce, serverHandle, debug, opnums_called)
            user_details = get_user_details(dce, domainHandle, user, debug, opnums_called)
            enumerated_objects = [user_details]

        elif enumeration == 'local-group-details':

            aliasName = args.get('group', '')

            if not aliasName:
                raise Exception("Missing 'group=' argument for local-group-details")
            # Use the Builtin domain to look up the alias
            builtinHandle, builtin_domain, _ = get_builtin_domain_handle(dce, serverHandle, debug, opnums_called)
            # Get primary domain handle (and its SID) for resolving member SIDs
            primaryHandle, primaryDomainName, primaryDomainSid = get_domain_handle(dce, serverHandle, debug,
                                                                                   opnums_called)
            alias_details = get_local_group_details(dce, builtinHandle, aliasName, debug, opnums_called, primaryHandle,
                                                    primaryDomainSid)
            enumerated_objects = [alias_details]
            domainSidString = alias_details.get('primary_domain_sid', '')

        elif enumeration == 'domain-group-details':
            groupName = args.get('group', '')
            if not groupName:
                raise Exception("Missing 'group=' argument for domain-group-details")
            domainHandle, domainName, domainSidString = get_domain_handle(dce, serverHandle, debug, opnums_called)
            group_details = get_domain_group_details(dce, domainHandle, groupName, debug, opnums_called)
            enumerated_objects = [group_details]

        elif enumeration == 'password-policy':  # New enumeration type
            domainHandle, domainName, domainSidString = get_domain_handle(dce, serverHandle, debug, opnums_called)
            add_opnum_call(opnums_called, "SamrEnumerateDomainsInSamServer")
            add_opnum_call(opnums_called, "SamrLookupDomainInSamServer")
            add_opnum_call(opnums_called, "SamrOpenDomain")
            password_policy = get_password_policy(dce, domainHandle, debug, opnums_called)
            enumerated_objects = [password_policy]

        elif enumeration == 'lockout-policy':
            domainHandle, domainName, domainSidString = get_domain_handle(dce, serverHandle, debug, opnums_called)
            add_opnum_call(opnums_called, "SamrEnumerateDomainsInSamServer")
            add_opnum_call(opnums_called, "SamrLookupDomainInSamServer")
            add_opnum_call(opnums_called, "SamrOpenDomain")
            lockout_policy = get_lockout_policy(dce, domainHandle, debug, opnums_called)
            enumerated_objects = [lockout_policy]

        elif enumeration == 'domain-info':
            domain_info = get_domain_info(dce, serverHandle, debug, opnums_called)
            enumerated_objects = [domain_info]
            domainSidString = domain_info.get('domain_sid', '')

        elif enumeration == 'display-info':
            info_type = args.get('type', '').lower()
            if not info_type:
                raise Exception("Missing 'type=' argument for display-info")
            if info_type not in ['users', 'domain-groups', 'local-groups', 'computers']:
                raise Exception(
                    "Invalid 'type' for display-info. Must be one of: 'users', 'domain-groups', 'local-groups', 'computers'")
            enumerated_objects = display_info(dce, serverHandle, info_type, debug, opnums_called)

        elif enumeration == 'summary':
            # Call get_summary() to get the aggregated domain summary info
            summary = get_summary(dce, serverHandle, debug, opnums_called)
            enumerated_objects = [summary]

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

    if enumerated_objects and execution_status == "success":

        if enumeration == 'users':
            max_length = max(
                len(str(obj[0])) for obj in enumerated_objects if isinstance(obj, tuple)
            ) if enumerated_objects else 25

            # Add +2 instead of +1 to shift "RID" a bit further right
            print("\nUsername".ljust(max_length + 5), "RID")
            print("-" * (max_length + 4), "----")
            for obj in enumerated_objects:
                if isinstance(obj, tuple) and len(obj) >= 2:
                    user_name = obj[0]
                    user_rid = obj[1]
                    # Also use max_length + 2 here
                    print(f"{user_name:<{max_length + 4}} {user_rid}")

        elif enumeration == 'computers':
            max_length = max(
                len(str(comp.get('computer_name', '')).rstrip('$'))
                for comp in enumerated_objects if isinstance(comp, dict)
            ) if enumerated_objects else 25
            print("\nName".ljust(max_length + 5), "RID")
            print("-" * (max_length + 4), "----")
            for comp in enumerated_objects:
                if isinstance(comp, dict):
                    comp_name = str(comp.get('computer_name', '')).rstrip('$')
                    comp_rid = comp.get('rid', 'N/A')
                    print(f"{comp_name:<{max_length + 4}} {comp_rid}")

        elif enumeration == 'user-memberships-domaingroups':
            max_length = max(len(str(obj[0])) for obj in enumerated_objects) if enumerated_objects else 25
            print(f"\n{'Member':<{max_length}} RID     Attributes")
            print("-" * (max_length + 30))
            for obj in enumerated_objects:
                if isinstance(obj, tuple) and len(obj) >= 3:
                    print(f"{obj[0]:<{max_length}} {obj[1]:<7} {decode_group_attributes(obj[2])}")

        elif enumeration == 'account-details':
            # Handle account details display
            details = enumerated_objects[0]
            print(f"\nAccount Details for {details.get('username', 'N/A')}:")
            print(f"  RID:                  {details.get('rid', 'N/A')}")
            print(f"  Username:             {details.get('username', 'N/A')}")
            print(f"  Full Name:            {details.get('full_name', 'N/A')}")
            print(f"  Description:          {details.get('description', 'N/A')}")
            print(f"  Last Logon:           {format_time(details.get('last_logon', 0))}")
            print(f"  Logon Count:          {details.get('logon_count', 'N/A')}")
            print(f"  Password Last Set:    {format_time(details.get('password_last_set', 0))}")
            print(f"  Password Can Chg:     {format_time(details.get('password_can_change', 0))}")
            print(f"  Password Force Chg:   {format_time(details.get('password_force_change', 0))}")
            print(f"  Password Expired:     {yes_no(details.get('password_expired', False))}")
            print(f"  Password Never Exp-s: {yes_no(details.get('password_never_expires', False))}")
            print(f"  Password Bad Count:   {details.get('password_bad_count', False)}")
            print(f"  Account Expires:      {format_time(details.get('account_expires', 0))}")
            print(f"  Account Disabled:     {yes_no(details.get('account_disabled', False))}")
            print(f"  Pre-Auth. Required:   {yes_no(details.get('pre_auth', False))}")
            print(f"  Delegation Allowed:   {yes_no(details.get('delegated', False))}")
            print(f"  Smartcard Required:   {yes_no(details.get('smartcard_required', False))}\n")

            print(f"  Primary Group ID:     {details.get('primary_gid', 'N/A')}")
            print(f"  Home Directory:       {details.get('home_directory', 'N/A')}")
            print(f"  Home Drive:           {details.get('home_drive', 'N/A')}")
            print(f"  Profile Path:         {details.get('profile_path', 'N/A')}")
            print(f"  Script Path:          {details.get('script_path', 'N/A')}")
            print(f"  Workstations:         {details.get('workstations', 'N/A')}")

        elif enumeration == 'local-group-details':
            details = enumerated_objects[0]
            print(f"{'-'*65}")
            print(f"{'Local Group Name:':<20}\t{details.get('alias_name', 'N/A')}")
            print(f"{'RID:':<20}\t{details.get('rid', 'N/A')}")
            print(f"{'Member Count:':<20}\t{details.get('member_count', 'N/A')}")
            print(f"{'Domain SID:':<20}\t{details.get('primary_domain_sid', 'N/A')}")
            members = details.get('members')
            if members:
                print(f"{'-'*65}")
                print(f"{'RID':<20}\t{'Username':<20}")
                print(f"{'-'*32}")
                for rid, username in members:
                    print(f"{rid:<20}\t{username:<20}")
            print()

        elif enumeration == 'domain-group-details':
            print("\nGroup Details")
            print("-------------")
            details = enumerated_objects[0]
            print(f"group_name: {details.get('group_name', 'N/A')}")
            print(f"rid: {details.get('rid', 'N/A')}")
            print(f"member_count: {details.get('member_count', 'N/A')}")
            members = details.get('members')
            if members:
                print("RID\tUsername")
                print("----------------")
                for rid, username in members:
                    print(f"{str(rid):<7} {username}")
            print()

        elif enumeration == 'password-policy':  # Handle password policy output
            policy = enumerated_objects[0]
            print("\nDomain Password Policy:")
            print(f"  Minimum password length:       {policy['min_length']}")
            print(f"  Password history length:       {policy['history_length']}")
            print(
                f"  Maximum password age (days):   {policy['max_age_days'] if policy['max_age_days'] > 0 else 'Never expire'}")
            print(f"  Minimum password age (days):   {policy['min_age_days']}")
            print(f"  Account lockout threshold:     {policy['lockout_threshold']}")
            print(f"  Lockout duration (days):       {policy['lockout_duration']}")
            print(f"  Lockout observation window:    {policy['lockout_window']}")
            print("  Password properties:")
            for prop in policy['properties']:
                print(f"    - {prop}")

        elif enumeration == 'lockout-policy':
            policy = enumerated_objects[0]
            print("\nDomain Lockout Policy:")
            print(f"  Account lockout threshold:     {policy['lockout_threshold']}")
            print(
                f"  Lockout duration (days):       {policy['lockout_duration'] if policy['lockout_duration'] > 0 else 'Indefinite'}")
            print(f"  Lockout observation window:    {policy['lockout_window']} days")

        elif enumeration == 'domain-info':
            info = enumerated_objects[0]
            # In main() function where domain-info is printed:
            print("\nDomain Information:")
            print(f"  Domain Name:             {info['domain_name']}")
            print(f"  OEM Information:         {info['oem_information']}")
            print(f"  Modified Count:          {info['modified_count']}")
            print(
                f"  Max Password Age (days): {info['max_password_age_days'] if info['max_password_age_days'] > 0 else 'Never'}")
            print(f"  Min Password Age (days): {info['min_password_age_days']}")
            print(
                f"  Force Logoff (days):     {info['force_logoff_days'] if info['force_logoff_days'] > 0 else 'Never'}")
            print(f"  Lockout Threshold:       {info['lockout_threshold']}")
            print(
                f"  Lockout Duration (days): {info['lockout_duration_days'] if info['lockout_duration_days'] > 0 else 'Never'}")
            print(f"  Lockout Window (days):   {info['lockout_window_days']}")
            print(f"  Server State:            0x{info['server_state']:08X}")
            print(f"  Server Role:             {info['server_role']}")
            print(f"  UAS Compatible:          {info['uas_compatible']}")
            print(f"  Total Users:             {info['num_users_total']}")
            print(f"  Global Groups:           {info['num_global_groups']}")
            print(f"  Aliases:                 {info['num_aliases']}")

        elif enumeration == 'display-info' and args.get('type', '').lower() == 'domain-groups':
            print("\nDomain Group Details")
            print("--------------------")
            for obj in enumerated_objects:
                if 'error' in obj:
                    print(f"Group: {obj.get('group_name', 'N/A')} (RID: {obj.get('rid', 'N/A')}) ERROR: {obj['error']}")
                else:
                    print(f"Group: {obj.get('group_name', 'N/A')} (RID: {obj.get('rid', 'N/A')}) "
                          f"Members: {obj.get('member_count', 'N/A')}")

        elif enumeration == 'display-info' and args.get('type', '').lower() == 'users':
            print("\nUsername Details")
            print("---------------")
            for obj in enumerated_objects:
                if 'error' in obj:
                    print(f"{obj.get('username', 'N/A')} - ERROR: {obj['error']}")
                else:
                    print(f"Username:             {obj.get('username', 'N/A')}")
                    print(f"Full Name:            {obj.get('full_name', 'N/A')}")
                    print(f"Home Directory:       {obj.get('home_directory', 'N/A')}")
                    print(f"Home Drive:           {obj.get('home_drive', 'N/A')}")
                    print(f"Profile Path:         {obj.get('profile_path', 'N/A')}")
                    print(f"Script Path:          {obj.get('script_path', 'N/A')}")
                    print(f"Last Logon:           {format_time(obj.get('last_logon', 0))}")
                    print(f"Last Logoff:          {format_time(obj.get('last_logoff', 0))}")
                    print(f"Password Last Set:    {format_time(obj.get('password_last_set', 0))}")
                    print(f"Account Expires:      {format_time(obj.get('account_expires', 0))}")
                    print(f"Account Disabled:     {obj.get('account_disabled', False)}")
                    print(f"Password Never Expires: {obj.get('password_never_expires', False)}")
                    print(f"Smartcard Required:   {obj.get('smartcard_required', False)}")
                    print(f"RID:                  {obj.get('rid', 'N/A')}")
                    print()

        elif enumeration == 'display-info' and args.get('type', '').lower() == 'local-groups':
            print("\nLocal Group Details")
            print("-------------------")
            for obj in enumerated_objects:
                if 'error' in obj:
                    print(
                        f"Local Group: {obj.get('group_name', 'N/A')} (RID: {obj.get('rid', 'N/A')}) ERROR: {obj['error']}")
                else:
                    for key, value in obj.items():
                        print(f"{key}: {value}")
                    print()

        elif enumeration == 'display-info' and args.get('type', '').lower() == 'computers':
            print("\nComputer Details")
            print("----------------")
            for obj in enumerated_objects:
                if 'error' in obj:
                    print(
                        f"Computer: {obj.get('computer_name', 'N/A')} (RID: {obj.get('rid', 'N/A')}) ERROR: {obj['error']}")
                else:
                    for key, value in obj.items():
                        print(f"{key}: {value}")
                    print()

        elif enumeration == 'display-info':
            info_type = args.get('type', '').lower()
            if not info_type:
                raise Exception("Missing 'type=' argument for display-info")
            if info_type not in ['users', 'domain-groups', 'local-groups', 'computers']:
                raise Exception(
                    "Invalid 'type' for display-info. Must be one of: 'users', 'domain-groups', 'local-groups', 'computers'")
            enumerated_objects = display_info(dce, serverHandle, info_type, debug, opnums_called)

        elif enumeration == 'summary':
            print("\nDomain Summary")
            print("--------------")
            summary = enumerated_objects[0]
            # Print Domain Info summary
            domain_info = summary.get('domain_info', {})
            print("Domain Information:")
            for key, value in domain_info.items():
                print(f"  {key}: {value}")
            print()
            print(f"Total Users:           {summary.get('total_users', 'N/A')}")
            print(f"Total Computers:       {summary.get('total_computers', 'N/A')}")
            print(f"Total Domain Groups:   {summary.get('total_domain_groups', 'N/A')}")
            print(f"Total Local Groups:    {summary.get('total_local_groups', 'N/A')}")
            print()
            print("Password Policy:")
            for key, value in summary.get('password_policy', {}).items():
                print(f"  {key}: {value}")
            print()
            print("Lockout Policy:")
            for key, value in summary.get('lockout_policy', {}).items():
                print(f"  {key}: {value}")
            print()

        else:
            # Handle regular enumerations (users/groups/computers)
            if isinstance(enumerated_objects[0], dict):
                max_length = max(
                    len(str(obj.get('username', 'N/A'))) for obj in enumerated_objects) if enumerated_objects else 25
                print(f"\n{'Username':<{max_length}} Details")
                print("-" * (max_length + 15))
                for obj in enumerated_objects:
                    if 'error' in obj:
                        print(f"{obj.get('username', 'N/A'):<{max_length}} ERROR: {obj['error']}")
                    else:
                        print(f"{obj.get('username', 'N/A'):<{max_length}} {obj.get('rid', 'N/A')}")
            else:
                max_length = max(len(str(obj[0])) for obj in enumerated_objects) if enumerated_objects else 25
                print(f"\n{'Member':<{max_length}} RID")
                print("-" * (max_length + 15))
                for obj in enumerated_objects:
                    if isinstance(obj, tuple) and len(obj) >= 2:
                        print(f"{obj[0]:<{max_length}} {obj[1]}")

    print("================================================================")
    print(f"{'Execution time:':<20}\t{duration:.2f} seconds")
    print(f"{'Destination target:':<20}\t{target}")
    print(f"{'Domain SID:':<20}\t{domainSidString}")
    print(f"{'Account:':<20}\t{input_username}")
    print(f"{'Enumerate:':<20}\t{enumeration}")
    print(f"{'Authentication:':<20}\t{auth_mode.upper()}")
    print(f"{'Execution status:':<20}\t{execution_status}")
    print(f"{'Number of objects:':<20}\t{len(enumerated_objects) if execution_status == 'success' else 0}")
    if opnums_param and opnums_called:
        print("OpNums called:")
        # Print a header
        print("  Name".ljust(35), "OpNum".ljust(6), "Access Mask")
        print("-" * 55)

        for item in opnums_called:
            # Example item formats you might see:
            #   "SamrConnect (OpNum 0, Access Mask: 0x00000031)"
            #   "SamrEnumerateDomainsInSamServer (OpNum 6)"
            #   "SamrCloseHandle"
            name_str = item
            opnum_str = "--"
            mask_str = "--"

            # Attempt to find something like "(OpNum 7"
            paren_idx = item.find("(OpNum ")
            if paren_idx != -1:
                # Extract the function name from the front
                name_str = item[:paren_idx].strip()
                # Grab the substring inside the parentheses, e.g. "OpNum 0, Access Mask: 0x00000031)"
                inside = item[paren_idx:].strip("()")  # e.g. "OpNum 0, Access Mask: 0x00000031"
                # Split by commas (or do more robust parsing if needed)
                parts = inside.split(",")
                if parts:
                    # First part should be "OpNum X"
                    first = parts[0].strip()
                    # e.g. first == "OpNum 0"
                    if first.startswith("OpNum "):
                        opnum_str = first[len("OpNum "):].strip()

                if len(parts) > 1:
                    # Possibly "Access Mask: 0x00000031"
                    second = parts[1].strip()
                    if second.startswith("Access Mask:"):
                        mask_str = second[len("Access Mask:"):].strip()

            # Print each line, adjusting spacing
            print("  " + name_str.ljust(33), opnum_str.ljust(5), mask_str)
    print("================================================================")

    # Optionally export data
    if export_file and execution_status == "success" and enumerated_objects:
        export_data(export_file, export_format, enumerated_objects)


if __name__ == "__main__":
    main()
