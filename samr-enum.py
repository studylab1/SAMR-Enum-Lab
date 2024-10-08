#!/usr/bin/env python

import sys
import logging
import argparse
from impacket.examples import logger
from impacket import version
from impacket.dcerpc.v5 import transport, samr
from impacket.nt_errors import STATUS_MORE_ENTRIES
from impacket.dcerpc.v5.rpcrt import DCERPCException

# Define variables here
USERNAME = 'user01'
PASSWORD = 'LabUser1!'
DOMAIN = 'domain-a.lab'
TARGET = 'dc01.domain-a.lab'
USE_KERBEROS = False  # Set to False to use NTLM

class SAMRDump:
    def __init__(self, username='', password='', domain='', hashes=None, aesKey=None, doKerberos=False, kdcHost=None, port=445, csvOutput=False):
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__aesKey = aesKey
        self.__doKerberos = doKerberos
        self.__kdcHost = kdcHost
        self.__port = port
        self.__csvOutput = csvOutput
        if hashes is not None:
            self.__lmhash, self.__nthash = hashes.split(':')

    def dump(self, remoteName, remoteHost):
        """Dumps the list of users and shares registered at remoteName."""
        entries = []
        logging.info('Retrieving endpoint list from %s' % remoteName)
        stringbinding = r'ncacn_np:%s[\pipe\samr]' % remoteName
        logging.debug('StringBinding %s' % stringbinding)
        rpctransport = transport.DCERPCTransportFactory(stringbinding)
        rpctransport.set_dport(self.__port)
        rpctransport.setRemoteHost(remoteHost)
        if hasattr(rpctransport, 'set_credentials'):
            # This method exists only for selected protocol sequences.
            rpctransport.set_credentials(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash, self.__aesKey)
        rpctransport.set_kerberos(self.__doKerberos, self.__kdcHost)

        try:
            entries = self.__fetchList(rpctransport)
        except Exception as e:
            logging.critical(str(e))

        print(f"Total number of users: {len(entries)}")

    def __fetchList(self, rpctransport):
        dce = rpctransport.get_dce_rpc()
        entries = []
        dce.connect()
        dce.bind(samr.MSRPC_UUID_SAMR)
        try:
            resp = samr.hSamrConnect(dce)
            serverHandle = resp['ServerHandle']
            resp = samr.hSamrEnumerateDomainsInSamServer(dce, serverHandle)
            domains = resp['Buffer']['Buffer']
            logging.info("Looking up users in domain %s" % domains[0]['Name'])
            resp = samr.hSamrLookupDomainInSamServer(dce, serverHandle, domains[0]['Name'])
            resp = samr.hSamrOpenDomain(dce, serverHandle=serverHandle, domainId=resp['DomainId'])
            domainHandle = resp['DomainHandle']
            status = STATUS_MORE_ENTRIES
            enumerationContext = 0

            while status == STATUS_MORE_ENTRIES:
                try:
                    resp = samr.hSamrEnumerateUsersInDomain(dce, domainHandle, enumerationContext=enumerationContext)
                except DCERPCException as e:
                    if str(e).find('STATUS_MORE_ENTRIES') < 0:
                        raise
                    resp = e.get_packet()

                for user in resp['Buffer']['Buffer']:
                    r = samr.hSamrOpenUser(dce, domainHandle, samr.MAXIMUM_ALLOWED, user['RelativeId'])
                    info = samr.hSamrQueryInformationUser2(dce, r['UserHandle'], samr.USER_INFORMATION_CLASS.UserAllInformation)
                    entry = (user['Name'], user['RelativeId'], info['Buffer']['All'])
                    entries.append(entry)
                    samr.hSamrCloseHandle(dce, r['UserHandle'])

                enumerationContext = resp['EnumerationContext']
                status = resp['ErrorCode']

        except Exception as e:
            logging.critical("Error listing users: %s" % e)
        dce.disconnect()
        return entries

def main():
    logger.init()
    print(version.BANNER)

    remoteName = TARGET
    remoteHost = TARGET

    dumper = SAMRDump(USERNAME, PASSWORD, DOMAIN, None, None, USE_KERBEROS, None, 445, False)
    dumper.dump(remoteName, remoteHost)

if __name__ == '__main__':
    main()
