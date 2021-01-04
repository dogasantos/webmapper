#!/usr/bin/env python
# -*- coding: utf-8 -*-
# /*
#
#
# */

__version__ = '1.0'

import sys
import os
import argparse
import nmap
import ipaddress

global CPPATH
CPPATH=os.path.dirname(os.path.realpath(__file__))

# how nmap tags a web service in the "name" field
web_service_names = ["http","http-proxy","https","https-alt","ssl"]

def readFile(filename):
    #yeh yeh yeh, toctou i know i know
    content = False
    if os.path.isfile(filename) == False:
        return False
    with open(filename, "r") as f:
        content = f.readlines()
    return content

def saveFile(filename,content):
    print("  + Saving report: {}".format(str(filename)))
    with open(filename, "w") as h:
        for item in content:
            h.write(item + "\n")

def nmap_LoadXmlObject(filename):
    nm = nmap.PortScanner()
    nxo = open(filename, "r")
    xmlres = nxo.read()
    nm.analyse_nmap_xml_scan(xmlres)
    nxo.close()
    return nm
 
def getHostnameFromIp(massdnsstruct,ip):
    host_ips = list()
    for node in massdnsstruct:
        if str(node['ipaddr'].rstrip()) == str(ip.rstrip()):
            host_ips.append(str(node['vhost'].rstrip()))
            print("    + Found hostname: {}".format(str(node['vhost'].rstrip())))
    return host_ips

def isGlobalIpv4(ipaddr):
    try:
        ipObj = ipaddress.ip_address(unicode(ipaddr))
    except:
        try:
            ipObj = ipaddress.ip_address(ipaddr)
        except:
            return False
    if ipObj.is_private == False and ipObj.version == 4:
        return True
    else:
        return False

def parseMassdnsStruct(massdnsreport):
    m_file = readFile(massdnsreport)
    aux=list()
    for massdns_item in m_file:
        hosts=dict()
        line = massdns_item.replace('. ', ',').replace(' ', ',')
        if line.split(',')[1] == "CNAME": # just ignore cnames as you can take it directly from massdnsreport + grep
            continue
        host_massdns = line.split(',')[0].rstrip('\n')
        ip_massdns = line.split(',')[2].rstrip('\n')

        if isGlobalIpv4(ip_massdns):
            hosts['vhost'] = host_massdns
            hosts['ipaddr'] = ip_massdns
            aux.append(hosts)
    return aux

def FindWeb(massdnsreport, nmapObj):
    weblist = list()
    if massdnsreport is not False:
        massdnsstruct = parseMassdnsStruct(massdnsreport)
    else:
        massdnsstruct = False

    for ip in nmapObj.all_hosts():
        print("  + Parsing target: {}".format(str(ip)))

        if massdnsstruct:
            vhostlist = getHostnameFromIp(massdnsstruct, ip)
        else:
            vhostlist = ''
        openports = nmapObj[ip]['tcp'].keys()
        for port in openports:
            service_details = nmapObj[ip]['tcp'][port]
            for wtag in web_service_names:
                if wtag == service_details['name']:
                    proto = "http"
                    if service_details['name'] == 'ssl' \
                            or 'https' in service_details['name'] \
                            or service_details['tunnel'] == "ssl":
                        proto = "https"

                    if len(vhostlist) > 0:
                        for vhost in vhostlist:
                            weblist.append(proto + "://" + vhost + ":" + str(port))
                    else:
                        weblist.append(proto + "://" + ip + ":" + str(port))

    weblist = list(set(weblist))
    return weblist


def banner():
    print("webmapper "+str(__version__)+" @ dogasantos")
    print("-------------------------------------------------------")
    print("parse nmap xml report and get all web services running ")
    print("-------------------------------------------------------")

def parser_error(errmsg):
    banner()
    print("Usage: python " + sys.argv[0] + " [Options] use -h for help")
    print("Error: %s" %errmsg)
    sys.exit(1)

def parse_args():
    parser = argparse.ArgumentParser(epilog='\tExample: \r\npython ' + sys.argv[0] + " -n <nmap report file> -m <massdns report file> -o <output file>")
    parser.error = parser_error
    parser._optionals.title = "Options:"
    parser.add_argument('-n', '--nmapreport', help="nmap xml report file", required=True)
    parser.add_argument('-m', '--massdns', help="massdns report file (ip - hostname) so we can get the proper hostname for each ip address", required=False)
    parser.add_argument('-o', '--output', help="Output is a text file containing hosts in the format proto://ip-or-host:port (with a .web suffix)", required=False)
    return parser.parse_args()


if __name__ == "__main__":

    args = parse_args()
    nmapreport = args.nmapreport
    massdnsreport = args.massdns
    output = args.output

    print(massdnsreport)
    banner()
    nmapObj = nmap_LoadXmlObject(nmapreport)

    if os.path.isfile(nmapreport) == True and os.path.getsize(nmapreport) > 0:
        nmapObj = nmap_LoadXmlObject(nmapreport)
        print("  + Nmap report successfully loaded")
    else:
        print("[x] Nmap report not found. Please review.")
        sys.exit(1)
    if nmapObj:
        #list_of_webservers_found = WebDiscovery(nmapObj, massdnsreport, user_verbose)
        if massdnsreport:
            webhosts=FindWeb(massdnsreport, nmapObj)
        else:
            webhosts=FindWeb(False, nmapObj)

        saveFile(output, webhosts)
        print("[*] Done.")




