#!/usr/bin/python
import sys
import xml.etree.ElementTree as ET
import re

zones = dict()
policies = dict()
keystores = dict()

def time_convert(time):
    items = re.split('(\d+)', time)
    outtime = ''
    tmptime = 0
    print(items)
    for i in range(0, len(items)):
        if items[i] == 'Y':
            tmptime += 365 * int(items[i - 1])
        elif items[i] == 'M':
            tmptime += 31 * int(items[i - 1])
        elif items[i] == 'D':
            tmptime += int(items[i - 1])
            outtime += str(tmptime) + 'd'
        if items[i] == 'H':
            outtime += items[i - 1] + 'h'
        elif items[i] == 'M':
            outtime += items[i - 1] + 'm'
        elif items[i] == 'S':
            outtime += items[i - 1] + 's'
    return outtime

def process_kasp(root):
    global policies
    out = ''
    for policy in root:
        if policy.tag != "Policy":
            raise
        out = 'policy:\n  - id: ' + policy.attrib['name'] + '\n    manual: false\n'
        # TODO SIGNATURES, KEYS, ZONE, PARENT, KEYSTORE FROM CONF
        for item in policy:
            if item.tag == "Denial":
                if item[0].tag == "NSEC3":
                    # TODO: TTL, OptOut?
                    out += "    nsec3: true\n"
                    for nsec3item in item[0]:
                        if nsec3item.tag == "Resalt":
                            # TODO: how to process opendnssec time
                            out += "    nsec3-salt-lifetime: " + time_convert(nsec3item.text) + '\n'
                            for hash in nsec3item:
                                if hash.tag == "Iterations":
                                    out += "    nsec3-iterations: " + hash.text + '\n'
                                elif hash.tag == "Salt":
                                    out += "    nsec3-salt-length: " + hash.attrib['length'] + '\n'

            policies[policy.attrib['name']] = out
    return out

def process_zonelist(root):
    global zones
    #TODO: SignerConfiguration, ADDNS
    for zone in root:
        if zone.tag != "Zone":
            raise
        out = 'zone:\n  - domain: ' + zone.attrib['name'] + '\n'
        name = zone.attrib['name']
        for item in zone:
            if item.tag == "Policy":
                out += '    dnssec-policy: ' + item.text + '\n'
            elif item.tag == "Adapters":
                for io in item:
                    for adapter in io:
                        if io.tag == "Input" and adapter.attrib['type'] == "DNS":
                            #TODO: ADDNS
                            out += ''
                        if io.tag == "Input" and adapter.attrib['type'] == "File":
                            out += '    file: ' + adapter.text + '\n'
                        if io.tag == "Output" and adapter.attrib['type'] == "File":
                            out += '    zonefile-sync: -1 ' \
                                   '# Knot doest not allow separate Input/Output'
        zones[name] = out

def process_config(root):
    global keystores

    for conf in root:
        #TODO: PEM?
        if conf.tag == "RepositoryList":
            for repo in conf:
                if repo.tag != 'Repository':
                    raise
                keystore = "keystore:\n  - id: "
                keystore += repo.attrib['name'] + "\n    backed: pkcs11\n    config: "
                token = 'token='
                pin = 'pin-value='
                lib = ''
                for item in repo:
                    if item.tag == "Module":
                        lib += item.text
                    elif item.tag == "TokenLabel":
                        token += item.text + ';'
                    elif item.tag == "PIN":
                        pin += item.text
                keystore += '"pkcs11:' + token +  pin + ' ' + lib + '"\n'
                keystores[repo.attrib['name']] = keystore



def opendnssec_to_knot(config):
    global zones, policies
    tree = ET.parse(config)
    root = tree.getroot()

    out = ''
    if root.tag == "KASP":
        process_kasp(root)
    elif root.tag == "ZoneList":
        process_zonelist(root)
    elif root.tag == "Configuration":
        process_config(root)
    else:
        print("unsupported tag")
        #exit(1)

    return out

def main(argv):
    #try:
    out = '# Knot DNS configuration file generated from OpenDNSSEC configuration\n\n'
    for file in argv[1:]:
        opendnssec_to_knot(file)
    #except Exception as e:
    #    print(e)
    #    exit(1)

    for policy in policies:
        out += policies[policy]
    for zone in zones:
        out += zones[zone]
    for keystore in keystores:
        out += keystores[keystore]

    print(out)
    exit(0)

#TODO: kasp, zonefilelist, addns, singconf
if __name__ == "__main__":
    main(sys.argv)
