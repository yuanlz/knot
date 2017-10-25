#!/usr/bin/python
import sys
import xml.etree.ElementTree as ET

zones = dict()
policies = dict()

def opendnssec_knot_time_convert(time):
    #TODO: https: // wiki.opendnssec.org / display / DOCS20 / Date + Time + Durations

def process_kasp(root):
    global policies
    out = ''
    for policy in root:
        if policy.tag != "Policy":
            raise
        out = 'policy:\n  - id: ' + policy.attrib['name'] + '\n    manual: false\n'
        # TODO SIGNATURES, KEYS, ZONE, PARENT
        for item in policy:
            if item.tag == "Denial":
                if item[0].tag == "NSEC3":
                    # TODO: TTL, OptOut?
                    out += "    nsec3: true\n"
                    for nsec3item in item[0]:
                        if nsec3item.tag == "Resalt":
                            # TODO: how to process opendnssec time
                            out += "   nsec3-salt-lifetime: " + nsec3item.text + '\n'
                        elif nsec3item.tag == "Hash":
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


def opendnssec_to_knot(config):
    global zones, policies
    tree = ET.parse(config)
    root = tree.getroot()

    out = ''
    if root.tag == "KASP":
        process_kasp(root)
    elif root.tag == "ZoneList":
        process_zonelist(root)
    else:
        print("unsupported tag")
        exit(1)

    return out

def main(argv):
    try:
        out = '# Knot DNS configuration file generated from OpenDNSSEC configuration\n\n'
        for file in argv[1:]:
           opendnssec_to_knot(file)
    except Exception as e:
        print(e)
        exit(1)

    for policy in policies:
        out += policies[policy]
    for zone in zones:
        out += zones[zone]

    print(out)
    exit(0)

#TODO: kasp, zonefilelist, addns, singconf
if __name__ == "__main__":
    main(sys.argv)
