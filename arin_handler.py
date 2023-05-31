import argparse
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
import textwrap

def process_line(line, include_cidr, include_orgname, include_asn):
    line = line.strip()
    if not line:
        return None

    command = ['whois', '-h', 'whois.arin.net', '--', 'n', '!', line]
    output = subprocess.check_output(command).decode('utf-8')
    lines = output.strip().split('\n')
    entry = []

    for line in lines:
        line = line.strip()
        if include_cidr and line.startswith('CIDR:'):
            _, value = line.split(':', 1)
            cidrs = value.strip().split(', ')  # Break multiple CIDR entries into separate lines
            entry.extend(cidrs)
        elif include_orgname and line.startswith('OrgName:'):
            _, value = line.split(':', 1)
            entry.append(value.strip())
        elif include_asn and line.startswith('OriginAS:'):
            _, value = line.split(':', 1)
            if value.strip():
                asns = value.strip().split(', ')  # Break multiple ASN entries into separate lines
                entry.extend(asns)

    return entry

def arin_handler_info(include_cidr, include_orgname, include_asn):
    entries = []
    try:
        with ThreadPoolExecutor() as executor:
            futures = []
            for line in sys.stdin:
                future = executor.submit(process_line, line, include_cidr, include_orgname, include_asn)
                futures.append(future)

            for future in futures:
                entry = future.result()
                if entry:
                    entries.extend(entry)
    except KeyboardInterrupt:
        print("\nOperation interrupted by user. Exiting...")

    return entries

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='ARIN Whois Information')
    parser.add_argument('--cidr', action='store_true', help='Include CIDR information')
    parser.add_argument('--orgname', action='store_true', help='Include OrgName information')
    parser.add_argument('--asn', action='store_true', help='Include ASN information')
    args = parser.parse_args()

    include_cidr = args.cidr
    include_orgname = args.orgname
    include_asn = args.asn

    entries = arin_handler_info(include_cidr, include_orgname, include_asn)
    output = "\n".join(entries)
    print(output)
