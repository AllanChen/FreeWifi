from __future__ import print_function
import subprocess
import re
import sys
import argparse
import os
from collections import defaultdict

import netifaces
from netaddr import EUI, mac_unix_expanded
from wireless import Wireless
from tqdm import tqdm

NO_SSID = 'No SSID is currently available. Connect to the network first.'


def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


def run_process(cmd, err=False):
    err_pipe = subprocess.STDOUT if err else open(os.devnull, 'w')
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=err_pipe)
    while True:
        retcode = p.poll()
        line = p.stdout.readline()
        yield line
        if retcode is not None:
            break


def main(args):
    parser = argparse.ArgumentParser(
        description='Find active users on the current wireless network.')
    parser.add_argument('-p', '--packets',
                        default=1000,
                        type=int,
                        help='How many packets to capture.')
    parser.add_argument('-r', '--results',
                        default=None,
                        type=int,
                        help='How many results to show.')
    parser.add_argument('-v', '--verbose',
                        action='store_true',
                        help='Print sniffed data instead of showing progress bar.')
    args = parser.parse_args()

    try:
        wireless = Wireless()
        ssid = wireless.current()
        if ssid is None:
            eprint(NO_SSID)
            return
        eprint('SSID: {}'.format(ssid))
    except:
        eprint('Couldn\'t get current wireless SSID.')
        raise

    network_macs = set()
    try:
        gw = netifaces.gateways()['default'][netifaces.AF_INET]
        iface = gw[1]
        gw_arp = subprocess.check_output(['arp', '-n', str(gw[0])])
        gw_arp = gw_arp.decode('utf-8')
        gw_mac = re.search(' at (.+) on ', gw_arp).group(1)
        gw_mac = EUI(gw_mac, dialect=mac_unix_expanded)
        network_macs.add(gw_mac)
        eprint('Gateway: {}'.format(gw_mac))
    except KeyError:
        eprint('No gateway is available: {}'.format(netifaces.gateways()))
    except:
        eprint('Error getting gateway mac address. Did you run `sudo chmod o+r /dev/bpf*`?')

    bssid_re = re.compile(' BSSID:(\S+) ')

    mac_re = re.compile('(SA|DA|BSSID):(([\dA-F]{2}:){5}[\dA-F]{2})', re.I)
    length_re = re.compile(' length (\d+)')
    client_macs = set()
    data_totals = defaultdict(int)

    cmd = 'tcpdump -i {} -Ile -c {}'.format(iface, args.packets).split()
    try:
        bar_format = '{n_fmt}/{total_fmt} {bar} {remaining}'
        progress = run_process(cmd)
        if not args.verbose:
            progress = tqdm(progress,
                            total=args.packets,
                            bar_format=bar_format)
        for line in progress:
            line = line.decode('utf-8')

            # find BSSID for SSID
            if ssid in line:
                bssid_matches = bssid_re.search(line)
                if bssid_matches:
                    bssid = bssid_matches.group(1)
                    if 'Broadcast' not in bssid:
                        bssid = EUI(bssid, dialect=mac_unix_expanded)
                        bssid.dialect = mac_unix_expanded
                        if args.verbose and bssid not in network_macs:
                            eprint('SSID: {} BSSID: {}'.format(ssid, bssid))
                        network_macs.add(bssid)

            # count data packets
            length_match = length_re.search(line)
            if length_match:
                length = int(length_match.group(1))
                mac_matches = mac_re.findall(line)
                if mac_matches:
                    macs = set([EUI(match[1], dialect=mac_unix_expanded) for match in mac_matches])
                    leftover = macs - network_macs
                    if len(leftover) < len(macs):
                        for mac in leftover:
                            data_totals[mac] += length
                            if args.verbose and mac not in client_macs:
                                eprint('Client: {} Length: {}'.format(mac, length))
                            client_macs.add(mac)

    except subprocess.CalledProcessError:
        eprint('Error collecting packets.')
        raise
    except KeyboardInterrupt:
        pass

    totals_sorted = sorted(data_totals.items(),
                           key=lambda x: x[1],
                           reverse=True)

    eprint('Total of {} user(s)'.format(len(totals_sorted)))

    for mac, total in reversed(totals_sorted[:args.results]):
        mac.dialect = mac_unix_expanded
        if total > 0:
            print('{}\t{} bytes'.format(mac, total))


if __name__ == '__main__':
    from sys import argv

    try:
        main(argv)
    except KeyboardInterrupt:
        pass
    sys.exit()
