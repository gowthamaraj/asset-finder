#! /usr/bin/env python3

from ipaddress import IPv4Network
import random
import argparse
from scapy.all import ICMP, IP, sr1, TCP

parser = argparse.ArgumentParser(description='Asset Finder Script!!!')
parser.add_argument('-i','--ip', help='Host IP',required=False)
parser.add_argument('-n','--network', help='Network Range (x.y.z.z/24)',required=False)

args = parser.parse_args()


def port_scan(host):
	# Send SYN with random Src Port for each Dst port
	port_range = [22, 23, 80, 443, 3389]
	for dst_port in port_range:
		src_port = random.randint(1025,65534)
		# constructing packet
		resp = sr1(
		IP(dst=host)/TCP(sport=src_port,dport=dst_port,flags="S"),timeout=1,
		verbose=0,
		)
		# Packet is dropped by the firewall or host
		if resp is None:
			print(f"{host}:{dst_port} is filtered (silently dropped).")

		elif(resp.haslayer(TCP)):
			if(resp.getlayer(TCP).flags == 0x12):
			    # Send a gratuitous RST to close the connection
			    # Create gratuitous RST Packet
			    send_rst = sr(
				IP(dst=host)/TCP(sport=src_port,dport=dst_port,flags='R'),
				timeout=1,
				verbose=0,
			    )
			    print(f"{host}:{dst_port} is open.")

		elif (resp.getlayer(TCP).flags == 0x14):
		    print(f"{host}:{dst_port} is closed.")

		elif(resp.haslayer(ICMP)):
		# ICMP unreachable
			if(
			    int(resp.getlayer(ICMP).type) == 3 and
			    int(resp.getlayer(ICMP).code) in [1,2,3,9,10,13]
			):
			    print(f"{host}:{dst_port} is filtered (silently dropped).")
            

def network_scan(network):
	# make list of addresses out of network, set live host counter
	addresses = IPv4Network(network)
	live_count = 0

	# Send ICMP ping request, wait for answer
	for host in addresses:
		if (host in (addresses.network_address, addresses.broadcast_address)):
		# Skip network and broadcast addresses
			continue

		resp = sr1(
		IP(dst=str(host))/ICMP(),
		timeout=2,
		verbose=0,
		)

		if resp is None:
			print(f"{host} is down or not responding.")
		elif (
			int(resp.getlayer(ICMP).type)==3 and
			int(resp.getlayer(ICMP).code) in [1,2,3,9,10,13]
			):
			print(f"{host} is blocking ICMP.")
		else:
			print(f"{host} is responding.")
			port_scan(host)
			live_count += 1

	print(f"{live_count}/{addresses.num_addresses} hosts are online.")
	
	
if args.ip is not None:
	port_scan(args.ip)
if args.network is not None:
	network_scan(args.network)
