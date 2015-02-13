#!/usr/bin/python3

# Firewall Rater Tool (Prototype)
# Nicholas Schmidt
# 12 Feb 2015
# Version 0.1: Initial File Creation

#Includes go here
import ipaddress

#Imports go here
from ipaddress import ip_address
from ipaddress import ip_network

#Functions go here

#Process IPTables Chain
def processIPTables (IPTables_input):
  if IPTables_input[0:5] == "Chain":
    print ("IPTables Chain " + IPTables_input.split()[1] + " found with " + str(len(IPTables_input.splitlines())) + " lines!")
    if IPTables_input.splitlines()[1] == "target     prot opt source               destination":
      print ("IPTables Chain header " + IPTables_input.split()[1] + " found! Beginning line-by-line processing...")
      if len(IPTables_input.splitlines()) > 2 :
	print("Do stuff")
      else:
	print("No IPTables Lines to process!")
	return 0
    else:
      print("No IPTables Header found!")
      return 0
  else:
    print("No IPTables Chain found!")
    return 0
  return 1

##Score Function - To be improved
def score (srcIP, destIP):
  # Modifier, TBD 
  modifier = 1
  return srcIP.num_addresses*destIP.num_addresses


#Main goes here
print(score(ip_network("192.168.1.1/32"),ip_network("192.168.1.2/31")))
print(processIPTables("Chain input_ext (1 references)\ntarget     prot opt source               destination\nDROP       all  --  anywhere             anywhere             PKTTYPE = broadcast"))