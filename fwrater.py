#!/usr/bin/python3

# Firewall Rater Tool (Prototype)
# Nicholas Schmidt
# 12 Feb 2015

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
            if len(IPTables_input.splitlines()) >= 3 :
                for iter_loop in range(len(IPTables_input.splitlines())):
                    temp_var=IPTables_input.splitlines()[iter_loop]
                    if temp_var[0:5] == "Chain":
                        print("Found the chain again!")
                        continue
                    if temp_var[0:6] == "target":
                        print("Found the header again!")
                        continue
                    srcIP=""
                    dstIP=""
                    print(temp_var.split())
                    if temp_var.split()[3] == "anywhere":
                        srcIP= ip_network("0.0.0.0/0")
                    else:
                        srcIP= ip_network(temp_var.split[3])
                    if temp_var.split()[4] == "anywhere":
                        dstIP= ip_network("0.0.0.0/0")
                    else:
                        dstIP= ip_network(temp_var.split()[4])
                    if temp_var.split()[0] == "DROP":
                        print("DROP statement " + srcIP + " " + dstIP + " score " + score(srcIP,dstIP,.00001))
                    elif temp_var.split()[0] == "ACCEPT" or temp_var.split()[0] == "LOG":
                        print("PERMIT/LOG statement " + srcIP + " " + dstIP + " score " + score(srcIP,dstIP,1))
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
def score (srcIP, destIP, scoreMOD):
    return srcIP.num_addresses*destIP.num_addresses*scoreMOD


#Main goes here
print(score(ip_network("192.168.1.1/32"),ip_network("192.168.1.2/31"),2.0))
print(processIPTables("Chain input_ext (1 references)\ntarget     prot opt source               destination\nDROP       all  --  anywhere             anywhere             PKTTYPE = broadcast"))
