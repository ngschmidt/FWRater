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
# takes a string, preferably multiline, but you want the entire chain.
#Returns a list, including the action, protocol, src/dest, score
def processIPTables (IPTables_input):
    #find the iptables chain - input verification step 1
    if IPTables_input[0:5] == "Chain":
        #find the iptables header - input verification step 2
        if IPTables_input.splitlines()[1] == "target     prot opt source               destination":
            #after input verification for the chain and header is done, proceed to verify there are actual entries
            if len(IPTables_input.splitlines()) >= 3 :
                return_list = []
                return_list.append([IPTables_input.splitlines()[0].split()[1],"","","",""])
                #iterate through the entries, skipping chain/header line, proceed to process entries.
                #anywhere is assumed to be 0.0.0.0/0 as it's a keyword and that's what it means.
                #insert header line to returned list
                for iter_loop in range(len(IPTables_input.splitlines())):
                    temp_var=IPTables_input.splitlines()[iter_loop]
                    if temp_var[0:5] == "Chain":
                        continue
                    if temp_var[0:6] == "target":
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
                        return_list.append(["DROP",temp_var.split()[1],srcIP,dstIP,score_entry(srcIP,dstIP,temp_var.split()[1],.00000000000000000001)])
                    elif temp_var.split()[0] == "ACCEPT" or temp_var.split()[0] == "LOG":
                        return_list.append(["PERMIT",temp_var.split()[1],srcIP,dstIP,score_entry(srcIP,dstIP,temp_var.split()[1],1)])
                    else:
                        return_list.append(["UNK",temp_var.split()[1],srcIP,dstIP,score_entry(srcIP,dstIP,temp_var.split()[1],1)])
                return return_list
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

#Score Function
#Takes 2 ip networks, a protocol ID, protocol port (if applicable, if not 0) and a modifier (if applicable, if not 1)
def score_entry (srcIP, destIP, proto, scoreMOD):
    return srcIP.num_addresses*destIP.num_addresses*scoreMOD


#Main goes here
print(processIPTables("Chain input_ext (1 references)\n" + \
        "target     prot opt source               destination\n" + \
        "DROP       all  --  anywhere             anywhere             PKTTYPE = broadcast\n" + \
        "ACCEPT     udp  --  anywhere             anywhere             udp dpt:domain"))
