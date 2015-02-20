#!/usr/bin/env python3

# Firewall Rater Tool (Prototype)
# Nicholas Schmidt
# 12 Feb 2015

#Includes go here
import ipaddress

#Imports go here
from ipaddress import ip_address
from ipaddress import ip_network

#Functions go here

###LIST INTERPRETERS GO HERE###


##IPTABLES HERE##


#Process IPTables Chain
# takes a string, preferably multiline, but you want the entire chain.
#Returns a list, including the action, protocol, src/dest, score

def processIPTablesChain (IPTables_input):
    #if it's not a list, make it a list
    if type(IPTables_input) is list:
        IPTables_data= IPTables_input
    else:
        IPTables_data= IPTables_input.splitlines()
    
    #find the iptables chain - input verification step 1
    if IPTables_data[0].startswith("Chain"):
        #find the iptables header - input verification step 2
        if IPTables_data[1].startswith("target"):
            #after input verification for the chain and header is done, proceed to verify there are actual entries
            if len(IPTables_data) >= 3 :
                return_list = []
                return_list.append([IPTables_data[0].split()[1],"","","",""])
                #iterate through the entries, skipping chain/header line, proceed to process entries.
                #anywhere is assumed to be 0.0.0.0/0 as it's a keyword and that's what it means.
                #insert header line to returned list
                for iter_loop in range(len(IPTables_data)):
                    temp_var=IPTables_data[iter_loop]
                    if temp_var.startswith("Chain"):
                        continue
                    if temp_var.startswith("target"):
                        continue
                    if len(temp_var.split()) < 5:
                        continue
                    srcIP=""
                    dstIP=""
                    if temp_var.split()[3] == "anywhere":
                        srcIP= ip_network("0.0.0.0/0")
                    else:
                        srcIP= ip_network(temp_var.split()[3])
                    if temp_var.split()[4] == "anywhere":
                        dstIP= ip_network("0.0.0.0/0")
                    else:
                        dstIP= ip_network(temp_var.split()[4])
                    if temp_var.split()[0] == "DROP":
                        return_list.append(["DROP",temp_var.split()[1],srcIP,dstIP,scoreEntry(srcIP,dstIP,temp_var.split()[1],.00000000000000000001)])
                    elif temp_var.split()[0] == "ACCEPT" or temp_var.split()[0] == "LOG":
                        return_list.append(["PERMIT",temp_var.split()[1],srcIP,dstIP,scoreEntry(srcIP,dstIP,temp_var.split()[1],1)])
                    else:
                        return_list.append(["UNK",temp_var.split()[1],srcIP,dstIP,scoreEntry(srcIP,dstIP,temp_var.split()[1],1)])
                return return_list
            else:
                #if no chain found, return 0
                return 0
        else:
            #if no header found, return 1
            return 1
    else:
        #if no chain found, return 0
        return 0
    #if no known errors occur, but no list found, return 2
    return 2


##IPTables Read##
def readIPTablesOutput(iptables_data):
    return_list = []
    temp_list = []
    temp_list = splitByToken(iptables_data,"Chain")
    for i in temp_list:
        return_list.append(processIPTablesChain(i))
    return return_list


###UTILITY FUNCTIONS GO HERE###
#Score Function
#Takes 2 ip networks, a protocol ID, protocol port (if applicable, if not 0) and a modifier (if applicable, if not 1)

def scoreEntry (srcIP, destIP, proto, scoreMOD):
    known_protocols = { "udp" : 0.5,
            "tcp" : 0.5,
            "icmp" : 0.1}
    addressCountMod = srcIP.num_addresses*destIP.num_addresses*scoreMOD
    try:
        return addressCountMod*known_protocols[proto]
    except KeyError:
        return addressCountMod*1


#Print 2d array improvement

def print2DList (list_2d):
    for i in range(len(list_2d)):
        print(list_2d[i])


#Print 3d array improvement

def print3DList (list_3d):
    for i in range(len(list_3d)):
        if type(list_3d[i]) is list:
            print2DList(list_3d[i])


###IO GOES HERE###


#Open a file <file_name> if it exists. Return file as a string

def fileRead (filename_to_read):
    try:
        file_return_io = open(filename_to_read,"r")
        file_return_list = file_return_io.readlines()
        file_return_io.close()
        return file_return_list
    except OSError:
        print("File not found!")

#split list by token - used primarily for iptables -L sorting

def splitByToken(list_to_split,list_token):
    return_list = []
    list_temp = []
    for i in list_to_split:
        if i.startswith(list_token) and list_temp:
            return_list.append(list_temp[:])
            list_temp = []
        list_temp.append(i)
    return_list.append(list_temp)
    return return_list


###MAIN FUNCTIONALITY GOES HERE###


print3DList(readIPTablesOutput(fileRead("file-test")))
