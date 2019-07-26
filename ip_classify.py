#!/usr/bin/env python3

import re
import sys


def is_ipaddr(ipaddr):
    ipaddr_list = ipaddr.split(".")
    if not len(ipaddr_list) == 4:
        return False
    for octet in ipaddr_list:
        try:
            octet = int(octet)
        except:
            return False
        if not octet >= 0 or not octet <= 255:
            return False
    
    return True


def is_nwaddr(ipaddr):
    if not is_ipaddr(ipaddr):
        return False
    if ipaddr.split(".")[3] != "0":
        return False

    return True


def is_broadcast(ipaddr):
    if not is_ipaddr(ipaddr):
        return False
    if ipaddr.split(".")[3] != "255":
        return False

    return True


def is_private(ipaddr):
    if not is_ipaddr(ipaddr):
        return False
    # Class A
    if re.search("^10\.",ipaddr) != None:
        return True
    # Class B
    if re.search("^172\.(1[6-9]|2[0-9]|3[0-1])\.",ipaddr) != None:
        return True
    # Class C
    if re.search("^192\.168\.",ipaddr) != None:
        return True

    return False


def is_local(ipaddr):
    if not is_ipaddr(ipaddr):
        return False
    # Localhost IP address
    if re.search("^127\.",ipaddr) != None:
        return True

    return False


def is_test(ipaddr):
    if not is_ipaddr(ipaddr):
        return False
    if re.search("^192\.0\.2\.",ipaddr) != None:
        return True
    if re.search("^198\.51\.100\.",ipaddr) != None:
        return True
    if re.search("^203\.0\.113\.",ipaddr) != None:
        return True

    return False
    

def is_multicast(ipaddr):
    if not is_ipaddr(ipaddr):
        return False
    if re.search("^2(2[4-9]|3[0-9])\.",ipaddr) == None:
        return False
    
    return True


def is_special(ipaddr):
    if not is_ipaddr(ipaddr):
        return False
    if re.search("^0\.0\.0\.0$",ipaddr) != None:
        return True
    # ISP Shared Address
    if re.search("^100\.(6[4-9]|[7-9][0-9]|1[0-1][0-9]|12[0-7])\.",ipaddr) != None:
        return True
    # Localhost IP address
    if is_local(ipaddr):
        return True
    # Link-local IP address
    if re.search("^169\.254\.",ipaddr) != None:
        return True
    # IETF Protocol Assignments
    if re.search("^192\.0\.0\.",ipaddr) != None:
        return True
    # 6to4 IP address
    if re.search("^192\.88\.99\.",ipaddr) != None:
        return True
    # Benchmark Test IP address
    if re.search("^198\.1[8-9]\.",ipaddr) != None:
        return True
    if re.search("^2[4-5][0-9]\.",ipaddr) != None:
        return True
    # Multicast IP address
    if is_multicast(ipaddr):
        return True
    # Sample IP Address
    if is_test(ipaddr):
        return True

    return False

def is_public(ipaddr):
    if not is_ipaddr(ipaddr):
        return False
    if is_private(ipaddr) or is_special(ipaddr):
        return False

    return True


def main():
    argv = sys.argv
    argc = len(argv)
    if argc != 2:
        print("Usage: %s IPaddress" % argv[0])
        exit(1)
    ipaddr = argv[1]
    print("IP address : %s" % is_ipaddr(ipaddr))
    print("Network IP address : %s" % is_nwaddr(ipaddr))
    print("Broadcast IP address : %s" % is_broadcast(ipaddr))
    print("Private IP address : %s" % is_private(ipaddr))
    print("Public IP address : %s" % is_public(ipaddr))
    print("Localhost IP address : %s" % is_local(ipaddr))
    print("Test IP address : %s" % is_test(ipaddr))
    print("Multicast IP address : %s" % is_multicast(ipaddr))
    print("Special IP address : %s" % is_special(ipaddr))



if __name__ == '__main__':
    main()
