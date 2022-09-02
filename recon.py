###################################
#Developer: Parthiv Patel
#Date: 26/3/2022
#Version: v2.1.0
###################################

import scapy.all as s

#Method to calculate the mode of a given list
def mode(ls):
    counts = {}
    for item in ls:
        if item in counts:
            counts[item] += 1
        else:
            counts[item] = 1
    return [key for key in counts.keys() if counts[key] == max(counts.values())]

#Method to check for a Geometric Progression
def check_gp(lst):
    length = len(lst)
    common_ratio = lst[1]/lst[0]
    for i in range(2, length):
        if (lst[i]/lst[i - 1] != common_ratio) and (lst[i]-1/lst[i-1] != common_ratio):
            return False

    return True


#Test whether the given URL/IP responds to ICMP pings and if it does analyze the behaviour of the responses
def icmp_test(dest):

    #Declare Variables
    ping_response = False
    ip_id = []
    diff = []
    #Send an ICMP packet with a sample payload to test whether the server responds back
    a = s.IP(dst=dest)/s.ICMP()/"Hello"
    pkt = s.sr1(a, verbose=0 ,timeout=10)

    #If it responds then it is confirmed that server responds to ICMP pings else the server does not responds to ICMP pings
    if(pkt):
        ping_response = True
        print("The server " + dest + " responds to ICMP pings\n")
        print("The TTL value of the ICMP response is: " + str(pkt.ttl) + "\n")

        #Sending 5 ICMP ping packets to check the IP-ID of the responses
        for i in range(5):
            p = s.sr1(a,verbose=0, timeout=10)
            if p:
                ip_id.insert(i, p.id)
        for j in range(1,len(ip_id)):
            diff.insert(j, abs(ip_id[j] - ip_id[j-1]))
        if min(mode(diff)) > 100:
            print("The IP ID in the replies of ICMP packets sent to "+ dest +"  is random\n")
        elif min(mode(diff)) == 0:
            print("The IP ID in the replies of ICMP packets sent to "+ dest +"  is zero\n")
        else:
            print("The IP ID in the replies of ICMP packets sent to "+ dest +" is incremental\n")
    
    else:
        print("Does not respond to ICMP pings\n")
    
    return ping_response

        
def TCP_test(dest):

    #Declare Variables
    TCP_response = False
    ip_id = []
    diff = []
    cap_time = []
    cap_time_diff = []

    #Send a TCP packet with port 80 to test whether the server responds back
    b = s.IP(dst=dest)/s.TCP(dport=80)
    pkt = s.sr1(b, verbose=0, timeout=10)

    #If the packet responds back then analyze the TTL and windows size for OS fingerprinting
    if(pkt) and pkt[1].flags == "SA":
        print("The TTL value in TCP response is: " + str(pkt.ttl) + "\n")
        print("The window size in TCP response is: " + str(pkt.window) + "\n")
        if(pkt.ttl < 70):
            if(pkt.window < 6000):
                print("The OS is probably Linux 2.4 or 2.6\n")
            elif(pkt.window < 17000):
                print("The OS is probably OpenBSD\n")
            elif(pkt.window < 35000):
                print("The OS is probably Linux Kernal 2.2\n")
            else:
                print("The OS is probably FreeBSD or MAC\n")
        elif(pkt.ttl < 200):
            if(pkt.window < 10000):
                print("The OS is probably Windows 7, Vista or Server 8\n")
            elif(pkt.window < 25000):
                print("The OS is probably Windows 2000\n")
            else:
                print("The OS is probably Windows XP\n")
        else:
            if(pkt.window < 6000):
                print("The OS is probably Cisco Router\n")
            else:
                print("The OS is probably Solaris 7\n")
        TCP_response = True
        print("Port 80 on " + dest + " is open\n")

        #Start capturing the retransmissions if any
        ip_addr = pkt.src
        capture = s.sniff(filter="host " + ip_addr, timeout=50)
        for k in range(len(capture)):
            cap_time.insert(k, capture[k].time)
        
        #If there are any retransmissions then there are no syn cookies on deployed by the server/service on port 80 
        #If there are no retransmission then there are syn cookies deployed by the server/service on port 80
        if len(capture) > 0:
            print("SYN-Cookies are not deployed by service running on port 80 on " + dest + "\n")
            print("Maximum observed packets retransmitted by service on TCP port 80 is " + str(len(capture)) + "\n")
            for i in range(len(capture)):
                if i == 0:
                    cap_time_diff.insert(i, round(capture[i].time - pkt.time))
                else:
                    cap_time_diff.insert(i, round(capture[i].time - capture[i-1].time))
            if len(cap_time_diff) > 1:
                gp = check_gp(cap_time_diff)
            else:
                gp = False
            if gp:
                print("The retransmission occurs with exponential increase in the time of sent packets\n")
            else:
                print("The retransmission does not occur with a fixed pattern\n")
            
            print(str(pkt.time) + "\n")
            for j in range(len(cap_time)):
                if j < len(cap_time_diff):
                    print(str(cap_time[j]) + "  " + str(cap_time_diff[j]) + "\n")
                else:
                    print(str(cap_time[j]) + "\n")
        else:
            syn_cookie = True
            print("SYN-Cookies deployed by service running on port 80 on " + dest + "\n")
        

        #Send 5 TCP packets to analyze the behaviour of IP-IDs in the response of TCP packets
        i = 0
        
        while i < 5:
            p = s.sr1(b,verbose=0, timeout=20)
            if p:
                ip_id.insert(i, p.id)
            else:
                break
            i += 1
        if(i < 3 and len(capture) < 3):
                print("The IP-IDs for TCP packets are: \n" + str(pkt.id) + "\n")
                for x in range(len(capture)):
                    print(str(capture[x].id) + "\n")
                for y in range(len(ip_id)):
                    print(str(ip_id[y]) + "\n")
        elif(i < 5 and len(capture) >= 3):
            for j in range(len(capture)-1):
                diff.insert(j, (capture[j+1].id - capture[j].id))
            if (min(mode(diff)) < 0 or min(mode(diff)) > 5000):
                print("The IP ID in the replies of TCP packets sent to "+ str(dest) +" is random\n")
                for x in range(len(capture)):
                    print("The IDs are: " + str(capture[x].id) + "\n")
            elif min(mode(diff)) == 0:
                print("The IP ID in the replies of TCP packets sent to "+ str(dest) +" is zero\n")
            else:
                print("The IP ID in the replies of TCP packets sent to "+ str(dest) +" is incremental\n")
                for x in range(len(capture)):
                    print("The IDs are: " + str(capture[x].id) + "\n")
        else:
            for j in range(len(ip_id)-1):
                diff.insert(j, abs(ip_id[j+1] - ip_id[j]))
            if min(mode(diff)) > 100:
                print("The IP ID in the replies of TCP packets sent to "+ str(dest) +" is random\n")
                for x in range(len(ip_id)):
                    print("The IDs are: " + str(ip_id[x]) + "\n")
            elif min(mode(diff)) == 0:
                print("The IP ID in the replies of TCP packets sent to "+ str(dest) +" is zero\n")
            else:
                print("The IP ID in the replies of TCP packets sent to "+ str(dest) +" is incremental\n")
                for x in range(len(ip_id)):
                    print("The IDs are: " + str(ip_id[x]) + "\n")
    else:
        print("Cannot determine results for port 80 on " + str(dest))
        
    return TCP_response

        
if __name__ == "__main__":

        #Take the input as URL/IP
        destination = input("Enter the Destination URL/IP Address: \n")
        try:
            #Performing ICMP and TCP tests
            print("-----------  Performing ICMP Ping test on " + str(destination) + "  -----------\n")
            t1 = icmp_test(dest=destination)
            print("-----------  Performing TCP test on " + str(destination) + "  -----------\n")
            t2 = TCP_test(dest=destination)
            print("----------- Finish -----------\n")
        except:
            print("Invalid URL/IP provided!")
