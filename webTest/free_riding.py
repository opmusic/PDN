import time
import random
import os
from webContainer import *
from peer_ip_leak import parse_peer_ips

# free riding test: require two websites, url1 & url2. both integrated into same PDN API and play a customized video stream.
## for domain spoofing, modify /etc/localhost to redirect url1 to localhost

def free_riding_test(url1, url2, pcapfile):
    timeout = 60

    host_ip = '127.0.0.1'
    port0 = 4443

    containers = []
    for i in range(2):
        print("-----------start to initiate peer{0}-----------".format(i))
        port = 4443 + i
        name = "chrome"+str(i)
        container = WebContainer(name, port, host_ip)
        containers.append(container)

    containers[0].load_url(url1)
    containers[1].load_url(url2)


    print("-----------start recording docker 0 traffic------------")
    p = subprocess.Popen("timeout "+str(timeout)+" sudo tcpdump -i docker0 -w " +
                          str(pcap_file), shell=True)
    time.sleep(timeout)
    p.terminate()

    print("----------quit drivers-------------")
    for i in range(num_of_peers)
        containers[i].quit_driver()
    print("----------done----------------")

baseFolder = "./tcpdump"
if (not os.path.exists(baseFolder)):
    os.mkdir(baseFolder)

if __name__ == '__main__':
    url1 = sys.argv[1]
    url2 = sys.argv[2]

    ## turn on proxy for domain spoofing attack
    #set_proxy()
    pcapfile = "./tcpdump/free_ride.pcap"

    if (not os.path.exists(pcapfile)):
        free_riding_test(url1, url2, pcapfile)
        time.sleep(60)

    if (os.path.exists(pacapfile)):
        jsonfile = pcapfile.replace('.pcap','.json')
        parse_pcap_file(pcapfile, jsonfile)
        ip_set = parse_peer_ips(jsonfile)

        if (ip_set):
            print("detected free riding risk!")

    print("done")
