import subprocess
import json
import time
import os

local_host = '192.168.0.243'

def record_p2p_traffic(url, num_of_peers, pcapfile):
    timeout = 600

    host_ip = '127.0.0.1'
    port0 = 4443

    containers = []
    for i in range(num_of_peers):
        print("-----------start to initiate peer{0}-----------".format(i))
        port = 4443 + i
        name = "chrome"+str(i)
        container = WebContainer(name, port, host_ip)
        container.play_url(url)
        containers.append(container)


    print("-----------start recording docker 0 traffic------------")
    p = subprocess.Popen("timeout "+str(timeout)+" sudo tcpdump -i docker0 -w " +
                          str(pcap_file), shell=True)
    time.sleep(timeout)
    p.terminate()

    print("----------quit drivers-------------")
    for i in range(num_of_peers)
        containers[i].quit_driver()
    print("----------done----------------")

def parse_pcap_file(pcapfile, jsonfile):
    #tshark decode file
    if (not os.path.exists(jsonfile)):
        p =subprocess.Popen("tshark -r "+ pcapfile +" -Y 'stun' -T ek > "+ jsonfile, shell=True)
        time.sleep(60)

def parse_peer_ips(jsonfile):
    user_info = {}
    ip_set = set()
    if (os.path.exists(jsonfile)):
        with open(jsonfile) as f:
            for line in f:
                try:
                    info = json.loads(line.strip())
                    if ('layers' in info):
                        layers = info['layers']
                        ip_src = layers['ip']['ip_ip_src']
                        ip_dst = layers['ip']['ip_ip_dst']

                        user = None
                        ip = None
                        if ('stun' in layers):
                            stun = layers['stun']
                            if ('stun_attribute_stun_att_username' in stun):
                                user = stun['stun_attribute_stun_att_username']
                                user_info[user] = ip_src
                                if (ip_dst != local_host):
                                    ip_set.add(ip_dst)

                except Exception as e:
                    print(e, jsonfile)
                    pass
    else:
        print("tshark file not exists!")

    return ip_set


## =========Peer IP leak test ========

baseFolder = "./tcmdump"
if (not os.path.exists(baseFolder)):
    os.mkdir(baseFolder)

if __name__ == '__main__':
    url =sys.argv[1]
    pcapfile = "tcpdump/"+url+".pcap"
    if (not os.path.exists(pcapfile)):
        record_p2p_traffic(url, 2, pcapfile)
        time.sleep(600)

    if (os.path.exists(pacapfile)):
        jsonfile = pcapfile.replace('.pcap','.json')
        parse_pcap_file(pcapfile, jsonfile)
        ip_set = parse_peer_ips(jsonfile)

print("identified peer IPs:", len(ip_set))

print("done")
