import subprocess
import json
import time
import os

#remove local host ip
local_host = '192.168.0.243'

def parse_pcap_file(pcapfile, jsonfile):
    #tshark decode file
    if (not os.path.exists(jsonfile)):
        p =subprocess.Popen("tshark -r "+ pcapfile +" -Y 'stun or dtls' -T ek > "+ jsonfile, shell=True)
        time.sleep(60)

def detect_pdn_traffic(file):
    peer_ip = set()
    if (os.path.exists(jsonfile)):
        with open(jsonfile) as f:
            for line in f:
                try:
                    info = json.loads(line.strip())
                    if ('layers' in info):
                        layers = info['layers']
                        ip_src = layers['ip']['ip_ip_src']
                        ip_dst = layers['ip']['ip_ip_dst']

                        ip = None
                        if ('stun' in layers):
                            stun = layers['stun']
                            if ('stun_attribute_stun_att_ipv4' in stun):
                                ip = stun['stun_attribute_stun_att_ipv4']
                        if (ip != local_host):
                            peer_ip.add(ip)

                        if ('dtls' in layers):
                            if (ip_src in peer_ip or ip_dst in peer_ip):
                                print("identified pdn traffic from peer: ", ip_src, " to peer: ", ip_dst)
                                return True
                except Exception as e:
                    print(e)
                    pass
    else:
        print("tshark file not exists!")

    return False
