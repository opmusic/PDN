import subprocess
import json
import time
import os

ip_set = set()
user_info = {}

baseFolder = "../../tcpdump"
def parse_pcap_file(file):
    pcapfile = os.path.join(baseFolder, file)

    jsonfile = pcapfile.replace('.pcap','.json')
    #tshark decode file
    if (not os.path.exists(jsonfile)):
        p =subprocess.Popen("tshark -r "+ pcapfile +" -J 'stun udp ip' -Y stun -T ek > "+ jsonfile, shell=True)
        time.sleep(60)

    #print(jsonfile)
    with open(jsonfile) as f:
        for line in f:
            try:
                info = json.loads(line.strip())
                if ('layers' in info):
                    layers = info['layers']
                    ip_src = layers['ip']['ip_ip_src']
                    ip_dst = layers['ip']['ip_ip_dst']

                    user = None
                    if ('stun' in layers):
                        stun = layers['stun']
                        if ('stun_attribute_stun_att_username' in stun):
                            user = stun['stun_attribute_stun_att_username']

                        #ip_set.add(ip_src)
                        if (user):
                            if (user in user_info):
                                #if (ip_src not in user_info[user] or ip_dst not in user_info[user]):
                                    #print(user_info[user], ip_src, ip_dst)
                                user_info[user].add(ip_src)
                                user_info[user].add(ip_dst)
                            else:
                                user_info[user] = set([ip_src, ip_dst])
                            ip_set.add(ip_src)
                            ip_set.add(ip_dst)
                            #print(ip_src, ip_dst, user)
            except Exception as e:
                print(e)
                pass

#parse_pcap_file('huya_20220128_1.pcap')

print("done")
#remove your own IP address
#ip_set.remove('192.168.0.243')
print(ip_set, len(ip_set))

# save ip_list
"""
ipfile = os.path.join(baseFolder,'ip_list')
with open(ipfile,'w') as f:
    for ip in ip_set:
        f.write(ip+'\n')
"""
