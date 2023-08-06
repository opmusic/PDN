import time
import os
import sys
import subprocess
from webContainer import WebContainer


def record_container_stats_one(url, num_of_peers):
    timeout = 600

    host_ip = '127.0.0.1'
    port0 = 4443

    containers = []
    for i in range(num_of_peers):
        print("-----------start to initiate peer{0}-----------".format(i))
        port = 4443 + i
        name = "chrome"+str(i)
        container = WebContainer(name, port, host_ip)
        containers.append(container)

    containers[0].play_url(url)
    time.sleep(5)
    for i in range(1,num_of_peers):
        containers[i].play_url(url)

    print("-----------start recording container 0 traffic------------")
    log_file = "chrome1_peer" + str(num_of_peer) + ".log"
    p = subprocess.Popen("sudo echo -ne 'GET /containers/chrome1/stats HTTP/1.0\r\n\r\n' | " + "timeout " + str(
        timeout) + " sudo nc -U /var/run/docker.sock > " +
                          str(log_file), shell=True)

    time.sleep(timeout)
    p.terminate()

    print("----------quit drivers-------------")
    for i in range(num_of_peers)
        containers[i].quit_driver()
    print("----------done----------------")


def record_container_stats_all(url, num_of_peers):

    timeout = 600

    host_ip = '127.0.0.1'
    port0 = 4443

    containers = []
    for i in range(num_of_peers):
        print("-----------start to initiate peer{0}-----------".format(i))
        port = 4443 + i
        name = "chrome"+str(i)
        container = WebContainer(name, port, host_ip)
        containers.append(container)

    containers[0].play_url(url)
    time.sleep(5)
    for i in range(1,num_of_peers):
        containers[i].play_url(url)

    jobs = []
    for i in range(num_of_peers):
        print("-----------start recording container {0} traffic------------".format(i))
        name = "chrome"+srr(i)
        logfile = name+"_peer"+str(num_of_peers)+'.log'
        p = subprocess.Popen("sudo echo -ne 'GET /containers/{0}/stats HTTP/1.0\r\n\r\n' | " + "timeout " + str(
            timeout) + " sudo nc -U /var/run/docker.sock > " +
                              str(log_file).format(name), shell=True)

        jobs.append(p)

    time.sleep(timeout)

    print("----------quit drivers-------------")
    for i in range(num_of_peers):
        jobs[i].terminate()
        containers[i].quit_driver()
    print("----------done----------------")


if __name__ == '__main__':
    url =sys.argv[1]
    record_container_stats_all(url, 2)
