# PDN

This is the code repo of our paper: Stealthy Peer: Understanding and Mitigating Security Risks in Peer-Assisted Video Delivery.

# How to install

You should install docker, selenium (also web drivers), Wireshark to run our code.
 * docker: https://docs.docker.com/engine/install/
 * selenium: https://pypi.org/project/selenium/
 * tshark: https://tshark.dev/setup/install/

# How to run

 * apkDetector:
   <pre>python3 apk_detector_workflow_mp.py temp/ [androzoo_list.csv] pdn_signs.json results ./apktool [your_androzoo_key_path] -dt pdn_signs -ndep [num_of_detection_threads] -ndop [num_of_download_threads] -to 800000 -adf 2000-01-01 -bdf 2200-01-01</pre>
 * webDetector: <pre>python webDetector.py</pre>
 * webTest:  <pre>python free_riding.py</pre>

# Settings

 * wenDetector (settings.py):
	- chrome_driver: set your web driver path
	- domain_file: domains to be scanned

 * webTest:
	- set local_host to your local ip address

