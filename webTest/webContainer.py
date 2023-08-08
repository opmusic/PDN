import os
import subprocess
from selenium import webdriver
from selenium.webdriver import ChromeOptions
from selenium.webdriver import FirefoxOptions
from selenium.webdriver.common.by import By

class WebContainer:
    def __init__(self, name, port, server_ip="127.0.0.1"):

        self.init_docker(name. port)
        self.driver = self.init_chrome_driver(server_ip)

    def init_docker(self, name, port):
        command = "docker run -d --name {0} -p {1}:4444 -v /dev/shm:/dev/shm selenium/standalone-chrome".format(name, port)
        os.open(command)
        time.sleep(5)

    def init_chrome_driver(self, server_ip):
        chrome_options = ChromeOptions()
        chrome_options.page_load_strategy = 'none'
        chrome_options.add_argument("--autoplay-policy=no-user-gesture-required")
        server_addr = "http://"+str(server_ip)
        driver = webdriver.Remote(command_executor=server_addr+":"+str(self.port)+"/wd/hub", options=chrome_options)

        return driver

    def init_firefox_driver(self, server_ip):
        firefox_options = FirefoxOptions()

        firefox_profile = webdriver.FirefoxProfile()
        firefox_profile.set_preference('permissions.default.image', 2)
        firefox_profile.set_preference('security.sandbox.content.level', 5)

        driver = webdriver.Firefox(executable_path="/u/tangsi/WebCrawler/geckodriver", options=firefox_options, firefox_profile=firefox_profile)

        return driver

    def play_url(self, url):

        video_url = url
        #add autoplay=true
        if ('autoplay=' in url):
            video_url = url.replace('autoplay=false','autoplay=true')
        elif ('?' in url):
            video_url = url+'&autoplay=true'
        else:
            video_url = url+'?autoplay=true'

        self.driver.get(video_url)
        time.sleep(1)

    def quit_driver(self):
        self.driver.quit()


    def load_url(self, url):
        video_url = url
        #add autoplay=false
        if ('autoplay=' in url):
            video_url = url.replace('autoplay=true','autoplay=false')
        elif ('?' in url):
            video_url = url+'&autoplay=false'
        else:
            video_url = url+'?autoplay=false'

        self.driver.get(video_url)
        time.sleep(1)

def set_proxy():
    # https://github.com/esplo/docker-local-ssl-termination-proxy
    # set up an https proxy to localhost

        print("-----------start an https proxy on localhost------------")
        p = subprocess.Popen("docker run -it \
              -e \"PORT=80\" \
              -p 443:443 \
              --rm \
              esplo/docker-local-ssl-termination-proxy", shell=True)
        time.sleep(10)
