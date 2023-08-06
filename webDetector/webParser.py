import time
import os
import csv
import json
import random
import hashlib
import logging
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
from urllib.parse import urljoin
import multiprocessing as mp
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver import ChromeOptions
from selenium.webdriver import FirefoxOptions
from selenium.webdriver.common.by import By
from selenium.common.exceptions import NoSuchElementException
from webDetector import webDetector
import settings

class webParser:
    def __init__(self, logfile):
        self.domain = None
        self.resdir = None
        self.logger = self.set_logger(__name__, logfile)
        self.interLinks = {}
        self.jsFiles = {}
        self.detector = None

    def set_logger(self, logger_name, log_file, level=logging.INFO):
        FORMAT = "%(asctime)s [%(levelname)s] %(message)s"
        logger = logging.getLogger(logger_name)
        formatter = logging.Formatter(FORMAT)
        fileHandler = logging.FileHandler(log_file)
        fileHandler.setFormatter(formatter)
        logger.setLevel(level)
        logger.addHandler(fileHandler)
        return logger

    def set_paras(self, domain, resdir, detector=None):
        self.domain = domain

        if (not os.path.exists(resdir)):
            os.mkdir(resdir)
        self.resdir = resdir

        #linkfile = os.path.join(self.resdir, "_links")
        self.interLinks = {}

        #jsfile = os.path.join(self.resdir, "_js")
        self.jsFiles = {}

        self.detector = detector

    def hash(self, str):
        return hashlib.md5(str.encode('utf-8')).hexdigest()

    def save_dict_to_json(self, info, filename):
        with open(filename, 'w') as f:
            for val in info.values():
                f.write(json.dumps(val) + "\n")

    def norm_url(self,base_url, url):
        # convert  example.com to http://example.com
        url = urljoin(base_url, url.strip())
        if (url.startswith("https://")):
            url = "http://"+url[8:]
        url = url.strip('/')
        return url

    def get_pagesource(self, url, pagefile):
        if (os.path.exists(pagefile)):
            text = open(pagefile).read().strip()
            return text

        ## Firefox
        #firefox_options = FirefoxOptions()
        #firefox_options.add_argument("--headless")

        #firefox_profile = webdriver.FirefoxProfile()
        #firefox_profile.set_preference('permissions.default.image', 2)
        #firefox_profile.set_preference('security.sandbox.content.level', 5)
        # Chrome
        chrome_options = ChromeOptions()
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--headless")
        chrome_options.add_argument("--disable-gpu")

        chrome_prefs = {}
        chrome_prefs["profile.default_content_settings"] = {"images": 2}
        chrome_prefs["profile.managed_default_content_settings"] = {"images": 2}
        chrome_options.experimental_options["prefs"] = chrome_prefs

        try:
            #driver = webdriver.Firefox(executable_path=settings.firefox_driver,
            #                           options=firefox_options, firefox_profile=firefox_profile)
            driver = webdriver.Chrome(executable_path=settings.chromedriver,
                                                                options=chrome_options)
            driver.set_page_load_timeout(30)

            start = time.time()
            driver.get(url)
            text = driver.page_source.strip()
            self.logger.info("%s seconds to load url: %s", str(time.time() - start), url)
            driver.quit()

            # save html file
            #with open(pagefile, 'w') as f:
            #    f.write(text)
            #self.logger.info("save file successfully: " + pagefile)
            return text
        except Exception as e:
            self.logger.warning("error when parsing url: " + url + ", " + str(e))
            driver.quit()
            return None

    def get_jsfile(self, url, jsfile):
        if (os.path.exists(jsfile)):
            text = open(jsfile).read().strip()
            return text
        try:
            r = requests.get(url, timeout=3)
            if (r.status_code == 200):
                self.logger.info("get js file successfully: " + url)

                # save js file
                #with open(jsfile, 'w') as f:
                #    f.write(r.text.strip())
                #self.logger.info("save file successfully: " + jsfile)
                return r.text.strip()
        except Exception as e:
            self.logger.info("fail to get js file: " + url+", "+str(e))
            return None

    def parse_internal_url(self, url, pagefile, curr_depth, max_depth):
        text = self.get_pagesource(url, pagefile)
        if (text):
            # detect html code
            res = self.detector.detect_text(text)
            if (res):
                # save html file
                with open(pagefile, 'w') as f:
                    f.write(text)
                self.logger.info("save file successfully: " + pagefile)

                res['url'] = url
                return res

            soup = BeautifulSoup(text.strip(), 'html.parser')
            # detect js files
            if (soup.find('video')):
                for script in soup.find_all('script'):
                    src = script.get('src')
                    if (src):
                        src = self.norm_url(url,src)
                        if ('.js' in src and src not in self.jsFiles):
                            self.jsFiles[src] = {'url': url, 'js': src, 'hash': self.hash(src)}
                            jsfile = os.path.join(self.resdir, self.jsFiles[src]['hash'])
                            text = self.get_jsfile(src, jsfile)
                            res = self.detector.detect_js_text(text)
                            if (res):
                                # save js file
                                with open(jsfile, 'w') as f:
                                    f.write(text.strip())
                                self.logger.info("save file successfully: " + jsfile)

                                res['url'] = url
                                return res

                self.logger.info("get js files: " + str(len(self.jsFiles)))
            else:
                self.logger.info("no video tag found in "+url)

            # get interal links
            if (curr_depth < max_depth):
                for elem in soup.find_all('a'):
                    href = elem.get('href')
                    if (href):
                        raw_link = self.norm_url(url,href)
                        href_domain = raw_link[7:].split('/')[0]
                        #ignore video files
                        is_video = False
                        video_types = ['.mp3','.mp4','.flv','.webm','.swf']
                        for t in video_types:
                            if (t in raw_link):
                                is_video = True
                        # remove link parameters
                        key = raw_link.split('#')[0].split('?')[0]
                        if (self.domain in href_domain and key not in self.interLinks and not is_video):
                            self.interLinks[key] = {'url': raw_link, 'hash': str(self.hash(raw_link)), 'depth': curr_depth}
                self.logger.info("get internal links: "+str(len(self.interLinks)))

        return {}

    def parse_domain(self, depth):
        timeout = 600
        start = time.time()
        home_url = "http://"+self.domain
        res = {}
        self.interLinks[home_url] = {'url': home_url, 'hash': str(self.hash(home_url)), 'depth': 0}

        res['domain'] = self.domain
        res['error'] = None
        res['detect_results'] = {}
        try:
            curr_depth = 0
            while (curr_depth < depth):
                temp_links = [t['url'] for t in self.interLinks.values() if t['depth'] == curr_depth]
                for url in temp_links:
                    pagefile = os.path.join(self.resdir, str(self.hash(url)) + ".html")
                    # res = self.parse_static_html(url, pagefile, curr_depth+1, depth)
                    res['detect_results'] = self.parse_internal_url(url, pagefile, curr_depth + 1, depth)
                    if (res['detect_results']):
                        break
                    if (time.time() - start >= timeout):
                        self.logger.info("timeout to parse domain: %s", self.domain)
                        break

                curr_depth += 1
        except Exception as e:
            self.logger.warning("error when parsing domain: %s, %s", self.domain, e)
            res['error'] = True

        linkfile = os.path.join(self.resdir, "linkFiles.json")
        self.save_dict_to_json(self.interLinks, linkfile)
        jsfile = os.path.join(self.resdir, "jsFiles.json")
        self.save_dict_to_json(self.jsFiles, jsfile)
        if (res['detect_results']):
            res['is_hit'] = True
        else:
            res['is_hit'] = False

        self.logger.info("%s seconds to parse domain: %s", str(time.time() - start), self.domain)
        return res

def parse_domain_one_process(url_list, resfolder, signfile, outfile, logfile, depth):
    a = webParser(logfile)
    detector = webDetector(signfile,logfile)

    with open(outfile,'a') as f:
        for url in url_list:
            domain = url
            #print(url)
            a.set_paras(url, os.path.join(resfolder,domain), detector)
            res = a.parse_domain(depth)
            f.write(json.dumps(res)+"\n")

if __name__ == '__main__':
    domain_file = settings.domain_file
    resfolder = "results"
    logfolder = "logs"
    signfile = "web_signs.json"

    if (not os.path.exists(resfolder)):
        os.mkdir(resfolder)

    if (not os.path.exists(logfolder)):
        os.mkdir(logfolder)

    detected_domains = set()

    detectfile = "detect_results.json"
    if (os.path.exists(detectfile)):
        with open(detectfile) as f:
            for line in f:
                info = json.loads(line.strip())
                domain = info['domain']
                detected_domains.add(domain)

    #with open(domain_file) as f:
    #    for line in f:
    #        domain = line.strip()
    #        if (domain not in detected_domains):
    #            domain_list.append(domain)

    num_proc = 1
    depth = 3
    n = len(domain_list)

    sub_len = int(n/num_proc)
    jobs = []
    for i in range(num_proc):
        sub_list = domain_list[i*sub_len: (i+1)*sub_len]
        logfile = os.path.join(logfolder, "parser"+str(i)+".log")
        outfile = "detect_results_proc_"+str(i)+".json"
        #parse_domain_one_process(sub_list, resFolder, logfile)
        p = mp.Process(target=parse_domain_one_process, args=(sub_list,resfolder, signfile, outfile, logfile, depth,))
        p.start()
        jobs.append(p)

    for p in jobs:
        p.join()

    #merge result files
    with open(detectfile,'a') as f:
        for i in range(num_proc):
            outfile = "detect_results_proc_"+str(i)+".json"
            with open(outfile) as o:
                for line in o:
                    f.write(line.strip()+'\n')
            os.remove(outfile)
    print("done")
