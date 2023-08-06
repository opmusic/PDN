import sys
import os
import time
import json
import re
import logging
import requests
from bs4 import BeautifulSoup
import multiprocessing as mp


class webDetector:

    def __init__(self, signfile, logfile):
        self.domain = None
        self.resdir = None
        self.logger = self.set_logger(__name__, logfile)
        self.interLinks = {}
        self.jsLinks = {}
        self.signs = {}
        with open(signfile) as f:
            for line in f:
                info = json.loads(line.strip())
                for sign in info['signs']:
                    #if (sign[1] == 'high'):
                    patt = re.compile(sign[0], re.M | re.I)
                    self.signs[patt] = info['pname']

    def set_logger(self, logger_name, log_file, level=logging.INFO):
        FORMAT = "%(asctime)s [%(levelname)s] %(message)s"
        logger = logging.getLogger(logger_name)
        formatter = logging.Formatter(FORMAT)
        fileHandler = logging.FileHandler(log_file)
        fileHandler.setFormatter(formatter)

        logger.setLevel(level)
        logger.addHandler(fileHandler)

        return logger

    def set_paras(self, domain, resdir):
        self.domain = domain
        self.resdir = resdir
        linkfile = os.path.join(resdir,"_links")
        self.interLinks = self.read_links_from_file(linkfile)
        jsfile = os.path.join(resdir,"_js")
        self.jsLinks = self.read_links_from_file(jsfile)
        #self.jsLinks = self.check_jsfile(jsfile)

    def read_links_from_file(self, filename):
        results = {}
        if (os.path.exists(filename)):
            with open(filename) as f:
                for line in f:
                    segs = line.strip().split()
                    url = segs[0]
                    hash = segs[1]
                    results[hash] = url
        return results

    def check_jsfile(self, filename):
        self.logger.info("start to check domain: "+self.domain)
        results = set()
        for pagefile in os.listdir(self.resdir):
            if (pagefile.endswith(".html")):
                filepath = os.path.join(self.resdir, pagefile)
                r = open(filepath).read().strip()

                try:
                    soup = BeautifulSoup(r, 'html.parser')

                    for script in soup.find_all('script'):
                        src = script.get('src')
                        if (src and '.js' in src):
                            if (src.startswith('//')):
                                src = "http://" + src.strip('/')
                            elif (not src.startswith("http://")) and (not src.startswith("https://")):
                                src = "http://" + self.domain + "/"+src.strip('/')
                            results.add(src)
                except:
                    pass

        with open(filename,'w') as f:
            for url in results:
                f.write(url+'\n')

        return results

    def detect_text(self, text):
        for sign, provider in self.signs.items():
            m = re.search(sign, text)
            if (m):
                match_text = m.group(0)
                self.logger.info("found match text: " + match_text)
                return {'provider': provider, 'text': match_text, 'src': 'html'}
        return {}

    def detect_domain(self):
        self.logger.info("start to detect domain: "+ self.domain)
        for hash, url in self.interLinks.items():
            pagefile = os.path.join(self.resdir, hash+".html")
            if (os.path.exists(pagefile)):
                text = open(pagefile).read().strip()
                for sign,provider in self.signs.items():
                    m = re.search(sign, text)
                    if (m):
                        match_text = m.group(0)
                        self.logger.info("found match text: "+ match_text)

                        return {'url':url,'provider': provider,'text':match_text, 'src': 'html'}

        self.logger.info("start to detect js files in domain: " + self.domain)
        for hash, url in self.jsLinks.items():
            pagefile = os.path.join(self.resdir, hash)
            if (os.path.exists(pagefile)):
                text = open(pagefile).read().strip()
                for sign,provider in self.signs.items():
                    m = re.search(sign, text)
                    if (m):
                        match_text = m.group(0)
                        self.logger.info("found match text: "+ match_text)

                        return {'url':url,'provider': provider,'text':match_text, 'src': 'js'}

        return {}

    def get_jsfile(self, url):
        headers = {}
        headers['User-Agent'] = "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:65.0) Gecko/20100101 Firefox/65.0"
        headers["Content-Type"] = "application/javascript; charset=UTF-8"
        headers['Accept'] = "application/javascript,text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"

        for t in range(0,3):
            try:
                r = requests.get(url,timeout=1)
                if (r.status_code == 200):
                    #self.logger.info("get js file successfully: "+url)
                    return r.text
            except:
                pass

        self.logger.info("fail to get js file: "+url)
        return None

    def detect_js_text(self, text):
        if (text):
            for sign, provider in self.signs.items():
                m = re.search(sign, text)
                if (m):
                    match_text = m.group(0)
                    self.logger.info("found match text: " + match_text)
                    return {'provider': provider, 'text': match_text, 'src': 'js'}
        return {}

def detect_domainList(domainList, resfolder, signfile, outfile, logfile):
    a = webDetector(signfile,logfile)
    detect_results = []
    for domain in domainList:
        a.set_paras(domain, os.path.join(resfolder,domain))
        results = {}
        results['domain'] = domain
        res = a.detect_domain()
        results['info'] = res

        if (results['info']):
            results['is_hit'] = True
        else:
            results['is_hit'] = False
        detect_results.append(results)

    with open(outfile,'w') as f:
        for info in detect_results:
            f.write(json.dumps(info)+'\n')

if __name__ == '__main__':
    domainFile = "top_10K_video.txt"
    resFolder = "results"
    logFolder = 'logs'

    detect_file = "detect_results.json"
    signFile = 'web_signs.json'

    if (not os.path.exists(resFolder)):
        exit(-1)

    domain_list = []

    with open(domainFile) as f:
        for line in f:
            domain = line.strip().split()[0]
            domain_list.append(domain)

    num_proc = 5
    n = len(domain_list)

    jobs = []
    sub_len = int(n / num_proc)
    for i in range(num_proc):
        sub_list = domain_list[i * sub_len: (i + 1) * sub_len]
        logFile = os.path.join(logFolder, "detector" + str(i) + ".log")
        outFile = "detect_results_" + str(i)+".json"
        # parse_domain_one_process(sub_list, resFolder, logfile)
        p = mp.Process(target=detect_domainList, args=(sub_list, resFolder, signFile, outFile, logFile))
        p.start()
        jobs.append(p)

    for p in jobs:
        p.join()

    # merge result files
    with open(detect_file, 'a') as f:
        for i in range(num_proc):
            outfile = "detect_results_" + str(i) + ".json"
            with open(outfile) as o:
                for line in o:
                    f.write(line.strip() + '\n')
            os.remove(outfile)
    print("done")
