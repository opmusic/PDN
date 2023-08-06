""" Signature-based detection of apps
    This is a workflow consisting of the following steps:
    1. Load in signatures, apk ids, and previous detection results
    2. download apks if not locally exists
    3. detect if any signatures matched
    4. delete/move if no signatures matched
"""
import subprocess
import multiprocessing as mp
import threading
import hashlib
import glob
import os, sys
import logging
import shutil
import json
import argparse
import queue
import time
import re
import typing
import get_apk_from_androzoo as du
import datetime


class ApkSign(object):
    def __init__(
        self,
        sign_str,
        confidence,
        provider,
        type='str',
    ):
        self.sign_str = sign_str
        self.confidence = confidence
        self.provider = provider
        self.type = type

class Apk(object):
    """ Define apk meta data
    """
    def __init__(
        self,
        id: str,
        pkg_id: str,
        dex_date: str='1966-06-06',
        market: str='Unknown',
    ):
        self.id = id
        self.pkg_id = pkg_id
        self.dex_date = dex_date
        self.market = market
        # the last 6 characters in id
        self.base_dir = os.path.join(
            self.id[-6:-4],
            self.id[-4:-2],
            self.id[-2:],
        )
        self.name = '{pkg_id}_{dex_ds}_{hash}.apk'.format(
            pkg_id=self.pkg_id,
            dex_ds=self.dex_date,
            hash=self.id[-6:],
        )
        self.apk_file = os.path.join(
            self.base_dir,
            self.name,
        )

class ApkDetector(object):
    def __init__(
        self,
        apk_tool,
        detect_dir,
        apk_signs=None,
        encoding=None,
    ):
        self.apk_tool = apk_tool
        self.detect_dir = detect_dir
        self.apk_signs = apk_signs if apk_signs else []
        self.encoding=encoding if encoding else 'utf-8'

    # unpack the given apk file to the result directory
    def unpack_apk(self, src_file, result_dir) -> bool:
        try:
            if not (os.path.exists(src_file)):
                logging.warning("No such file %s",src_file)
            subprocess.run(
                args=[
                    self.apk_tool,
                    'd',
                    '-f',
                    '--only-main-classes', # only detect main classes
                    '-o',
                    result_dir,
                    src_file,
                ],
                env={'PATH':'/usr/bin'},
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            return True
        except Exception as e:
            logging.warning(
                'error when unpacking the given apk %s',
                src_file,
                e
            )
            return False

    # list all files recursively in the given directory
    def exhaust_files(self, src_dir):
        src_dir = src_dir.rstrip('/') + '/'
        pathname = src_dir + '**'
        # print(pathname)
        sub_dirs_files = glob.glob(pathname, recursive=True)
        result_dirs_files = []
        base_dir_len = len(src_dir)
        for sub_path in sub_dirs_files:
            result_dirs_files.append(sub_path[base_dir_len:])
        return result_dirs_files

    def detect(self, apk_file):
        media_re = re.compile('.*\.(png|jpeg|gif|jpg|mp3|mp4|dll|yml)$', re.I)
        dir_re = re.compile('.*(original|assets)/.*$', re.I)
        media_re = re.compile('.*\.(png|jpeg|gif|jpg|mp3|mp4)$', re.I)
        dir_re = None
        signs_to_match = set([item.sign_str for item in self.apk_signs])
        matched_signs = set()
        detect_start_time = time.time()
        apk_binary = open(apk_file, 'rb').read()
        # match the whole binary content
        for apk_sign in signs_to_match:
            apk_sign_binary = apk_sign.encode(
                encoding=self.encoding,
                errors='backslashreplace',
            )
            if apk_sign_binary in apk_binary:
                matched_signs.add(apk_sign)
        signs_to_match -= matched_signs
        if len(signs_to_match) != 0:
            #  unpack the apk file
            apk_hash = hashlib.md5()
            apk_hash.update(apk_binary)
            unpack_dir = os.path.join(
                self.detect_dir,
                apk_hash.hexdigest(),
            )
            if not os.path.exists(unpack_dir):
                os.makedirs(unpack_dir)
            unpack_start_time = time.time()
            unpack_result = self.unpack_apk(apk_file, unpack_dir)
            if unpack_result == False:
                logging.info('skip this apk because of unpack error')
                shutil.rmtree(unpack_dir)
                return None
            unpack_end_time = time.time()
            # exhaust all files in the unpacked dir
            sub_paths = self.exhaust_files(unpack_dir)
            new_sub_paths = [
                sub_path
                for sub_path in sub_paths
                if dir_re is None or (not dir_re.match(sub_path))
            ]
            sub_paths = new_sub_paths
            #logging.info('got %d unpacked files', len(sub_paths))
            # match unpacked files
            media_skip = 0
            for sub_path in sub_paths:
                signs_to_match -= matched_signs
                if len(signs_to_match) == 0:
                    break

                # conduct path matching
                for sign in signs_to_match:
                    if sign in sub_path:
                        matched_signs.add(sign)
                signs_to_match -= matched_signs
                if len(signs_to_match) == 0:
                    break

                # conduct content match for a given file
                sub_file = os.path.join(
                    unpack_dir,
                    sub_path,
                )
                if not os.path.isfile(sub_file):
                    continue
                # exclude images
                if media_re.match(sub_file):
                    media_skip += 1
                    continue
                file_content_binary = open(sub_file, 'rb').read()
                file_content = file_content_binary.decode(
                    encoding=self.encoding,
                    errors='backslashreplace',
                )
                for sign in signs_to_match:
                    if sign in file_content:
                        matched_signs.add(sign)
                signs_to_match -= matched_signs
                if len(signs_to_match) == 0:
                    break
            shutil.rmtree(unpack_dir)
            logging.debug(
                'unpack time cost %f, matching cost is %f, overall %f',
                unpack_end_time - unpack_start_time,
                time.time() - unpack_end_time,
                time.time() - detect_start_time,
            )

        matched_sign_objs = []
        for sign_obj in self.apk_signs:
            if sign_obj.sign_str in matched_signs:
                matched_sign_objs.append(sign_obj.__dict__)
        return matched_sign_objs

class ApkDetectionConfig(object):
    def __init__(
        self,
        work_dir,
        apk_tool,
        apk_signs,
        result_file,
        detect_tag='sign_v1',
        timeout=80000,
        encoding=None,
        is_delete=True,
    ):
        self.task_queue = mp.Queue()
        self.result_queue = mp.Queue()
        self.is_stop = False
        self.work_dir = work_dir
        self.apk_tool = apk_tool
        self.encoding = encoding if encoding else 'utf-8'
        self.apk_signs = apk_signs
        self.result_file = result_file
        self.timeout = timeout
        # whether to delete the apks if no hit
        self.is_delete = is_delete
        self.detect_tag = detect_tag
        self.detect_count = 0

class ApkDownloadConfig(object):
    def __init__(
        self,
        api_key,
        thread_num=10,
        timeout=80000,
        is_overwrite=False,
    ):
        self.api_key = api_key
        self.task_queue = mp.Queue()
        self.result_queue = mp.Queue()
        self.timeout = timeout
        self.is_overwrite = is_overwrite
        self.thread_num = thread_num
        self.download_count = 0

def apk_detection(
    ad_cfg, # ApkDetectionConfig
    interval=5,
):
    logging.info(
        'Detection process %s started',
        mp.current_process().name,
    )
    apk_detector = ApkDetector(
        apk_tool=ad_cfg.apk_tool,
        detect_dir=ad_cfg.work_dir,
        apk_signs=ad_cfg.apk_signs,
        encoding=ad_cfg.encoding,
    )
    start_time = time.time()
    while True:
        if time.time() - start_time >= ad_cfg.timeout:
            break
        is_empty = ad_cfg.task_queue.empty()
        if is_empty:
            time.sleep(interval)
            continue
        apk_file = None
        try:
            task_str = ad_cfg.task_queue.get_nowait()
            task = json.loads(task_str)
            apk_file = task['apk_file']
            d_result = apk_detector.detect(apk_file)
            if d_result is None and os.path.exists(apk_file):
                os.remove(apk_file)
                continue
            d_results = {
                'id': task['id'],
                'detection': list(d_result),
                'detect_tag': ad_cfg.detect_tag,
                'detection_time': time.time(),
                'apk_meta': task,
                'is_hit': len(d_result) > 0,
            }
            ad_cfg.result_queue.put(json.dumps(d_results))
        except Exception as e:
            logging.warning(
                'error when detecting apk: %s',
                e,
            )
            if apk_file and os.path.exists(apk_file):
                os.remove(apk_file)
            time.sleep(interval)
    logging.info('quit apk detection proces')

# apk downloading process
def apk_download(
    apk_download_cfg: ApkDownloadConfig,
    interval: int=5,
):
    logging.info(
        'Download process %s started',
        mp.current_process().name,
    )
    start_time = time.time()
    download_workers = []
    for i in range(apk_download_cfg.thread_num):
        worker = threading.Thread(
            target=apk_download_thread,
            args=(
                apk_download_cfg,
            ),
        )
        download_workers.append(worker)
        worker.start()
    while True:
        time_cost = time.time() - start_time
        if time_cost >= apk_download_cfg.timeout:
            break
        time.sleep(interval)
    time.sleep(interval)
    logging.info('quit apk download process')


def apk_download_thread(
    apk_download_cfg: ApkDownloadConfig,
    interval: int=5,
):
    cfg = apk_download_cfg
    start_time = time.time()
    while True:
        if time.time() - start_time >= cfg.timeout:
            break
        is_empty = cfg.task_queue.empty()
        if is_empty:
            time.sleep(interval)
            continue
        apk_file = None
        try:
            task_str = cfg.task_queue.get_nowait()
            task = json.loads(task_str)
            apk_id = task['id']
            apk_file = task['apk_file']
            apk_dir = os.path.dirname(apk_file)
            if os.path.exists(apk_file):
                if not cfg.is_overwrite:
                    cfg.result_queue.put(task_str)
                    continue
            if not os.path.exists(apk_dir):
                os.makedirs(apk_dir)
            download_result = du.download_apk(
                apk_id,
                apk_file,
                cfg.api_key,
            )
            if download_result:
                cfg.result_queue.put(task_str)
        except Exception as e:
            logging.warning(
                'errror during downloading %s',
                e,
            )
            time.sleep(interval)
            if apk_file and os.path.exists(apk_file):
                os.remove(apk_file)

    logging.info('quit download thread')


def download_result_phase(
    apk_download_cfg: ApkDownloadConfig,
    apk_detect_cfg: ApkDetectionConfig,
    interval :int=5,
):
    start_time = time.time()
    download_count = 0
    while True:
        if time.time() - start_time >= apk_download_cfg.timeout:
            break
        is_empty = apk_download_cfg.result_queue.empty()
        if is_empty:
            time.sleep(interval)
            continue
        try:
            task = apk_download_cfg.result_queue.get_nowait()
            apk_download_cfg.download_count += 1
            download_count += 1
            apk_detect_cfg.task_queue.put(task)
            if download_count % 100 == 0:
                logging.info(
                    'download %d apks',
                    download_count,
                )
        except Exception as e:
            logging.warning(
                'error when parsing download results: %s',
                e,
            )
            time.sleep(interval)
            continue

def detect_result_phase(
    ad_cfg: ApkDetectionConfig,
    interval :int=5,
):
    result_fd = open(ad_cfg.result_file, 'a')
    result_count = 0
    start_time = time.time()
    delete_count = 0
    while True:
        try:
            if time.time() - start_time >= ad_cfg.timeout:
                break
            if ad_cfg.result_queue.empty():
                time.sleep(interval)
                continue
            result_item = ad_cfg.result_queue.get_nowait()
            result_count += 1
            ad_cfg.detect_count += 1
            if result_count % 50 == 0:
                logging.info(
                    """
                    dump detect results for %d apks with time cost %d seconds,
                    %d in the queue, %d deleted, %d in the task queu,
                    """,
                    result_count,
                    time.time() - start_time,
                    ad_cfg.result_queue.qsize(),
                    delete_count,
                    ad_cfg.task_queue.qsize(),
                )
            result_fd.write(result_item + '\n')
            result_fd.flush()
            result_obj = json.loads(result_item)
            if ad_cfg.is_delete and result_obj['is_hit'] == False:
                if os.path.exists(result_obj['apk_meta']['apk_file']):
                    os.remove(result_obj['apk_meta']['apk_file'])
                    delete_count += 1
        except Exception as e:
            logging.info('error when saving detection results: %s', e)
            time.sleep(interval)
            continue
    logging.info(
        'quit detect result dumping with %d done, and time cost %d seconds',
        result_count,
        time.time() - start_time,
    )
    result_fd.close()

def load_androzoo_apks(
    apk_file,
    before_ds='2000-01-01',
    after_ds='2017-01-01',
) -> typing.Dict[str, Apk]:
    date_format='%Y-%m-%d'
    after_date_filter = datetime.datetime.strptime(after_ds, date_format)
    before_date_filter = datetime.datetime.strptime(before_ds, date_format)
    apk_dict = {}
    # load in download tasks
    with open(apk_file, 'r') as fd:
        line_num = 0
        for line in fd:
            line_num += 1
            if line_num == 1:
                continue
            attrs = line.strip().split(',')
            sha256 = attrs[0].lower()
            dex_ds = attrs[3].split(' ')[0]
            market = attrs[-1]
            is_target = False
            if after_date_filter:
                if len(dex_ds) == 0: # some didn't have dex_ds
                    continue
                dex_date = datetime.datetime.strptime(dex_ds, date_format)
                if after_date_filter < dex_date:
                    is_target = True
            if before_date_filter:
                if len(dex_ds) == 0: # some didn't have dex_ds
                    continue
                dex_date = datetime.datetime.strptime(dex_ds, '%Y-%m-%d')
                if before_date_filter > dex_date:
                    is_target = True
            if (after_date_filter is not None or before_date_filter is not None) and is_target == False:
                continue
            pkg_id = attrs[5].strip('""')
            apk_dict[sha256] = Apk(
                id=sha256,
                pkg_id=pkg_id,
                dex_date=dex_ds,
                market=market,
            )
    return apk_dict

if __name__ == '__main__':
    format_str = '%(asctime)s - %(levelname)s - %(message)s -%(funcName)s'
    #logging.basicConfig(level=logging.DEBUG, format=format_str)
    logging.basicConfig(level=logging.INFO, format=format_str)
    parser = argparse.ArgumentParser()
    parser.add_argument('apk_base_dir') # where to store those apks
    parser.add_argument('apk_list_file') # androzoo apk list
    parser.add_argument('apk_sign_file') # sign file with confidence level
    parser.add_argument('result_dir') # result directory to store detection results
    parser.add_argument('apk_tool')
    parser.add_argument('api_key_file')
    parser.add_argument('-dt', '--detect_tag', type=str, default='sign_v1')
    parser.add_argument('-ndep', '--num_detect_processes', type=int, default=10)
    parser.add_argument('-ndop', '--num_download_processes', type=int, default=2)
    parser.add_argument('-ndot', '--num_download_threads', type=int, default=10)
    parser.add_argument('-to', '--timeout', type=int, default=80000)
    parser.add_argument('-adf', '--after_date_filter', type=str, default=None, help='format Y-m-d, e.g, 2017-01-01')
    parser.add_argument('-bdf', '--before_date_filter', type=str, default=None, help='format Y-m-d, e.g, 2017-01-01')
    parser.add_argument('-odf', '--old_detection_file', type=str, default=None)
    options = parser.parse_args()
    apk_base_dir = options.apk_base_dir
    apk_list_file = options.apk_list_file
    apk_sign_file = options.apk_sign_file
    result_dir = options.result_dir
    apk_tool = options.apk_tool
    api_key_file = options.api_key_file
    detect_tag = options.detect_tag
    num_detect_processes = options.num_detect_processes
    num_download_processes = options.num_download_processes
    num_download_threads = options.num_download_threads
    timeout = options.timeout
    before_ds = options.before_date_filter
    after_ds = options.after_date_filter
    old_detection_file = options.old_detection_file

    if not os.path.exists(result_dir):
        os.makedirs(result_dir)
    result_file = os.path.join(
        result_dir,
        'detection_results.json'
    )
    # load in apk signatures
    apk_signs = []
    with open(apk_sign_file, 'r') as fd:
        for line  in fd:
            p_obj = json.loads(line.strip())
            provider = p_obj['pname']
            for sign_item in p_obj['signs']:
                sign = sign_item[0]
                confidence = sign_item[1]
                apk_signs.append(
                    ApkSign(
                        sign_str=sign,
                        provider=provider,
                        confidence=confidence,
                    )
                )
    apk_sign_str_set = set([sign.sign_str for sign in apk_signs])
    logging.info(
        'loaded %d apk signs, %d unique sign strs',
        len(apk_signs),
        len(apk_sign_str_set),
    )
    api_key = open(api_key_file, 'r').read().strip()
    apk_download_cfg = ApkDownloadConfig(
        api_key=api_key,
        thread_num=num_download_threads,
        timeout=timeout,
    )
    apk_detect_cfg = ApkDetectionConfig(
        work_dir=os.path.join(
            result_dir,
            'temp',
        ),
        apk_tool=apk_tool,
        apk_signs=apk_signs,
        result_file=result_file,
        timeout=timeout,
        detect_tag=detect_tag,
    )

    # set up detect workers
    detect_workers = []
    for index in range(num_detect_processes):
        detect_worker = mp.Process(
            target=apk_detection,
            args=(
                apk_detect_cfg,
            ),
        )
        detect_workers.append(detect_worker)
        detect_worker.start()
    logging.info(
        'start %d detection processes',
        num_detect_processes,
    )

    # set up download workers
    download_workers = []
    for index in range(num_download_processes):
        download_worker = mp.Process(
            target=apk_download,
            args=(
                apk_download_cfg,
            )
        )
        download_workers.append(download_worker)
        download_worker.start()
    logging.info(
        'start %d download processes, each with %d threads',
        num_download_processes,
        num_download_threads,
    )

    # set up threads in main process to process download
    # and detection results
    download_result_thread = threading.Thread(
        target=download_result_phase,
        args=(
            apk_download_cfg,
            apk_detect_cfg,
        ),
    )
    download_result_thread.start()
    detect_result_thread = threading.Thread(
        target=detect_result_phase,
        args=(
            apk_detect_cfg,
        ),
    )
    detect_result_thread.start()
    start_time = time.time()
    # load in apk id and file path
    apk_dict = load_androzoo_apks(
        apk_list_file,
        before_ds,
        after_ds,
    )
    logging.info(
        'loaded %d apks',
        len(apk_dict),
    )
    # loaded in already done results
    done_apks = set()
    if os.path.exists(result_file):
        with open(result_file, 'r') as fd:
            for line in fd:
                result_obj = json.loads(line.strip())
                done_apks.add(result_obj['id'])
    old_new_detect_apks = set()
    old_no_detect = 0
    old_deprecate = 0
    if old_detection_file is not None:
        with open(old_detection_file, 'r') as fd:
            for line in fd:
                result_obj = json.loads(line.strip())
                apk_id = result_obj['id']
                if apk_id in done_apks:
                    continue
                old_detect_tag = result_obj['detect_tag']
                old_sign_strs = set([
                    detect['sign_str'] for detect in result_obj['detection']
                ])
                # deprecated signatures
                if len(old_sign_strs) > 0 and len(old_sign_strs & apk_sign_str_set) == 0:
                    result_obj['detection'] = []
                    result_obj['is_hit'] = False
                    old_deprecate += 1
                # keep the old detect tag for further distinguish
                # result_obj['detect_tag'] = detect_tag
                if len(result_obj['detection']) == 0:
                    old_no_detect += 1
                    apk_detect_cfg.result_queue.put(json.dumps(result_obj))
                    done_apks.add(apk_id)
                    continue
                old_new_detect_apks.add(apk_id)

    logging.info(
        """
        old detection results:
        no need for detection: %d,
        deprecated detection: %d,
        need new detection: %d,
        """,
        old_no_detect,
        old_deprecate,
        len(old_new_detect_apks),
    )
    apks_to_detect = set(apk_dict.keys()) - done_apks
    logging.info(
        'loaded %d apk ids, %d done, %d left to detect',
        len(apk_dict),
        len(done_apks),
        len(apks_to_detect),
    )
    if len(apks_to_detect) == 0:
        logging.info('no apks to detect, quit')
        sys.exit(0)

    # put downloaded apks in the queue of detection
    # put others in the queue of download
    apks_to_download = set()
    download_task_count = 0
    detect_task_count = 0
    for apk_id in old_new_detect_apks:
        apk_obj = apk_dict[apk_id]
        apk_obj.apk_file = os.path.join(
            apk_base_dir,
            apk_obj.base_dir,
            apk_obj.name,
        )
        if os.path.exists(apk_obj.apk_file):
            apk_detect_cfg.task_queue.put(
                json.dumps(apk_obj.__dict__)
            )
            detect_task_count += 1
        else:
            apks_to_download.add(apk_id)
            download_task_count += 1
    apks_to_detect -= old_new_detect_apks
    for apk_id in apks_to_detect:
        apk_obj = apk_dict[apk_id]
        apk_obj.apk_file = os.path.join(
            apk_base_dir,
            apk_obj.base_dir,
            apk_obj.name,
        )
        if os.path.exists(apk_obj.apk_file):
            apk_detect_cfg.task_queue.put(
                json.dumps(apk_obj.__dict__)
            )
            detect_task_count += 1
        else:
            apks_to_download.add(apk_id)
            download_task_count += 1
    logging.info(
        'fed %d download tasks, %d detection tasks',
        download_task_count,
        detect_task_count,
    )
    task_unit = 1000
    while True:
        if time.time() - start_time >= timeout:
            break
        new_download_task_unit = task_unit - apk_detect_cfg.task_queue.qsize() - apk_download_cfg.task_queue.qsize()
        if (
            len(apks_to_download) == 0
            or new_download_task_unit <= 0
        ):
            time.sleep(10)
            continue
        for index in range(new_download_task_unit):
            apk_id = apks_to_download.pop()
            apk_obj = apk_dict[apk_id]
            apk_download_cfg.task_queue.put(
                json.dumps(apk_obj.__dict__)
            )
        time.sleep(10)


    # wait for workers to finish
    for worker in download_workers:
        worker.join()
    download_result_thread.join()
    for worker in detect_workers:
        worker.join()
    detect_result_thread.join()

    # output result stats
    logging.info(
        """
        overall stats
        Apks to detect: %d,
        Download: %d,
        Detection: %d,
        time cost is %d seconds
        """,
        len(apks_to_detect),
        apk_download_cfg.download_count,
        apk_detect_cfg.detect_count,
        int(time.time() - start_time),
    )
    logging.info('overall quit')
