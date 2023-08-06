import requests
import hashlib
import time
import logging
import threading
import queue
import sys, os
import traceback
import datetime
''' utils to download apks from androzoo
'''

global_download_task_queue = queue.Queue()
global_download_result_queue = queue.Queue()
global_is_stop = False
global_overall_start_time = time.time()
global_download_done_count = 0
global_download_error_count = 0


def download_apk(
    sha256,
    result_file,
    api_key,
    request_session=None,
    chunk_size=10240*1024,
    timeout=(60, 60),
):
    url = 'https://androzoo.uni.lu/api/download?apikey={api_key}&sha256={sha256}'.format(
        api_key=api_key,
        sha256=sha256,
    )
    start_time = time.time()
    if request_session is None:
        response = requests.get(url, stream=True, timeout=timeout)
    else:
        response = request_session.get(url, stream=True, timeout=timeout)
    new_sha256 = hashlib.sha256()
    with open(result_file, 'wb') as fd:
        for data in response.iter_content(chunk_size=chunk_size):
            new_sha256.update(data)
            fd.write(data)
    end_time = time.time()
    logging.debug(
        'time cost for downloading %s is %d seconds',
        sha256[-6:],
        end_time - start_time,
    )
    if new_sha256.hexdigest().lower()  != sha256.lower():
        logging.warning(
            'downloaded file is of a different sha256 hash: origin %s, download %s',
            sha256.lower(),
            new_sha256.hexdigest().lower(),
        )
        return False
    return True


def alive_message(
    alive_interval=30,
):
    global global_download_task_queue
    global global_overall_start_time
    global global_is_stop
    global global_download_done_count
    global global_download_error_count
    while True:
        time.sleep(alive_interval)
        task_count = global_download_task_queue.qsize()
        result_count = global_download_result_queue.qsize()
        logging.info(
            '%d tasks completed, %d error, %d left, time cost is %d seconds', 
            global_download_done_count,
            global_download_error_count,
            task_count,
            time.time() - global_overall_start_time,
        )
        if global_is_stop:
            break


def dump_download_stat(
    result_file,
    error_file,
    error_count_limit=3,
    dump_interval=5,
):
    global global_download_task_queue
    global global_download_result_queue
    global global_is_stop
    global global_download_done_count
    global global_download_error_count

    with open(result_file, 'a') as fd, open(error_file, 'a') as error_fd:
        while True:
            fd.flush()
            error_fd.flush()
            download_result = None
            if not global_download_result_queue.empty():
                download_result = global_download_result_queue.get(
                    block=False,
                )
            if download_result is not None:
                if download_result.is_done:
                    fd.write(
                        '{sha256}\t{result_file}\n'.format(
                            sha256=download_result.sha256,
                            result_file=os.path.join(
                                download_result.result_direct_dir,
                                download_result.result_file,
                            )
                        )
                    )
                    global_download_done_count += 1
                if download_result.is_error:
                    if download_result.error_type == TaskError.HASH_UNMATCH:
                        error_fd.write(
                            '{sha256}\t{result_file}\t{error_type}\t{error_msg}\t{error_count}\n'.format(
                                sha256=download_result.sha256,
                                result_file=download_result.result_file,
                                error_type=download_result.error_type,
                                error_msg=download_result.error_msg,
                                error_count=download_result.error_count,
                            )
                        )
                        global_download_error_count += 1
                    elif download_result.error_count >= error_count_limit:
                        error_fd.write(
                            '{sha256}\t{result_file}\t{error_type}\t{error_msg}\t{error_count}\n'.format(
                                sha256=download_result.sha256,
                                result_file=download_result.result_file,
                                error_type=download_result.error_type,
                                error_msg=download_result.error_msg,
                                error_count=download_result.error_count,
                            )
                        )
                        global_download_error_count += 1
                    else:
                        download_result.is_error = False
                        download_result.error_msg = None
                        download_result.error_type = None
                        global_download_task_queue.put(download_result)
            else:
                time.sleep(dump_interval)
                if global_download_result_queue.empty() and global_is_stop:
                    break

class TaskError(object):
    HASH_UNMATCH = 1
    UNKNOWN = 2

class DownloadTask(object):
    def __init__(
        self,
        sha256, # sha256 hash of the apk file
        result_base_dir,
        result_direct_dir,
        result_file, # file to save the downloaded app
        is_done=False,
        done_msg=None,
        is_error=False,
        error_msg=None,
        error_type=None,
    ):
        self.sha256 = sha256
        self.result_file = result_file
        self.result_base_dir = result_base_dir
        self.result_direct_dir = result_direct_dir
        self.is_done = is_done
        self.done_msg = done_msg
        self.is_error = is_error
        self.error_type = error_type
        self.error_msg = error_msg
        self.error_count = 0


class DownloadThread(threading.Thread):
    def __init__(
        self,
        download_tasks,
        api_key,
        request_session=None,
        sleep_interval=0,
        task_timeout=(60, 120),
    ):
        super().__init__()
        self.download_tasks = download_tasks
        self.api_key = api_key
        if request_session is None:
            self.request_session = requests.Session()
        else:
            self.request_session = request_session
        self.sleep_internal = sleep_interval
        self.task_timeout = task_timeout

    def run(self):
        global global_download_result_queue
        for download_task in self.download_tasks:
            try:
                result_dir = os.path.join(
                    download_task.result_base_dir,
                    download_task.result_direct_dir,
                )
                if not os.path.exists(result_dir):
                    os.makedirs(result_dir)
                result_file = os.path.join(
                    result_dir,
                    download_task.result_file,
                )
                download_result = download_apk(
                    sha256=download_task.sha256,
                    result_file=result_file,
                    api_key=self.api_key,
                    timeout=self.task_timeout,
                )
                if download_result == False:
                    download_task.is_error = True
                    download_task.error_type = TaskError.HASH_UNMATCH
                    download_task.error_msg = 'sha256 hashes not matched'
                    download_task.error_count += 1
                else:
                    download_task.is_done = True
            except Exception as e:
                logging.warning('download exception %s, %s', e, traceback.format_exc())
                download_task.is_error = True
                download_task.error_type = TaskError.UNKNOWN
                download_task.error_msg = 'exception: {0}'.format(e)
                download_task.error_count += 1
            global_download_result_queue.put(download_task)


if __name__ == '__main__':
    import argparse
    logging.getLogger().setLevel(logging.INFO)
    parser = argparse.ArgumentParser()
    parser.add_argument('download_task_file', type=str)
    parser.add_argument('download_result_file', type=str)
    parser.add_argument('download_error_file', type=str)
    parser.add_argument('download_result_dir', type=str)
    parser.add_argument('api_key_file', type=str)
    parser.add_argument('-tn', '--thread_num', type=int, default=10)
    parser.add_argument('-ttu', '--thread_task_unit', type=int, default=10)
    parser.add_argument('-to', '--timeout', type=int, default=22*3600) # job time
    parser.add_argument('-ecl', '--error_count_limit', type=int, default=3)
    parser.add_argument('-adf', '--after_date_filter', type=str, default=None, help='format Y-m-d, e.g, 2017-01-01')
    parser.add_argument('-bdf', '--before_date_filter', type=str, default=None, help='format Y-m-d, e.g, 2017-01-01')
    options = parser.parse_args()
    download_task_file = options.download_task_file
    download_result_file = options.download_result_file
    download_error_file = options.download_error_file
    download_result_dir = options.download_result_dir
    api_key_file=options.api_key_file
    thread_num = options.thread_num
    thread_task_unit = options.thread_task_unit
    overall_timeout = options.timeout
    error_count_limit = options.error_count_limit
    date_filter_str = options.after_date_filter
    before_date_filter_str = options.before_date_filter
    if date_filter_str is None:
        date_filter = None
    else:
        date_filter = datetime.datetime.strptime(date_filter_str, '%Y-%m-%d')
    if before_date_filter_str is None:
        before_date_filter = None
    else:
        before_date_filter = datetime.datetime.strptime(before_date_filter_str, '%Y-%m-%d')
    if not os.path.exists(download_result_dir):
        os.makedirs(download_result_dir)
    api_key = None
    with open(api_key_file, 'r') as fd:
        for line in fd:
            attrs = line.strip().split('=')
            if attrs[0] == 'api_key':
                api_key = attrs[1]
                break
    if api_key is None:
        logging.error('no api key provided')
        sys.exit(1)

    apk_to_pkg_dict = {}
    apk_to_dex_ds_dict = {}
    # load in download tasks
    with open(download_task_file, 'r') as fd:
        line_num = 0
        for line in fd:
            line_num += 1
            if line_num == 1:
                continue
            attrs = line.strip().split(',')
            sha256 = attrs[0].lower()
            dex_ds = attrs[3].split(' ')[0]
            is_target = False
            if date_filter:
                if len(dex_ds) == 0: # some didn't have dex_ds
                    continue
                dex_date = datetime.datetime.strptime(dex_ds, '%Y-%m-%d')
                if date_filter < dex_date:
                    is_target = True
            if before_date_filter:
                if len(dex_ds) == 0: # some didn't have dex_ds
                    continue
                dex_date = datetime.datetime.strptime(dex_ds, '%Y-%m-%d')
                if before_date_filter > dex_date:
                    is_target = True
            if (date_filter is not None or before_date_filter is not None) and is_target == False:
                continue
            pkg_id = attrs[5].strip('""')
            apk_to_pkg_dict[sha256] = pkg_id
            apk_to_dex_ds_dict[sha256] = dex_ds
    # load in previous download results
    init_complte_task_set = set()
    if os.path.exists(download_result_file):
        with open(download_result_file, 'r') as fd:
            for line in fd:
                attrs = line.strip().split('\t')
                sha256 = attrs[0].lower()
                init_complte_task_set.add(sha256)
    apk_to_download_list = list(set(apk_to_pkg_dict.keys()) - init_complte_task_set)
    logging.info(
        '%d download tasks, %d finished, %d left in this round',
        len(apk_to_pkg_dict),
        len(init_complte_task_set),
        len(apk_to_download_list),
    )
    download_task_list = []
    for sha256 in apk_to_download_list:
        result_direct_dir = os.path.join(
            sha256[-6:-4],
            sha256[-4:-2],
            sha256[-2:],
        )
        result_file = '{pkg_id}_{dex_ds}_{hash}.apk'.format(
            pkg_id=apk_to_pkg_dict[sha256],
            dex_ds=apk_to_dex_ds_dict[sha256],
            hash=sha256[-6:],
        )
        download_task = DownloadTask(
            sha256=sha256,
            result_file=result_file,
            result_base_dir=download_result_dir,
            result_direct_dir=result_direct_dir,
        )
        download_task_list.append(download_task)
    alive_msg_thread = threading.Thread(
        target=alive_message,
        kwargs=dict(
            alive_interval=30,
        ),
    )
    dump_download_stat_thread = threading.Thread(
        target=dump_download_stat,
        args=(
            download_result_file,
            download_error_file,
        ),
        kwargs=dict(
            error_count_limit=error_count_limit,
            dump_interval=10,
        ),
    )
    alive_msg_thread.start()
    dump_download_stat_thread.start()
    download_index = 0
    request_session = None
    while download_index < len(download_task_list):
        timecost = time.time() - global_overall_start_time
        if timecost >= overall_timeout:
            break
        download_thread_list = []
        for i in range(thread_num):
            sub_download_task_list = []
            # prioritize failed task
            if not global_download_task_queue.empty():
                for i in range(thread_task_unit):
                    try:
                        download_task = global_download_task_queue.get_nowait()
                        sub_download_task_list.append(download_task)
                    except Exception as e:
                        break
            if len(sub_download_task_list) == 0:
                sub_download_task_list = download_task_list[download_index:download_index + thread_task_unit]
            download_thread = DownloadThread(
                download_tasks=sub_download_task_list,
                api_key=api_key,
                request_session=request_session,
            )
            download_thread_list.append(download_thread)
            download_index += thread_task_unit
            if download_index >= len(download_task_list):
                break
        logging.info('created %d threads for downloading', len(download_thread_list))
        for d_thread in download_thread_list:
            d_thread.start()
        for d_thread in download_thread_list:
            d_thread.join()
    global_is_stop = True
    alive_msg_thread.join()
    dump_download_stat_thread.join()
    logging.info(
        'Exit this round with %d successful downloads, %d errors',
        global_download_done_count,
        global_download_error_count,
    )
