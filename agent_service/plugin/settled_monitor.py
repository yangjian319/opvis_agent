#!/usr/bin/env python
# -*- coding:utf-8 -*-
# @Time  : 2019/1/8 15:36
# @Author: yangjian
# @File  : settled_monitor.py
# 定点监控插件

import os
import sys
import time
import urllib
import urllib2
import datetime
import subprocess
import logging
from logging.handlers import TimedRotatingFileHandler

reload(sys)
sys.setdefaultencoding('utf8')
LOG_FILE = "/home/opvis/utils/log/settled_monitor.log"
logger = logging.getLogger()
logger.setLevel(logging.INFO)
fh = TimedRotatingFileHandler(LOG_FILE,when='D',interval=1,backupCount=30)
datefmt = '%Y-%m-%d %H:%M:%S'
format_str = '%(asctime)s %(levelname)s %(message)s '
formatter = logging.Formatter(format_str, datefmt)
fh.setFormatter(formatter)
logger.addHandler(fh)

shell_name = sys.argv[1]
limit_time = sys.argv[2]
shell_path = "/home/opvis/utils/plugin/shell_scripts/" + shell_name
with open("/home/opvis/utils/agent.lock", "r") as fd:
  proxy_ip = fd.readline().split(":")[0]
settled_post_url = "http://" + proxy_ip + ":9995" + "/fixed_point_result/"  # 返回结果给transfer
#id = shell_name.split("##")[1]
id = shell_name
# 添加一个判断，判断shell_path是否存在，如果不存在就记录日志。
if os.path.exists(shell_path):
  with open(shell_path, "r") as fd:
    shell_cmd = fd.read()
  end_time = datetime.datetime.now() + datetime.timedelta(seconds=int(limit_time))
  # 脚本执行开始时间
  start_execute_time = time.time()
  sub = subprocess.Popen(shell_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
  while True:
    time.sleep(0.1)
    if end_time <= datetime.datetime.now():
      code = 2
      sub.kill()
      break  # 为了防止结果和错误都为空，如ls一个空目录
    else:
      code = 1
    (stdoutput, erroutput) = sub.communicate()
    if erroutput:
      result = erroutput
    else:
      result = stdoutput
    if result:
      break
    if sub.poll() is not None:
      break
  # logging.info("shell脚本定时执行结果：" + str(result))
  end_execute_time = time.time()
  if result == "":
    code = 0
  data = {}
  data["id"] = id
  data["code"] = code
  data["proxy_ip"] = proxy_ip
  data["monitor_time"] = str(start_execute_time)
  data["result"] = result
  data = urllib.urlencode(data)
  req = urllib2.Request(url=settled_post_url, data=data)
  res = urllib2.urlopen(req)
  get_data = res.read()
  logging.info("transfer feedback " + str(get_data))
else:
  logging.info("shell_scripts下的 " + str(shell_name) + " 不存在！")