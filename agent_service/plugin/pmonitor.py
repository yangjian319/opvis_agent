#!/usr/bin/env python
# -*- coding:utf-8 -*-
# @Time  : 2018/10/11 14:22
# @Author: yangjian
# @File  : pmonitor.py

import os
import sys
import json
import logging
from logging.handlers import TimedRotatingFileHandler


# log
LOG_FILE = "/home/opvis/opvis_agent/agent_service/log/pmonitor.log"
logger = logging.getLogger()
logger.setLevel(logging.INFO)
fh = TimedRotatingFileHandler(LOG_FILE, when='D', interval=1, backupCount=30)
datefmt = '%Y-%m-%d %H:%M:%S'
format_str = '%(asctime)s %(levelname)s %(message)s '
formatter = logging.Formatter(format_str, datefmt)
fh.setFormatter(formatter)
logger.addHandler(fh)

if not os.path.exists("/data/py/test"):
  os.mkdir("/home/opvis/opvis_agent/agent_service/pm")

arg_cycle = sys.argv[1]
allitems = "/home/opvis/opvis_agent/agent_service/pm/allitems"

fd = open(allitems,"r")
line = json.loads(fd.readline())
while line:
  key_word = line.get("key_word")
  IP = line.get("IP")
  process_name = line.get("process_name")
  trigger_cycle_value = line.get("trigger_cycle_value")
  trigger_value = line.get("trigger_value")
  need_monitor = []
  cmd = "grep " +  arg_cycle + " " + allitems + '|awk -F \',\' \'{print $2}\'|awk -F \'=\' \'{print $2}\''
  process = os.popen(cmd).readlines()
  for i in process:
    need_monitor.append(i.replace("\n",""))
  for p in need_monitor and p == key_word:
    count_new = os.popen("ps aux|grep %s|grep -v grep|wc -l" %p).readline()[0]
    if int(count_new) < int(trigger_value):
      # 记录日志
      content = process_name + " " + "老的进程数是：" + trigger_value + " 新的进程数是：" + count_new
      logging.info(content)
      pass
      # alarmprocess接口，上报错误信息给接口，包括程name，原有进程数count_old，现有进程数count_new?
    line = fd.readline()
fd.close()
