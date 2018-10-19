#!/usr/bin/env python
# -*- coding:utf-8 -*-
# @Time  : 2018/10/11 14:22
# @Author: yangjian
# @File  : pmonitor.py

import os
import sys
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
#arg_cycle = int(sys.argv[1].split("=")[1])  # arg_cycle是定时任务中传到本脚本的参数，这里要把cycle=1拆开后取数字
arg_cycle = sys.argv[1]
allitems = "/home/opvis/opvis_agent/agent_service/pm/allitems" # 首次取出的所有监控项信息

fd = open(allitems,"r")
line = fd.readline()
while line:
  name = line.split(",")[2].split("=")[1]
  regr = line.split(",")[3].split("=")[1]
  count_old = line.split(",")[4].split("=")[1]
  cycle = line.split(",")[5].split("=")[1]
  # 根据定时任务传入的周期数cycle去找出当前定时任务需要去查询哪些程序名需要去查询它们的进程将程序的特征值存入列表
  need_monitor = []
  cmd = "grep " +  arg_cycle + " " + allitems + '|awk -F \',\' \'{print $2}\'|awk -F \'=\' \'{print $2}\''
  process = os.popen(cmd).readlines()
  for i in process:
    need_monitor.append(i.replace("\n",""))
  for p in need_monitor and p == regr:
    count_new = os.popen("ps aux|grep %s|grep -v grep|wc -l" %p).readline()[0]
    if int(count_new) < int(count_old):
      # 记录日志
      content = name + " " + "老的进程数是：" + count_old + " 新的进程数是：" + count_new
      logging.info(content)
      pass
      # alarmprocess接口，上报错误信息给接口，包括程name，原有进程数count_old，现有进程数count_new?
    line = fd.readline()
fd.close()
