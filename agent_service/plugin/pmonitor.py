#!/usr/bin/env python
# -*- coding:utf-8 -*-
# @Time  : 2018/10/11 14:22
# @Author: yangjian
# @File  : pmonitor.py

import os
import sys
import json
import urllib
import urllib2
import logging
import datetime
from logging.handlers import TimedRotatingFileHandler


# log
LOG_FILE = "/home/opvis/utils/log/pmonitor.log"
logger = logging.getLogger()
logger.setLevel(logging.INFO)
fh = TimedRotatingFileHandler(LOG_FILE, when='D', interval=1, backupCount=30)
datefmt = '%Y-%m-%d %H:%M:%S'
format_str = '%(asctime)s %(levelname)s %(message)s '
formatter = logging.Formatter(format_str, datefmt)
fh.setFormatter(formatter)
logger.addHandler(fh)

arg = sys.argv[1]
arg_number = arg.split("=")[1].replace("\n","")[-2:-1]
logging.info(str(arg_number))
arg_time = arg.split("=")[1].replace("\n","")[-1:]
logging.info(str(arg_time))

allitems = "/home/opvis/utils/pm/allitems"
def fun():
  lm=[]
  lh = []
  with open(allitems,"r") as fd:
    for i in fd.readlines():
      j = json.loads(i)
      if arg_time == "m" and int(j["trigger_cycle_unit"]) == 0 and int(j["trigger_cycle_value"]) == int(arg_number):
        lm.append(j)
      else:
        if int(j["trigger_cycle_unit"]) != 0 and int(j["trigger_cycle_value"]) == int(arg_number):
          lh.append(j)
  if lm and arg_time == "m":
    check_process(lm)
  if lh and arg_time == "h":
    check_process(lh)

def check_process(ll):
  with open("/home/opvis/utils/agent.lock", "r") as fd:
    proxy_ip = fd.readline().split(":")[0]
  get_process_url = "http://" + proxy_ip + ":9995" + "/storeinfo/"
  for x in ll:
    id = x.get("id")
    biz_ip = x.get("biz_ip")
    manage_ip = x.get("manage_ip")
    process_name = x.get("process_name")
    key_word = x.get("key_word")
    key_word = "'" + key_word + "'"
    trigger_compare = x.get("trigger_compare")
    trigger_value = x.get("trigger_value")
    trigger_level = x.get("trigger_level")
    trigger_cycle_value = x.get("trigger_cycle_value")
    trigger_cycle_unit = x.get("trigger_cycle_unit")
    count_new = os.popen("ps aux|grep %s|grep -v grep|wc -l" % key_word).readline()[0]
    current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if int(count_new) < int(trigger_value):
      try:
        upload_data = {}
        upload_data["id"] = id
        upload_data["biz_ip"] = biz_ip
        upload_data["manage_ip"] = manage_ip
        upload_data["process_name"] = process_name
        upload_data["key_word"] = key_word
        upload_data["trigger_compare"] = trigger_compare
        upload_data["trigger_value"] = trigger_value
        upload_data["trigger_level"] = trigger_level
        upload_data["trigger_cycle_value"] = trigger_cycle_value
        upload_data["trigger_cycle_unit"] = trigger_cycle_unit
        upload_data["should_be"] = trigger_value
        upload_data["new_count"] = count_new
        upload_data["current_time"] = current_time
        upload_data = urllib.urlencode(upload_data)
        req = urllib2.Request(url=get_process_url, data=upload_data)
        res = urllib2.urlopen(req)
        get_data = res.read()
        if get_data == "ok":
          logging.info("process is less than original!" + " process name is: " + str(key_word) + " " + " machine ip is: " + str(biz_ip))
        else:
          logging.info(get_data)
      except Exception as e:
        logging.info("Storeinfo error. " + str(e))
    else:
      try:
        upload_data = {}
        upload_data["id"] = id
        upload_data["biz_ip"] = biz_ip
        upload_data["manage_ip"] = manage_ip
        upload_data["process_name"] = process_name
        upload_data["key_word"] = key_word
        upload_data["trigger_compare"] = trigger_compare
        upload_data["trigger_value"] = trigger_value
        upload_data["trigger_level"] = trigger_level
        upload_data["trigger_cycle_value"] = trigger_cycle_value
        upload_data["trigger_cycle_unit"] = trigger_cycle_unit
        upload_data["should_be"] = trigger_value
        upload_data["new_count"] = count_new
        upload_data["current_time"] = current_time
        upload_data = urllib.urlencode(upload_data)
        req = urllib2.Request(url=get_process_url, data=upload_data)
        res = urllib2.urlopen(req,timeout=70)
        get_data = res.read()
        if get_data == "ok":
          logging.info("process monitor is ok！" + " process name is: " + str(key_word) + " " + " machine ip is: " + str(biz_ip))
        else:
          logging.info(get_data)
      except Exception as e:
        logging.info("Storeinfo error. " + str(e))
fun()