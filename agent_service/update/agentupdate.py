#!/usr/bin/env python
# -*- coding:utf-8 -*-
# @Time  : 2008/7/5 10:26
# @Author: YYYY-MM
# @File  : agentupdate.py

import os
import sys
import json
import urllib
import logging
from logging.handlers import TimedRotatingFileHandler

reload(sys)
sys.setdefaultencoding('utf8')
LOG_FILE = "/home/opvis/utils/log/agent.log"
logger = logging.getLogger()
logger.setLevel(logging.INFO)
fh = TimedRotatingFileHandler(LOG_FILE,when='D',interval=1,backupCount=30)
datefmt = '%Y-%m-%d %H:%M:%S'
format_str = '%(asctime)s %(levelname)s %(message)s '
formatter = logging.Formatter(format_str, datefmt)
fh.setFormatter(formatter)
logger.addHandler(fh)

data = sys.argv[1:]
logging.info("Get data from proxy: " + str(data))
dic = data[0]
dic = json.loads(dic)
# "agentUrl":"http://172.30.130.126:18382/proxyDownLoad/opvis_agent.tar.gz"
url = dic.get("agentUrl")
with open("/home/opvis/utils/agent.lock", "r") as fd:
  proxy_ip = fd.readline()
#url = "http://" + proxy_ip + "/proxyDownLoad/opvis_agent.tar.gz"
logging.info("Download agent url: " + str(url))

try:
  if os.fork() > 0:
    sys.exit(0)
except OSError, error:
  logging.info("opvis_agent update first fork failed!")
  sys.exit(1)

os.chdir('/')
os.setsid()
os.umask(0)

try:
  if os.fork() > 0:
    sys.exit(0)
except OSError,error:
  logging.info("opvis_agent update second fork failed!")
  sys.exit(1)

agent_name = url.split("/")[4]  # opvis_agent_v1.tar.gz
loacl_agent_name = "/home/opvis/" + agent_name
urllib.urlretrieve(url, loacl_agent_name)
logging.info("Download " + str(agent_name) + " successfully!")
if os.path.exists(loacl_agent_name):
  os.system("sh /home/opvis/opvis_agent/agent_service/update/agentupdate.sh")
  logging.info("Update agent_udp successfully!")
else:
  logging.info("Download " + str(agent_name) + " failed!")
