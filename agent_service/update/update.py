#!/usr/bin/env python
# -*- coding:utf-8 -*-
# @Time  : 2018/7/11 14:14
# @Author: yangjian
# @File  : update.py

import os
import sys
import json
import urllib
import urllib2
import logging
from logging.handlers import TimedRotatingFileHandler

LOG_FILE = "/home/opvis/opvis_agent/agent_service/log/update.log"
logger = logging.getLogger()
logger.setLevel(logging.INFO)
fh = TimedRotatingFileHandler(LOG_FILE, when='D', interval=1, backupCount=30)
datefmt = '%Y-%m-%d %H:%M:%S'
format_str = '%(asctime)s %(levelname)s %(message)s '
formatter = logging.Formatter(format_str, datefmt)
fh.setFormatter(formatter)
logger.addHandler(fh)

plugin_dir = "/home/opvis/opvis_agent/agent_service/plugin/"
if not os.path.exists(plugin_dir):
  os.mkdir(plugin_dir)
dirs = os.listdir(plugin_dir)
data = sys.argv[1:]
logging.info("Received data from proxy:" + str(data))
data1 = data[0]
data2 = json.loads(data1)
dic = data2["pluginfo"]
url = dic.get("url")
name = dic.get("name")
cycle = dic.get("cycle")
status = int(dic.get("status"))
file_name = url.split("/")[-1]

plugin_dir1 = os.path.join(plugin_dir, file_name)
tmp_url = dic.get('url')

requrl = "http://" + tmp_url.split("/")[2] + "/umsproxy/autoProxyPlugIn/agentType"
requrl = str(requrl)

def installPlugin():
  logging.info("When install plugin, get hostid and plugid: ")
  logging.info(data2.get('hostid'))
  logging.info(data2.get('plugid'))
  try:
    if (file_name not in dirs):
      try:
        urllib.urlretrieve(url, os.path.join(plugin_dir, file_name))
        html = urllib.urlopen(url)
        html1 = html.read()
        code = html.code
        with open(os.path.join(plugin_dir, file_name), "wb") as fp:
          fp.write(html1)
      except Exception, e:
        logging.info("Install plugin, plugin not exists and download plugin failed: " + str(e))
      if code == 200:
        req_data = {}
        req_data['hostId'] = data2.get('hostid')
        req_data['plugId'] = data2.get('plugid')
        #temp = os.popen('sudo python %s' % plugin_dir1).readlines()
        logging.info("Install plugin, plugin not exists, download plugin successfully: " + str(file_name))
        req_data["type"] = "11"
        req_data["cause"] = "success"
        try:
          req_data = urllib.urlencode(req_data)
          req = urllib2.Request(url=requrl, data=req_data)
          res = urllib2.urlopen(req)
          data = res.read()
          logging.info("Interface feedback plugin installed successfully: " + str(data))
        except Exception as e:
          logging.info("Interface feedback plugin install failed: " +str(e))
      elif code != 200:
        req_data = {}
        req_data['hostId'] = data2.get('hostid')
        req_data['plugId'] = data2.get('plugid')
        req_data['type'] = '10'
        req_data['cause'] = "下载文件失败"
        try:
          req_data = urllib.urlencode(req_data)
          req = urllib2.Request(url=requrl, data=req_data)
          res = urllib2.urlopen(req)
          data = res.read()
          logging.info("Interface feedback install plugin, plugin not exists and download plugin failed:" + str(data))
        except Exception as e:
          logging.info("Interface feedback install plugin, plugin not exists and download plugin failed: " + str(file_name))
  except Exception, e:
    logging.info("When install plugin, error:" + str(e))
    req_data = {}
    req_data['hostId'] = data2.get('hostid')
    req_data['plugId'] = data2.get('plugid')
    req_data["type"] = "10"
    req_data["cause"] = "系统异常"
    try:
      req_data = urllib.urlencode(req_data)
      req = urllib2.Request(url=requrl, data=req_data)
      res = urllib2.urlopen(req)
      data = res.read()
      logging.info("Interface feedback system error successfully: " + str(data))
    except Exception as e:
      logging.info("Interface feedback system error failed: " + str(e))

def doPlugin():
  try:
    if (file_name not in dirs):
      try:
        urllib.urlretrieve(url, os.path.join(plugin_dir, file_name))
        html = urllib.urlopen(url)
        html1 = html.read()
        code = html.code
        with open(os.path.join(plugin_dir, file_name), "wb") as fp:
          fp.write(html1)
      except Exception, e:
        logging.info("Download plugin error: " + str(e))
      if code == 200:
        try:
          logging.info("Plugin not exists, download plugin successfully: " + str(file_name))
          logging.info("Period excute plugin: " + str(file_name) + str(cycle))
          cron_dir = "/home/opvis/opvis_agent/agent_service/cron/" + str(file_name.split(".")[0])
          f = open(cron_dir, "w")
          f.write("%s python %s\n" % (cycle, plugin_dir1))
          f.close()
          cron_cmd = "crontab" + " " + cron_dir
          cron_ret = os.system(cron_cmd)
          if cron_ret == 0:
            os.remove(cron_dir)
          req_data = {}
          req_data['hostId'] = data2.get('hostid')
          req_data['plugId'] = data2.get('plugid')
          req_data['type'] = '21'
          req_data['cause'] = 'success'
          req_data = urllib.urlencode(req_data)
          req = urllib2.Request(url=requrl, data=req_data)
          res = urllib2.urlopen(req)
          data = res.read()
          logging.info("Interface feedback doPlugin successfully: " + str(data))
        except Exception as e:
          logging.info("Plugin not exists, download plugin error: " + str(e))

      elif code != 200:
        logging.info("Plugin not exists, download plugin failed: " + str(file_name))
        try:
          req_data = {}
          req_data['hostId'] = data2.get('hostid')
          req_data['plugId'] = data2.get('plugid')
          req_data['type'] = '20'
          req_data['cause'] = "下载文件失败"
          req_data = urllib.urlencode(req_data)
          req = urllib2.Request(url=requrl, data=req_data)
          res = urllib2.urlopen(req)
          data = res.read()
          logging.info("Interface feedback successfully: " + str(data))
        except Exception as e:
          logging.info("Interface feedback plugin not exists, download plugin failed, error" + str(e))
    else:
      logging.info("Plugin not exists and doplugin: " + str(file_name))
      try:
        cron_dir = "/home/opvis/opvis_agent/agent_service/cron/" + str(file_name.split(".")[0])
        f = open(cron_dir, "w")
        f.write("%s python %s\n" % (cycle, plugin_dir1))
        f.close()
        cron_cmd = "crontab" + " " + cron_dir
        cron_ret = os.system(cron_cmd)
        if cron_ret == 0:
          os.remove(cron_dir)
        req_data = {}
        req_data['hostId'] = data2.get('hostid')
        req_data['plugId'] = data2.get('plugid')
        req_data['type'] = '21'
        req_data['cause'] = 'success'
        req_data = urllib.urlencode(req_data)
        req = urllib2.Request(url=requrl, data=req_data)
        res = urllib2.urlopen(req)
        data = res.read()
        logging.info("Interface feedback successfully: " + str(data))
      except Exception as e:
        logging.info("Interface feedback plugin not exists and doplugin, error: " + str(e))

  except Exception, e:
    logging.info("doPlugin error：" + str(e))
    try:
      req_data = {}
      req_data['hostId'] = data2.get('hostid')
      req_data['plugId'] = data2.get('plugid')
      req_data['type'] = '20'
      req_data['cause'] = str(e)
      req_data = urllib.urlencode(req_data)
      req = urllib2.Request(url=requrl, data=req_data)
      res = urllib2.urlopen(req)
      data = res.read()
      logging.info("Interface feedback successfully: " + str(data))
    except Exception as e:
      logging.info("Interface feedback doPlugin error: " + str(e))

def updatePlugin():
  try:
    file_name = url.split("/")[-1]
    try:
      urllib.urlretrieve(url, os.path.join(plugin_dir, file_name))
      html = urllib.urlopen(url)
      html1 = html.read()
      code = html.code
      with open(os.path.join(plugin_dir, file_name), "wb") as fp:
        fp.write(html1)
        logging.info("UpdatePlugin, download plugin successfully.")
    except Exception, e:
      logging.info("UpdatePlugin, download plugin failed: " + str(e))
    if code == 200:
      logging.info("UpdatePlugin, successfully.")
      try:
        req_data = {}
        req_data['hostId'] = data2.get('hostid')
        req_data['plugId'] = data2.get('plugid')
        req_data['type'] = '31'
        req_data['cause'] = 'success'
        logging.info(req_data)
        req_data = urllib.urlencode(req_data)
        req = urllib2.Request(url=requrl, data=req_data)
        res = urllib2.urlopen(req)
        data = res.read()
        logging.info("Interface feedback, updatePlugin successfully: " + str(data))
      except Exception as e:
        logging.info("UpdatePlugin, failed: " + str(e))

  except Exception, e:
    try:
      req_data = {}
      req_data['hostId'] = data2.get('hostid')
      req_data['plugId'] = data2.get('plugid')
      req_data['type'] = '30'
      req_data['cause'] = str(e)
      req_data = urllib.urlencode(req_data)
      req = urllib2.Request(url=requrl, data=req_data)
      res = urllib2.urlopen(req)
      data = res.read()
      logging.info("Interface feedback, updatePlugin successfully: " + str(data))
    except Exception as e:
      logging.info("UpdatePlugin error: " + str(e))

def savePlugin():
  file_name = url.split("/")[-1]
  if (file_name not in dirs):
    urllib.urlretrieve(url, os.path.join(plugin_dir, file_name))  # 直接覆盖？
    html = urllib.urlopen(url)
    html1 = html.read()
    code = html.code
    logging.info(code)
    with open(os.path.join(plugin_dir, file_name), "wb") as fp:
      fp.write(html1)
    try:
      if code == 200:
        logging.info("Saveplugin, plugin not exists, download plugin successfully: " + str(file_name))
        req_data = {}
        req_data['hostId'] = data2.get('hostid')
        req_data['plugId'] = data2.get('plugid')
        req_data['type'] = '41'
        req_data['cause'] = 'success'
        req_data = urllib.urlencode(req_data)
        req = urllib2.Request(url=requrl, data=req_data)
        res = urllib2.urlopen(req)
        data = res.read()
        logging.info("Interface feedback successfully: " + str(data))
    except Exception, e:
      try:
        req_data = {}
        req_data['hostId'] = data2.get('hostid')
        req_data['plugId'] = data2.get('plugid')
        req_data['type'] = '40'
        req_data['cause'] = str(e)
        req_data = urllib.urlencode(req_data)
        req = urllib2.Request(url=requrl, data=req_data)
        res = urllib2.urlopen(req)
        data = res.read()
        logging.info("Interface feedback, successfully: " + str(data))
      except Exception as e:
        logging.info("Saveplugin error: " + str(e))

def deletePlugin():
  for d in dirs:
    if d == file_name:
      os.remove(plugin_dir + d)
      req_data = {}
      req_data['hostId'] = data2.get('hostid')
      req_data['plugId'] = data2.get('plugid')
      req_data['type'] = '51'
      req_data['cause'] = 'success'
      try:
        req_data = urllib.urlencode(req_data)
        req = urllib2.Request(url=requrl, data=req_data)
        res = urllib2.urlopen(req)
        data = res.read()
        logging.info("Interface feedback successfully, deleteplugin: " + str(data))
      except Exception as e:
        logging.info("Deleteplugin error: " + str(e))

def hostInformation():
  try:
    if (file_name not in dirs):
      try:
        urllib.urlretrieve(url, os.path.join(plugin_dir, file_name))
        html = urllib.urlopen(url)
        html1 = html.read()
        code = html.code
        with open(os.path.join(plugin_dir, file_name), "wb") as fp:
          fp.write(html1)
      except Exception, e:
        logging.info("Install plugin, plugin not exists and download plugin failed: " + str(e))
      if code == 200:
        temp = os.popen('sudo python %s' % plugin_dir1).readlines()
        logging.info("Install plugin, plugin not exists, download and excute plugin successfully: " + str(file_name))
        # HostRelationship
        try:
          url_new = "http://" + tmp_url.split("/")[2] + "/umsproxy/hostExtract/uploadHostInformation"
          url_new = str(url_new)
          hostRelationship = {}
          hostRelationship["tableName"] = data2.get("tableName")
          hostRelationship["hostRelationship"] = temp
          hostRelationship = json.dumps(hostRelationship)
          header_dict = {"Content-Type": "application/json;charset=UTF-8"}
          req = urllib2.Request(url=url_new, data=hostRelationship, headers=header_dict)
          res = urllib2.urlopen(req)
          logging.info("Interface feedback upload hostinformation successfully: " + str(res.read()))
        except Exception as e:
          logging.info("Interface feedback upload hostinformation failed:" + str(e))
      elif code != 200:
          logging.info("Plugin not exists and download plugin failed: " + str(file_name))
    else:
      temp = os.popen('sudo python %s' % plugin_dir1).readlines()
      logging.info("Plugin exists and execute successfully." + str(file_name))
      # HostRelationship
      try:
        url_new = "http://" + tmp_url.split("/")[2] + "/umsproxy/hostExtract/uploadHostInformation"
        url_new = str(url_new)
        hostRelationship = {}
        hostRelationship["tableName"] = data2.get("tableName")
        hostRelationship["hostRelationship"] = temp
        hostRelationship = json.dumps(hostRelationship)
        header_dict = {"Content-Type": "application/json;charset=UTF-8"}
        req = urllib2.Request(url=url_new, data=hostRelationship, headers=header_dict)
        res = urllib2.urlopen(req)
        logging.info("Interface feedback upload hostinformation successfully: " + str(res.read()))
      except Exception as e:
        logging.info("Interface feedback upload hostinformation failed: " + str(e))
  except Exception, e:
    logging.info("When install plugin, error:" + str(e))

logging.info("Received status: " + str(status))

if status == 1 and url:
  try:
    installPlugin()
  except Exception as e:
    logging.info(e)

elif status == 2 and url and cycle:
  try:
    doPlugin()
  except Exception as e:
    logging.info(e)

elif status == 3 and url:
  try:
    updatePlugin()
  except Exception as e:
    logging.info(e)

elif status == 4 and url:
  try:
    savePlugin()
  except Exception as e:
    logging.info(e)

elif status == 5 and url:
  try:
    deletePlugin()
  except Exception as e:
    logging.info(e)
elif status == 6 and url:
  try:
    hostInformation()
  except Exception as e:
    logging.info(e)