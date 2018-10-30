#!/usr/bin/env python
# -*- coding:utf-8 -*-
# @Time  : 2018/7/4 9:25
# @Author: yangjian
# @File  : agent_udp.py
# Agent程序主文件，包括判断本机属于哪个机房，上传本机authorized_keys文件的md5值，上传本机IP以及已安装插件，主机关系上传
# 接收指令调用update.py对插件进行管理，以及调用agentupdate.py对agent整个程序进行升级

import os
import sys
import time
import json
import fcntl
import struct
import array
import getopt
import socket
import urllib
import urllib2
import MySQLdb
import logging
import commands
import threading
from logging.handlers import TimedRotatingFileHandler


VERSION = 1

# log
LOG_FILE = "/home/opvis/opvis_agent/agent_service/log/agent.log"
logger = logging.getLogger()
logger.setLevel(logging.INFO)
fh = TimedRotatingFileHandler(LOG_FILE, when='D', interval=1, backupCount=30)
datefmt = '%Y-%m-%d %H:%M:%S'
format_str = '%(asctime)s %(levelname)s %(message)s '
formatter = logging.Formatter(format_str, datefmt)
fh.setFormatter(formatter)
logger.addHandler(fh)

##################################################################################
os.mkdirs("/home/opvis/opvis_agent/agent_service/pm")
allitems = "/home/opvis/opvis_agent/agent_service/pm/allitems"
allcycle_a = "/home/opvis/opvis_agent/agent_service/pm/allcycle_a"
allcycle_b = "/home/opvis/opvis_agent/agent_service/pm/allcycle_b"
allcycle_c = "/home/opvis/opvis_agent/agent_service/pm/allcycle_c"

crontab_opvis_a = "/home/opvis/opvis_agent/agent_service/cron/crontab_opvis_a"
crontab_opvis_b = "/home/opvis/opvis_agent/agent_service/cron/crontab_opvis_b"
crontab_opvis_c = "/home/opvis/opvis_agent/agent_service/cron/crontab_opvis_c"

pmonitorLog = "/home/opvis/opvis_agent/agent_service/log/pmonitor.log"
pmonitorDir = "/home/opvis/opvis_agent/agent_service/plugin/pmonitor.py"

# 看线上是用eth0还是eth1
localip = os.popen("ifconfig eth0|grep 'inet'|awk 'NR==1 {print $2}'").read().replace("\n", "")
##################################################################################

iplist = ["172.30.130.137:18382", "172.30.130.126:18382", "10.124.5.163:18382", "10.144.2.248:18382",
          "10.123.30.177:18382", "172.30.194.121:18382", "172.16.5.20:18382", "10.181.1.0:18382"]
for ip in iplist:
  try:
    so = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    so.settimeout(2)
    so.connect((ip.split(":")[0], 18382))
    currentip = ip
    with open("/home/opvis/opvis_agent/agent_service/agent.lock", "wb") as fd:
      fd.write(currentip)
    so.close()
  except Exception as e:
    logging.info("Determine which area the machine belongs to error: " + str(e))
jifangip = currentip
plugin_dir = "/home/opvis/opvis_agent/agent_service/plugin/"

try:
  address = ("0.0.0.0", 9997)
  udpsocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  udpsocket.bind(address)
except Exception as e:
  logging.info("Udp connection error: " + str(e))

try:
  if os.fork() > 0:
    sys.exit(0)
except OSError, error:
  logging.info("agent_udp.py first fork failed!")
  sys.exit(1)

os.chdir("/")
os.setsid()
os.umask(0)

try:
  if os.fork() > 0:
    sys.exit(0)
except OSError, error:
  logging.info("agent_udp.py second fork failed!")
  sys.exit(1)

def post_md5():
  (status, md5) = commands.getstatusoutput("sudo md5sum /root/.ssh/authorized_keys|awk '{print $1}'")
  requrl = "http://" + jifangip + "/umsproxy/autoProxyPlugIn/uploadMD5"
  req_data = {}
  req_data['md5'] = md5
  try:
    args_restful = urllib.urlencode(req_data)
    req = urllib2.Request(url=requrl, data=args_restful)
    res = urllib2.urlopen(req)
    data = res.read()
  except Exception as e:
    logging.info("Upload the native MD5 value to the proxy error: " + str(e))
  logging.info("Upload the native MD5 value to the proxy successfully: " + str(data))
try:
  post_md5()
except Exception as e:
  logging.info("Upload the native MD5 value to the proxy error: " + str(e))

def file_name(plugin_dir):
  list = []
  for root, dirs, files in os.walk(plugin_dir):
    for file in files:
      if os.path.splitext(file)[1] == '.py':
        list.append(file)
  return list

# get all ips of the server
def get_all_ips():
  max_possible = 128
  bytes = max_possible * 32
  s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  names = array.array('B', '\0' * bytes)
  outbytes = struct.unpack('iL', fcntl.ioctl(s.fileno(),0x8912,struct.pack('iL', bytes, names.buffer_info()[0])))[0]
  namestr = names.tostring()
  lst = []
  for i in range(0, outbytes, 40):
    ip = namestr[i+20:i+24]
    lst.append(ip)
  return lst

# format ip to be readable
def read_ip(addr):
  return str(int(addr[6:8],16)) + '.' + \
         str(int(addr[4:6],16)) + '.' + \
         str(int(addr[2:4],16)) + '.' + \
         str(int(addr[0:2],16))

# format ip to hex
def re_format_ip(addr):
  ret = ''
  if ord(addr[3]) < 16:
    ret = ret + "0" + str(hex(ord(addr[3])))[2:]
  else:
    ret = ret + str(hex(ord(addr[3])))[2:]
  if ord(addr[2]) < 16:
    ret = ret + "0" + str(hex(ord(addr[2])))[2:]
  else:
    ret = ret + str(hex(ord(addr[2])))[2:]
  if ord(addr[1]) < 16:
    ret = ret + "0" + str(hex(ord(addr[1])))[2:]
  else:
    ret = ret + str(hex(ord(addr[1])))[2:]
  if ord(addr[0]) < 16:
    ret = ret + "0" + str(hex(ord(addr[0])))[2:]
  else:
    ret = ret + str(hex(ord(addr[0])))[2:]
  return ret

# Upload installed plugins and get upgrade agent informations
def sendFileName():
  try:
    while True:
      requrl = "http://" + jifangip + "/umsproxy/autoProxyPlugIn/sendFileName"
      filenames = file_name(plugin_dir)
      #logging.info(filenames)
      name = {}
      allips = get_all_ips()
      for item in allips:
        hip = re_format_ip(item)
        out = read_ip(hip)
        out.replace("\n", "")
        out.replace("\r", "")
        if out == "127.0.0.1":
          continue
        name = {"names":filenames}
        name["ip"] = out
        name = urllib.urlencode(name)
        logging.info("Upload ip and pluginName: " + str(name))
      try:
        req = urllib2.Request(url=requrl, data=name)
        res = urllib2.urlopen(req)
        data = res.read()
      except Exception as e:
        logging.info("Upload the machine IP and installed plugins to the proxy error: " + str(e))
      logging.info("Upload the machine IP and installed plugins to the proxy success: " + str(data))
      try:
        agentrequrl = "http://" + jifangip + "/umsproxy/autoProxyPlugIn/checkAgentVersion"
        data = ""
        req = urllib2.Request(url=agentrequrl, data=data)
        res = urllib2.urlopen(req)
        result = res.read()
        if result:
          logging.info("Get data from proxy when upgrade agent: " + str(result))
          result1 = json.loads(result)
          NEW_VERSION = result1["agentVersion"]
          if NEW_VERSION > VERSION:
            send_to_server = result
            udpsocket.sendto(send_to_server, address)
            udpsocket.close()
        #logging.info("Send upgrade data to agent.")
      except Exception as e:
        logging.info("Upgrade agent error: " + str(e))
      time.sleep(float(240))
  except Exception as e:
    logging.info("Upload the machine IP and installed plugins to the proxy error: " + str(e))
try:
  sendfilename = threading.Thread(target=sendFileName, args=())
  sendfilename.start()
except Exception as e:
  logging.info("Upload the machine IP and installed plugins to the proxy, thread error: " + str(e))

# report heart
def reportheart():
  try:
    while True:
      if os.path.exists("/home/opvis/opvis_agent/agent_service/agent.lock"):
        with open("/home/opvis/opvis_agent/agent_service/agent.lock", "r") as fd:
          jifangip = fd.read()
      else:
        logging.info("agent.lock not found!")
        sys.exit(1)
      ips = []
      ip = {}
      allips = get_all_ips()
      for item in allips:
        hip = re_format_ip(item)
        out = read_ip(hip)
        out.replace("\n", "")
        out.replace("\r", "")
        if out == "127.0.0.1":
          continue
        ips.append(out)
        ip["ip"] = ",".join(ips)
      logging.info(ip)
      ip = urllib.urlencode(ip)
      requrl = "http://" + jifangip + "/umsproxy/autoProxyPlugIn/sendIp"
      try:
        req = urllib2.Request(url=requrl, data=ip)
        res = urllib2.urlopen(req)
        data = res.read()
      except Exception as e:
        logging.info("Report heart to proxy error: " + str(e))
      if data:
        logging.info("Report heart to proxy success: " + str(data))
        time.sleep(float(240))
  except Exception as e:
    logging.info("Report heart to proxy error: " + str(e))
try:
  t = threading.Thread(target=reportheart, args=())
  t.daemon = True
  t.start()
except Exception as e:
  logging.info("Report heart to proxy error: " + str(e))


def callplugin():
  dirs = os.listdir(plugin_dir)
  plugin_dir1 = os.path.join(plugin_dir, plugin_name)
  if status == 6:
    if (plugin_name in dirs):
      try:
        temp = os.popen('sudo python %s' % plugin_dir1).readlines()
        logging.info("Plugin exists and execute successfully." + str(plugin_name))
        url_new = "http://" + tmp_url.split("/")[2] + "/umsproxy/hostExtract/uploadHostInformation"
        url_new = str(url_new)
        hostRelationship = {}
        hostRelationship["tableName"] = dic.get("tableName")
        hostRelationship["hostRelationship"] = temp
        hostRelationship = json.dumps(hostRelationship)
        header_dict = {"Content-Type": "application/json;charset=UTF-8"}
        req = urllib2.Request(url=url_new, data=hostRelationship, headers=header_dict)
        res = urllib2.urlopen(req, timeout=70)
        logging.info("Interface feedback upload hostinformation successfully: " + str(res.read()))
      except Exception as e:
        logging.info("Interface feedback upload hostinformation failed: " + str(e))
    else:
      logging.info("Plugin is not install: topologic.")
  else:
    cmd = "python /home/opvis/opvis_agent/agent_service/plugin/update.py" + " " + data2
    ret = os.system(cmd)

########################################################################################################################
# 获得本机房proxy的ip地址用于url拼接
with open("/home/opvis/opvis_agent/agent_service/agent.lock","r") as fd:
  proxy_ip = fd.readline()

# 查询数据库函数
def getAllprocess():
  get_process_url = "http://" + proxy_ip + ":9995" + "/selectinfo/"  # 这里应该也是需要拼接，ip为读取写入本地的ip文件
  ips = []
  ip = {}
  allips = get_all_ips()
  for item in allips:
    hip = re_format_ip(item)
    out = read_ip(hip)
    out.replace("\n", "")
    out.replace("\r", "")
    if out == "127.0.0.1":
      continue
    ips.append(out)
    ip = ",".join(ips)
  logging.info(ip)
  get_process_url += ip # 这下面的data就无意义
  # ip = urllib.urlencode(ip)
  req = urllib2.Request(url=get_process_url, data=ip)
  res = urllib2.urlopen(req)
  get_data = res.read()
  return get_data

def get_Old_cycle():
  get_data = getAllprocess()
  for i in range(get_data.__len__()):
    with open("all_items", "a") as fd:
      fd.write(json.dumps(get_data[i]))
      fd.write("\n")
  for i in range(get_data.__len__()):
    with open("allcycle_a", "a") as fd:
      trigger_cycle_value = "trigger_cycle_value" + str(get_data[i]["trigger_cycle_value"])
      fd.write(trigger_cycle_value)  # str
      fd.write("\n")

def get_New_cycle():
  get_data = getAllprocess()
  for i in range(get_data.__len__()):
    with open("allcycle_b", "a") as fd:
      trigger_cycle_value = "trigger_cycle_value" + str(get_data[i]["trigger_cycle_value"])
      fd.write(trigger_cycle_value)  # str
      fd.write("\n")

def gen_Cron_first():
  os.system("crontab -l >> {0}".format(crontab_opvis_a))
  p = os.popen("crontab -l|grep pmonitor|wc -l").readline()[0]
  if int(p) < 1:
    with open(allcycle_a, "r") as fd:
      lines = fd.readlines()
      for i in lines:
        cron_cmd = "*" + "/" + str(1) + " \* \* \* \* python " + pmonitorDir + " " + "trigger_cycle_value=" + str(i) + " \>\> " + " " + pmonitorLog
        os.system("echo {0} >> {1}".format(cron_cmd, crontab_opvis_b))
      os.system("crontab {0}".format(crontab_opvis_b))

def gen_Cron_later():
  get_New_cycle()
  stra = []
  strb = []
  strc = []
  fa = open(allcycle_a, 'r')
  fb = open(allcycle_b, 'r')
  fc = open(allcycle_c, 'w')
  for line in fa.readlines():
    stra.append(line.replace("\n", ''))
  for line in fb.readlines():
    strb.append(line.replace("\n", ''))
  for j in strb:
    if j not in stra:
      strc.append(j)
  for i in strc:
    fc.write(i + "\n")
  fa.close()
  fb.close()
  fc.close()
  os.system("crontab -l|grep pmonitor.py >> {0}".format(crontab_opvis_c))
  with open(allcycle_c, "r") as fd:
    lines = fd.readlines()
    for i in lines:
      cron_cmd = "*" + "/" + str(1) + " \* \* \* \* python " + pmonitorDir + " " + "trigger_cycle_value=" + str(i) + " \>\> " + " " + pmonitorLog
      os.system("echo {0} >> {1}".format(cron_cmd, crontab_opvis_c))
    os.system("crontab {0}".format(crontab_opvis_c))
os.remove(allcycle_a)
os.rename(allcycle_b, allcycle_a)

get_Old_cycle()
gen_Cron_first()
gen_Cron_later()
########################################################################################################################

# Get data from proxy
while True:
  data, addr = udpsocket.recvfrom(2018)
  time_second = time.time()
  logging.info(addr)
  logging.info("Time of data received: " + str(time_second))
  logging.info("Receive data from proxy: " + str(data))
  data1 = "{0}".format(data)
  lstr = "'''"
  rstr = "'''"
  data2 = lstr + data1 + rstr
  dic = json.loads(data)
  logging.info("Change data to dict: " + str(dic))
  if addr[0] != "127.0.0.1":
    status = dic["pluginfo"]["status"]
    tmp_url = dic["pluginfo"]["url"]
    plugin_name = tmp_url.split("/")[-1]
  name = dic.get("name")
########################################################################################################################
  pstatus = dic["pstatus"]
  processip = dic[ip]
  if pstatus == 7 and processip == localip:
    gen_Cron_later()
########################################################################################################################
  if name == "updateAgent":
    break
  else:
    try:
      t = threading.Thread(target=callplugin, args=())
      t.daemon = True
      t.start()
    except Exception, e:
      logging.info("Call the plugin error: " + str(e))

# Upgrade agent
udpsocket.close()
try:
  cmd = "python /home/opvis/opvis_agent/agent_service/update/agentupdate.py" + " " + data2
  ret = os.system(cmd)
except Exception as e:
  logging.info("Upgrade agent error: " + str(e))
