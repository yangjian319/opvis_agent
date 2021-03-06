#!/usr/bin/env python
# -*- coding:utf-8 -*-
# @Time  : 2008/7/4 9:25
# @Author: YYYY-MM
# @File  : agent_udp.py

import os
import sys
import time
import json
import fcntl
import struct
import array
import getopt
import socket
import random
import urllib
import urllib2
import filecmp
import logging
import commands
import datetime
import threading
import subprocess
import ConfigParser
from logging.handlers import TimedRotatingFileHandler

reload(sys)
sys.setdefaultencoding('utf8')
VERSION = 1
# log
if not os.path.exists("/home/opvis/utils/log"):
  os.makedirs("/home/opvis/utils/log")
if not os.path.exists("/home/opvis/utils/plugin"):
  os.makedirs("/home/opvis/utils/plugin")
LOG_FILE = "/home/opvis/utils/log/agent.log"
logger = logging.getLogger()
logger.setLevel(logging.INFO)
fh = TimedRotatingFileHandler(LOG_FILE, when='D', interval=1, backupCount=30)
datefmt = '%Y-%m-%d %H:%M:%S'
format_str = '%(asctime)s %(levelname)s %(message)s '
formatter = logging.Formatter(format_str, datefmt)
fh.setFormatter(formatter)
logger.addHandler(fh)

def daemon_process():
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

def post_md5(jifangip):
  (status, md5) = commands.getstatusoutput("sudo md5sum /root/.ssh/authorized_keys|awk '{print $1}'")
  requrl = "http://" + jifangip + "/umsproxy/autoProxyPlugIn/uploadMD5"
  req_data = {}
  req_data['md5'] = md5
  try:
    args_restful = urllib.urlencode(req_data)
    req = urllib2.Request(url=requrl, data=args_restful)
    res = urllib2.urlopen(req,timeout=70)
    data = res.read()
    if data:
      logging.info("Success,-- post_md5()")
  except Exception as e:
    logging.info("Error," + str(e) + " -- post_md5()")

def check_sudoers_md5():
    while True:
      if os.path.exists(sudoers_original_md5):
        with open("/home/opvis/utils/agent.lock", "r") as fd:
          proxy_ip = fd.readline().split(":")[0]
        post_sudoers_url = "http://" + proxy_ip + ":9995" + "/check_agent_sudo/"
        with open(sudoers_original_md5, "r") as fd:
          original_md5 = fd.readline()
        (status, md5) = commands.getstatusoutput("sudo md5sum /etc/sudoers|awk '{print $1}'")
        (status, permission) = commands.getstatusoutput("ls -l /etc/sudoers |awk '{print $1}'")
        (status, owner) = commands.getstatusoutput("ls -l /etc/sudoers|awk '{print $3}'")
        (status, group) = commands.getstatusoutput("ls -l /etc/sudoers|awk '{print $4}'")
        # 文件权限、属主、文件组、文件位置、文件内容
        if md5 != original_md5 or permission != "-rw-------" or owner != "root" or group != "root":
          ips = ""
          allips = get_all_ips()
          for item in allips:
            hip = re_format_ip(item)
            out = read_ip(hip)
            out.replace("\n", "")
            out.replace("\r", "")
            if out == "127.0.0.1":
              continue
            ips += out
            ips += ","
          ip = {"ip": ips}
          try:
            args_restful = urllib.urlencode(ip)
            req = urllib2.Request(url=post_sudoers_url, data=args_restful)
            res = urllib2.urlopen(req, timeout=70)
            data = res.read()
          except Exception as e:
            logging.info("Error," + str(e) + "-- check_sudoers_md5")
          logging.info("Success,-- check_sudoers_md5()")
        c = ConfigParser.ConfigParser()
        c.read("/home/opvis/utils/plugin/conf.ini")
        check_sudoers_md5_cycle = c.get("cycle", "check_sudoers_md5_cycle")
        time.sleep(float(check_sudoers_md5_cycle))
        # time.sleep(float(3600))
      else:
        break
        logging.info("checksudoers is not installed.")

# get pluginname
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
  while True:
    c = ConfigParser.ConfigParser()
    c.read("/home/opvis/utils/plugin/conf.ini")
    send_filename_cycle = c.get("cycle", "send_filename_cycle")
    try:
      requrl = "http://" + jifangip + "/umsproxy/autoProxyPlugIn/sendFileName"
      filenames = file_name(plugin_dir)
      name = {}
      allips = get_all_ips()
      for item in allips:
        hip = re_format_ip(item)
        out = read_ip(hip)
        out.replace("\n", "")
        out.replace("\r", "")
        if out == "127.0.0.1":
          continue
        name = {"names": filenames}
        name["ip"] = out
        name = urllib.urlencode(name)
      try:
        req = urllib2.Request(url=requrl, data=name)
        res = urllib2.urlopen(req)
        data = res.read()
        if data:
          logging.info("Success,-- sendFileName()")
          time.sleep(float(send_filename_cycle))
      except Exception as e:
        logging.info("Error:," + str(e) + " -- sendFileName()")
        # time.sleep(float(240))
        time.sleep(float(send_filename_cycle))
    except Exception as e:
      logging.info("Error," + str(e) + " -- sendFileName()")
      # time.sleep(float(240))
      time.sleep(float(send_filename_cycle))

def check_version():
  while True:
    c = ConfigParser.ConfigParser()
    c.read("/home/opvis/utils/plugin/conf.ini")
    check_version_cycle = c.get("cycle", "check_version_cycle")
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
        if NEW_VERSION != VERSION:
          send_to_server = result
          udpsocket.sendto(send_to_server, address)
          udpsocket.close()
      # time.sleep(float(240))
      time.sleep(float(check_version_cycle))
    except Exception as e:
      logging.info("Upgrade agent error: " + str(e))
      # time.sleep(float(240))
      time.sleep(float(check_version_cycle))

def check_cron():
  while True:
    crontab_temp = "/home/opvis/utils/cron/crontab_temp"
    if os.path.exists(crontab_temp):
      os.system("crontab -l > /home/opvis/utils/cron/crontab_running")
      compare_result = filecmp.cmp(r"/home/opvis/utils/cron/crontab_temp", r"/home/opvis/utils/cron/crontab_running")
      if compare_result == False:
        os.system("crontab {0}".format(crontab_temp))
    time.sleep(30)

# report heart
def report_heart():
  while True:
    c = ConfigParser.ConfigParser()
    c.read("/home/opvis/utils/plugin/conf.ini")
    report_heart_cycle = c.get("cycle", "report_heart_cycle")
    try:
      if os.path.exists("/home/opvis/utils/agent.lock"):
        with open("/home/opvis/utils/agent.lock", "r") as fd:
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
      ip = urllib.urlencode(ip)
      requrl = "http://" + jifangip + "/umsproxy/autoProxyPlugIn/sendIp"
      try:
        req = urllib2.Request(url=requrl, data=ip)
        res = urllib2.urlopen(req)
        data = res.read()
        if data:
          logging.info("Success,-- report_heart()")
          # time.sleep(float(240))
          time.sleep(float(report_heart_cycle))
      except Exception as e:
        logging.info("Error," + str(e) + " -- report_heart()")
        time.sleep(float(report_heart_cycle))
    except Exception as e:
      logging.info("Error," + str(e) + " -- report_heart()")
      # time.sleep(float(240))
      time.sleep(float(report_heart_cycle))

def call_plugin(status,tmp_url,dic,plugin_name,data2):
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
        logging.info("Success," + str(res.read()) + " -- " + str(plugin_name))
      except Exception as e:
        logging.info("Failed," + str(e) + " -- " + str(plugin_name))
    else:
      logging.info("Plugin is not installed: topologic.")
  else:
    # pack
    cmd = "/home/opvis/utils/plugin/update" + " " + data2
    # cmd = "python /home/opvis/utils/plugin/update.py" + " " + data2
    os.system(cmd)

def getAllprocess():
  try:
    with open("/home/opvis/utils/agent.lock", "r") as fd:
      proxy_ip = fd.readline().split(":")[0]
    get_process_url = "http://" + proxy_ip + ":9995" + "/selectinfo/"
    ips = ""
    allips = get_all_ips()
    for item in allips:
      hip = re_format_ip(item)
      out = read_ip(hip)
      out.replace("\n", "")
      out.replace("\r", "")
      if out == "127.0.0.1":
        continue
      ips += out
      ips += ","
    ip = {"ip":ips}
    ip = urllib.urlencode(ip)
    req = urllib2.Request(url=get_process_url, data=ip)
    res = urllib2.urlopen(req)
    get_data = res.read()
    return get_data
  except Exception as e:
    logging.info("Error," + str(e) + " -- getAllprocess()")
    return ""

def gen_crontab(i,yanshi):
  while True:
    cmd = "python " + pmonitorDir + " " + i
    os.system(cmd)
    time.sleep(float(yanshi))

def gen_Cron_first_minute():
  try:
    with open(allcycle_a, "r") as fd:
      lines = fd.readlines()
      for i in lines:
        if i.split(":")[1].strip(" ")[-2:-1] == "m":
          j = "cycle=" + i.split(":")[1].strip(" ")[:-1]
          yanshi = int(j.split("=")[1].strip(" ")[:-1])*60
          random_time = random.randint(1,59)
          random_time = random_time + round(random.random(),2)
          time.sleep(float(random_time))
          pid = os.fork()
          if pid == 0:
            sub_process_id = os.getpid()
            pidfile = j.split("=")[1] + ":" + str(sub_process_id)
            with open(pid_of_process, "a") as fd:
              fd.write(pidfile)
              fd.write("\n")
            gen_crontab(j, yanshi)
  except Exception as e:
    logging.info("Error," + str(e) + " -- gen_Cron_first_minute()")

def gen_Cron_first_hour():
  try:
    with open(allcycle_a, "r") as fd:
      lines = fd.readlines()
      for i in lines:
        if i.split(":")[1].strip(" ")[-2:-1] == "h":
          j = "cycle=" + i.split(":")[1].strip(" ")[:-1]
          yanshi = int(j.split("=")[1].strip(" ")[:-1])*3600
          random_time = random.randint(1,59)
          random_time = random_time + round(random.random(), 2)
          time.sleep(float(random_time))
          pid = os.fork()
          if pid == 0:
            sub_process_id = os.getpid()
            pidfile = j.split("=")[1] + ":" + str(sub_process_id)
            with open(pid_of_process, "a") as fd:
              fd.write(pidfile)
              fd.write("\n")
            gen_crontab(j, yanshi)
  except Exception as e:
    logging.info("Error," + str(e) + " -- gen_Cron_first_hour()")

def get_Old_cycle():
  if os.path.exists(allcycle_a):
    os.remove(allcycle_a)
  if os.path.exists(allitems):
    os.remove(allitems)
  try:
    while True:
      c = ConfigParser.ConfigParser()
      c.read("/home/opvis/utils/plugin/conf.ini")
      get_old_cycle = c.get("cycle", "get_old_cycle")
      try:
        get_data = getAllprocess()
        if get_data:
          logging.info("第一次getAllprocess获得的消息：" + str(get_data))
          break
        else:
          # time.sleep(60)
          time.sleep(float(get_old_cycle))
          continue
      except Exception as e:
        logging.info("Can't connect to proxy")
        # time.sleep(60)
        time.sleep(float(get_old_cycle))
    if get_data  != "no data":
      for i in json.loads(get_data):
        with open(allitems, "a") as fd:
          fd.write(json.dumps(i))
          fd.write("\n")
      cycle_unit = json.loads(get_data)
      trigger_cycle_value_minute = []
      trigger_cycle_value_hour = []
      for x in cycle_unit:
        if x["trigger_cycle_unit"] == 0:
          trigger_cycle_value_minute.append(str(x["trigger_cycle_value"]))
        else:
          trigger_cycle_value_hour.append(str(x["trigger_cycle_value"]))

      for cycle in set(trigger_cycle_value_minute):
        with open(allcycle_a, "a") as fd:
          fd.write('"trigger_cycle_value": ' + str(cycle) + "m")
          fd.write("\n")

      for cycle in set(trigger_cycle_value_hour):
        with open(allcycle_a, "a") as fd:
          fd.write('"trigger_cycle_value": ' + str(cycle) + "h")
          fd.write("\n")

      if trigger_cycle_value_minute:
        gen_Cron_first_minute()
      if trigger_cycle_value_hour:
        gen_Cron_first_hour()
    else:
      with open(allitems, "w") as fd:
        pass
      with open(allcycle_a, "w") as fd:
        pass
      logging.info("No data return from database. --get_Old_cycle()")
  except Exception as e:
    logging.info("Error," + str(e) + "--get_Old_cycle()")

def get_New_cycle():
  while True:
    c = ConfigParser.ConfigParser()
    c.read("/home/opvis/utils/plugin/conf.ini")
    get_new_cycle = c.get("cycle", "get_new_cycle")
    try:
      get_data = getAllprocess()
      if get_data:
        logging.info("新增监控开始..." + str(get_data))
        break
    except Exception as e:
      logging.info("Can't connect to proxy")
      # time.sleep(60)
      time.sleep(float(get_new_cycle))
  try:
    if get_data == 'no data':
      if os.path.exists(pid_of_process):
        with open(pid_of_process) as fd:
          lines = fd.readlines()
        for line in lines:
          pid = line.split(":")[1].replace("\n","")
          cmd = "kill -9 " + pid
          os.system(cmd)
        os.remove(pid_of_process)
        #os.remove(allitems)
        #cron_del_cmd1 = "sed -i '1,$d' {0}".format(pid_of_process)
        cron_del_cmd2 = "sed -i '1,$d' {0}".format(allitems)
        #os.system(cron_del_cmd1)
        os.system(cron_del_cmd2)
        with open(allcycle_a, "w") as fd:
          pass
      logging.info("数据库里面没有信息！--get_New_cycle()")
    else:
      os.remove(allitems)
      for i in json.loads(get_data):
        with open(allitems, "a") as fd:
          fd.write(json.dumps(i))
          fd.write("\n")
      if not os.path.exists(allcycle_a):
        with open(allcycle_a, "w") as fd:
          pass
      cycle_unit = json.loads(get_data)
      trigger_cycle_value_minute = []
      trigger_cycle_value_hour = []
      for x in cycle_unit:
        if x["trigger_cycle_unit"] == 0:
          trigger_cycle_value_minute.append(str(x["trigger_cycle_value"]))
        else:
          trigger_cycle_value_hour.append(str(x["trigger_cycle_value"]))

      for cycle in set(trigger_cycle_value_minute):
        with open(allcycle_b, "a") as fd:
          fd.write('"trigger_cycle_value": ' + str(cycle) + "m")
          fd.write("\n")

      for cycle in set(trigger_cycle_value_hour):
        with open(allcycle_b, "a") as fd:
          fd.write('"trigger_cycle_value": ' + str(cycle) + "h")
          fd.write("\n")
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
      logging.info("stra: " + str(stra))
      logging.info("strb: " + str(strb))
      logging.info("strc: " + str(strc))
      if len(stra) < len(strb):  # 新增监控
        logging.info("新增监控")
        with open(allcycle_c, "r") as fd:
          lines = fd.readlines()
        for i in lines:
          if i.split(":")[1].strip(" ")[-2:-1] == "m":
            j = "cycle=" + i.split(":")[1].strip(" ")[:-1]
            yanshi = int(j.split("=")[1].strip(" ")[:-1]) * 60
            random_time = random.randint(1, 59)
            random_time = random_time + round(random.random(), 2)
            time.sleep(float(random_time))
            pid = os.fork()
            if pid == 0:
              sub_process_id = os.getpid()
              pidfile = j.split("=")[1] + ":" + str(sub_process_id)
              with open(pid_of_process, "a") as fd:
                fd.write(pidfile)
                fd.write("\n")
              gen_crontab(j, yanshi)
          elif i.split(":")[1].strip(" ")[-2:-1] == "h":
            j = "cycle=" + i.split(":")[1].strip(" ")[:-1]
            yanshi = int(j.split("=")[1].strip(" ")[:-1]) * 3600
            random_time = random.randint(1, 59)
            random_time = random_time + round(random.random(), 2)
            time.sleep(float(random_time))
            pid = os.fork()
            if pid == 0:
              sub_process_id = os.getpid()
              pidfile = j.split("=")[1] + ":" + str(sub_process_id)
              with open(pid_of_process, "a") as fd:
                fd.write(pidfile)
                fd.write("\n")
              gen_crontab(j, yanshi)
      # allcycle_a为空的时候，新增完监控，需要把allcycle_b里面的内容放到allcycle_b里面
      elif len(stra) > len(strb):  # 删除监控
        logging.info("删除监控")
        logging.info("stra: " + str(stra))
        logging.info("strb: " + str(strb))
        del_strc = set(stra) - set(strb)
        for i in del_strc:
          dic_minute_hour = {}
          del_minute_hour = i.split(":")[1].strip(" ")
          with open(pid_of_process, "r") as fd:
            for line in fd.readlines():
              line = line.replace("\n", "").split(":")
              dic_minute_hour[line[0]] = line[1]
          del_pid = dic_minute_hour[del_minute_hour]
          logging.info("要删除的进程：" + str(del_pid))
          cmd = "kill -9 " + del_pid
          os.system(cmd)
          cron_del_cmd = "sed -i '/{0}/d' {1}".format(del_pid, pid_of_process)
          os.system(cron_del_cmd)
      elif len(stra) == len(strb):  # 如果两个长度相等，再去判断是增加了呢还是删除了
        logging.info("修改监控")
        del_process = set(stra) - set(strb)
        logging.info("删除定时任务 " + str(del_process))
        if del_process:
          for x in del_process:
            del_cycle = x.split(":")[1].strip(" ")
          with open(pid_of_process, "r") as fd:
            for line in fd.readlines():
              if line.startswith(del_cycle):
                del_pid_number = line.split(":")[1].strip()
                logging.info("要删除的pid " + str(del_pid_number))
                cmd = "kill -9 " + str(del_pid_number)
                os.system(cmd)
                cron_del_cmd = "sed -i '/{0}/d' {1}".format(del_pid_number, pid_of_process)
                logging.info("删除文件里面的记录 " + str(cron_del_cmd))
                os.system(cron_del_cmd)
        add_process = set(strb) - set(stra)
        if add_process:
          logging.info("add_process：" + str(add_process))
          for x in add_process:  # "trigger_cycle_value: 2h"
            if x.split(":")[1].strip(" ")[-1:] == "m":
              j = "cycle=" + x.split(":")[1].strip(" ")
              yanshi = int(j.split("=")[1].strip(" ")[:-1]) * 60
              random_time = random.randint(1, 59)
              random_time = random_time + round(random.random(), 2)
              time.sleep(float(random_time))
              pid = os.fork()
              if pid == 0:
                sub_process_id = os.getpid()
                pidfile = j.split("=")[1] + ":" + str(sub_process_id)
                with open(pid_of_process, "a") as fd:
                  fd.write(pidfile)
                  fd.write("\n")
                gen_crontab(j, yanshi)
            elif x.split(":")[1].strip(" ")[-1:] == "h":
              j = "cycle=" + x.split(":")[1].strip(" ")
              yanshi = int(j.split("=")[1].strip(" ")[:-1]) * 3600
              random_time = random.randint(1, 59)
              random_time = random_time + round(random.random(), 2)
              time.sleep(float(random_time))
              pid = os.fork()
              if pid == 0:
                sub_process_id = os.getpid()
                pidfile = j.split("=")[1] + ":" + str(sub_process_id)
                with open(pid_of_process, "a") as fd:
                  fd.write(pidfile)
                  fd.write("\n")
                gen_crontab(j, yanshi)
  except Exception as e:
    logging.info("Error," + str(e) + "get_New_cycle()")

# 在线调试
def online_debug(dic):
  with open("/home/opvis/utils/agent.lock", "r") as fd:
    proxy_ip = fd.readline().split(":")[0]
  get_id_url = "http://" + proxy_ip + ":9995" + "/online_debug/"
  get_data_url = "http://" + proxy_ip + ":9995" + "/debug_info/" # 调用接口获取shell脚本内容
  id = dic["id"]
  get_debug_data = {}
  get_debug_data["id"] = id
  data = urllib.urlencode(get_debug_data)
  req = urllib2.Request(url=get_data_url, data=data)
  res = urllib2.urlopen(req)
  get_data = res.read()
  start_time = int(time.time()*1000)
  if not get_data:
    logging.info("数据库里面没有这条数据")
  elif get_data == "1":
    logging.info("python server error.")
  else:
    logging.info("get data from debug_info: " + str(get_data))
    debug_data = json.loads(get_data)
    shell_cmd = "cd /home/opvis;" + debug_data["data"]
    logging.info("shell_cmd: " + str(shell_cmd))
    execute_time = debug_data["execute_time"]
    if execute_time:
      end_time = datetime.datetime.now() + datetime.timedelta(seconds=int(execute_time))
    else:
      # 如果页面没有传超时时间，就默认10s
      end_time = datetime.datetime.now() + datetime.timedelta(seconds=10)
    sub = subprocess.Popen(shell_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    overtime_alarm = 1
    result = ""
    var = 1
    while True:
      if sub.poll() is not None:
        break
      time.sleep(0.1)
      if end_time <= datetime.datetime.now():
        var = 0
        overtime_alarm = 2
        sub.kill()
        break  # 为了防止结果和错误都为空，如ls一个空目录
      else:
        overtime_alarm = 1
    if var:
      (stdoutput, erroutput) = sub.communicate()
      if erroutput:
        result = erroutput
      else:
        result = stdoutput
    logging.info("overtime_alarm: " + str(overtime_alarm))
    data = {}
    ends_time = int(time.time()*1000)
    data["start_time"] = str(start_time)
    data["end_time"] = str(ends_time)
    data["id"] = dic["id"]
    data["result"] = result
    data["have_result"] = overtime_alarm
    data = urllib.urlencode(data)
    req = urllib2.Request(url=get_id_url, data=data)
    res = urllib2.urlopen(req)
    get_data = res.read()
    logging.info("transfer feedback " + str(get_data))

# 定点监控添加
def settled_mon_add(dic):
  try:
    with open("/home/opvis/utils/agent.lock", "r") as fd:
      proxy_ip = fd.readline().split(":")[0]
    get_data_url = "http://" + proxy_ip + ":9995" + "/fixed_point_data/"  # 调用接口获取shell脚本内容
    report_to_pyserver = "http://" + proxy_ip + ":9995" + "/agent_del_msg/"  # 新增完成后反馈给python server是否执行成功
    id = dic["id"]
    get_debug_data = {}
    get_debug_data["id"] = id
    data = urllib.urlencode(get_debug_data)
    req = urllib2.Request(url=get_data_url, data=data)
    res = urllib2.urlopen(req)
    get_data = res.read()
    logging.info("定点监控新增获取到的数据：" + str(get_data))
    if not get_data:
      logging.info("数据库里面没有这条数据")
    elif get_data == "1":
      logging.info("python server error.")
    else:
      logging.info("get data settled_mon_add: " + str(get_data))
      debug_data = json.loads(get_data)
      biz_ip = debug_data["biz_ip"]
      shell_cmd = debug_data["data"]
      execute_cycle = debug_data["execute_cycle"]
      limit_time = debug_data["limit_time"]  # 定点监控超时时间
      limit_time = str(limit_time)
      if limit_time == "":
        limit_time = "10"
      unit = debug_data["unit"]
      shell_path = settled_monitor + id
      shell_name = id
      with open(shell_path, "w") as fd:
        fd.write(shell_cmd)
      # 接下来要判断unit是分钟还是小时还是天，并进行转换
      if unit == 0:
        cron_cmd = "*" + "/" + str(
          execute_cycle) + " * * * * python /home/opvis/utils/plugin/settled_monitor.py " + "'" + shell_name + "'" + " " + limit_time + " " + biz_ip
      elif unit == 1:
        cron_cmd = "* *" + "/" + str(
          execute_cycle) + " * * * python /home/opvis/utils/plugin/settled_monitor.py " + "'" + shell_name + "'" + " " + limit_time + " " + biz_ip
      elif unit == 2:
        cron_cmd = "* * *" + "/" + str(
          execute_cycle) + " * * python /home/opvis/utils/plugin/settled_monitor.py " + "'" + shell_name + "'" + " " + limit_time + " " + biz_ip
      # shell_path =  "/home/opvis/utils/plugin/shell_scripts/id"
      logging.info("定点监控定时任务：" + str(cron_cmd))
      with open(crontab_settled_monitor, "a") as fd:
        fd.write(cron_cmd)
        fd.write("\n")
      os.system("crontab {0}".format(crontab_settled_monitor))
      report_data = {}
      report_data["id"] = id
      report_data["msg"] = "ok"
      report_data["status"] = 1
      data = urllib.urlencode(report_data)
      req = urllib2.Request(url=report_to_pyserver, data=data)
      res = urllib2.urlopen(req)
  except Exception as e:
    report_data = {}
    report_data["id"] = id
    report_data["msg"] = "no"
    report_data["status"] = 1
    data = urllib.urlencode(report_data)
    req = urllib2.Request(url=report_to_pyserver, data=data)
    res = urllib2.urlopen(req)


# 定点监控删除
def settled_mon_delete(dic):
  with open("/home/opvis/utils/agent.lock", "r") as fd:
    proxy_ip = fd.readline().split(":")[0]
  report_to_pyserver = "http://" + proxy_ip + ":9995" + "/agent_del_msg/"  # 新增完成后反馈给python server是否执行成功
  try:
    with open("/home/opvis/utils/agent.lock", "r") as fd:
      proxy_ip = fd.readline().split(":")[0]
    id = dic["id"]
    shell_name = id
    cron_del_cmd = "sed -i '/{0}/d' {1}".format(shell_name, crontab_settled_monitor)
    os.system(cron_del_cmd)
    os.system("crontab {0}".format(crontab_settled_monitor))
    old_shell_name = os.listdir(settled_monitor)
    for i in old_shell_name:
      if shell_name in i:
        os.chdir(settled_monitor)
        os.remove(i)
    logging.info("定点监控删除")
    report_data = {}
    report_data["id"] = id
    report_data["msg"] = "ok"
    report_data["status"] = 2
    data = urllib.urlencode(report_data)
    req = urllib2.Request(url=report_to_pyserver, data=data)
    res = urllib2.urlopen(req)
  except Exception as e:
    report_data = {}
    report_data["id"] = id
    report_data["msg"] = "no"
    report_data["status"] = 2
    data = urllib.urlencode(report_data)
    req = urllib2.Request(url=report_to_pyserver, data=data)
    res = urllib2.urlopen(req)

# 定点监控修改
def settled_mon_edit(dic):
  try:
    with open("/home/opvis/utils/agent.lock", "r") as fd:
      proxy_ip = fd.readline().split(":")[0]
    get_data_url = "http://" + proxy_ip + ":9995" + "/fixed_point_data/"  # 调用接口获取shell脚本内容
    report_to_pyserver = "http://" + proxy_ip + ":9995" + "/agent_del_msg/"  # 新增完成后反馈给python server是否执行成功
    id = dic["id"]
    get_debug_data = {}
    get_debug_data["id"] = id
    data = urllib.urlencode(get_debug_data)
    req = urllib2.Request(url=get_data_url, data=data)
    res = urllib2.urlopen(req)
    get_data = res.read()
    if not get_data:
      logging.info("数据库里面没有这条数据")
    elif get_data == "1":
      logging.info("python server error.")
    else:
      logging.info("get data from debug_info: " + str(get_data))
      debug_data = json.loads(get_data)
      biz_ip = debug_data["biz_ip"]
      shell_cmd = debug_data["data"]
      execute_cycle = debug_data["execute_cycle"]
      unit = debug_data["unit"]
      limit_time = debug_data["limit_time"]  # 定点监控超时时间
      limit_time = str(limit_time)
      if limit_time == "":
        limit_time = "10"
      shell_path = settled_monitor + id
      shell_name = id
      os.remove(shell_path)
      with open(shell_path, "w") as fd:
        fd.write(shell_cmd)
      cron_del_cmd = "sed -i '/{0}/d' {1}".format(id, crontab_settled_monitor)
      os.system(cron_del_cmd)
      if unit == 0:
        cron_cmd = "*" + "/" + str(
          execute_cycle) + " * * * * python /home/opvis/utils/plugin/settled_monitor.py " + "'" + shell_name + "'" + " " + limit_time + " " + biz_ip
      elif unit == 1:
        cron_cmd = "* *" + "/" + str(
          execute_cycle) + " * * * python /home/opvis/utils/plugin/settled_monitor.py " + "'" + shell_name + "'" + " " + limit_time + " " + biz_ip
      elif unit == 2:
        cron_cmd = "* * *" + "/" + str(
          execute_cycle) + " * * python /home/opvis/utils/plugin/settled_monitor.py " + "'" + shell_name + "'" + " " + limit_time + " " + biz_ip
      logging.info("定点监控修改定时任务：" + str(cron_cmd))
      with open(crontab_settled_monitor, "a") as fd:
        fd.write(cron_cmd)
        fd.write("\n")
      os.system("crontab {0}".format(crontab_settled_monitor))
      report_data = {}
      report_data["id"] = id
      report_data["msg"] = "ok"
      report_data["status"] = 3
      data = urllib.urlencode(report_data)
      req = urllib2.Request(url=report_to_pyserver, data=data)
      res = urllib2.urlopen(req)
  except Exception as e:
    report_data = {}
    report_data["id"] = id
    report_data["msg"] = "no"
    report_data["status"] = 3
    data = urllib.urlencode(report_data)
    req = urllib2.Request(url=report_to_pyserver, data=data)
    res = urllib2.urlopen(req)

def do_data(data,addr,dic,data2):
  if "pstatus" in dic:
    pid = os.fork()
    if pid == 0:
      get_New_cycle()
      os.remove(allcycle_a)
      os.rename(allcycle_b, allcycle_a)
      os.remove(allcycle_c)
      sys.exit()
  elif "status" in dic and dic["status"] == 8:
    try:
      (status, md5) = commands.getstatusoutput("sudo md5sum /etc/sudoers|awk '{print $1}'")
      if not os.path.exists(sudoers_original_md5):
        with open(sudoers_original_md5, "w") as fd:
          fd.write(md5)
      check_sudoers_md5s = threading.Thread(target=check_sudoers_md5, args=())
      random_time = random.randint(1, 59)
      random_time = random_time + round(random.random(), 2)
      time.sleep(float(random_time))
      check_sudoers_md5s.start()
    except Exception as e:
      logging.info("Check sudoers md5, thread error: " + str(e) + "-- check_sudoers_md5()")
  elif dic["status"] == 9:  # 在线调试
    try:
      pid = os.fork()
      if pid == 0:
        logging.info("处理在线调试9的进程id：" + str(os.getpid()))
        online_debug(dic)
    except Exception as e:
      logging.info("Online debug, error: " + str(e) + "-- online_debug")
  elif dic["status"] == 10:  # 定点监控新增
    try:
      logging.info("定点监控新增收到消息")
      settled_mon_add(dic)
    except Exception as e:
      logging.info("settled_mon_add, error: " + str(e) + "-- settled_mon_add()")
  elif dic["status"] == 11:  # 定点监控删除
    try:
      settled_mon_delete(dic)
    except Exception as e:
      logging.info("settled_mon_delete, error: " + str(e) + "-- settled_mon_delete()")

  elif dic["status"] == 12:  # 定点监控修改
    try:
      settled_mon_edit(dic)
    except Exception as e:
      logging.info("settled_mon_edit, error: " + str(e) + "-- settled_mon_edit()")
  else:
    if addr[0] != "127.0.0.1":
      status = dic["pluginfo"]["status"]
      tmp_url = dic["pluginfo"]["url"]
      plugin_name = tmp_url.split("/")[-1]
      try:
        callplugin = threading.Thread(target=call_plugin, args=(status, tmp_url, dic, plugin_name, data2))
        callplugin.daemon = True
        callplugin.start()
      except Exception, e:
        logging.info("Call the plugin error: " + str(e))

def main():
  try:
    sendfilename = threading.Thread(target=sendFileName, args=())
    sendfilename.start()
  except Exception as e:
    logging.info("Upload ip and plugin name to proxy, thread error: " + str(e))

  try:
    reportheart = threading.Thread(target=report_heart, args=())
    reportheart.daemon = True
    reportheart.start()
  except Exception as e:
    logging.info("Report heart, thread error: " + str(e))

  try:
    checkversion = threading.Thread(target=check_version, args=())
    checkversion.daemon = True
    checkversion.start()
  except Exception as e:
    logging.info("Check version, thread error: " + str(e))

  try:
    checkcron = threading.Thread(target=check_cron,args=())
    checkcron.daemon = True
    checkcron.start()
  except Exception as e:
    logging.info("Check crontab, thread error: " + str(e))

  # Get data from proxy
  while True:
    data, addr = udpsocket.recvfrom(2018)
    start_time = datetime.datetime.now()
    data1 = "{0}".format(data)
    lstr = "'''"
    rstr = "'''"
    data2 = lstr + data1 + rstr
    dic = json.loads(data)
    logging.info("Change data to dict: " + str(dic))
    if data:
      name = dic.get("name")
      if name == "updateAgent":
        break
      pid = os.fork()
      if pid == 0:
        pid2 = os.fork()
        if pid2 == 0:
          logging.info("Receive data from proxy: " + str(data))
          logging.info("统一处理data的进程id：" + str(os.getpid()))
          do_data(data, addr, dic, data2)
          sys.exit(0)
        else:
          os._exit(0)
      else:
        os.wait()
        end_time = datetime.datetime.now()
        c_time = end_time - start_time
        logging.info("时间： " + str(c_time))

  udpsocket.close()
  try:
    # pack
    # cmd = "/home/opvis/opvis_agent/agent_service/update/agentupdate" + " " + data2
    cmd = "python /home/opvis/opvis_agent/agent_service/update/agentupdate.py" + " " + data2
    ret = os.system(cmd)
  except Exception as e:
    logging.info("Upgrade agent error: " + str(e))

if __name__=='__main__':
  allitems = "/home/opvis/utils/pm/allitems"
  allcycle_a = "/home/opvis/utils/pm/allcycle_a"
  allcycle_b = "/home/opvis/utils/pm/allcycle_b"
  allcycle_c = "/home/opvis/utils/pm/allcycle_c"
  pid_of_process = "/home/opvis/utils/pm/pid_of_process"
  crontab_settled_monitor = "/home/opvis/utils/cron/crontab_temp"
  crontab_opvis_b_del = "/home/opvis/utils/cron/crontab_opvis_b_del"
  sudoers_original_md5 = "/home/opvis/utils/pm/sudoers_original_md5"
  pmonitorLog = "/home/opvis/utils/log/pmonitor.log"
  pmonitorDir = "/home/opvis/utils/plugin/pmonitor.py"
  plugin_dir = "/home/opvis/utils/plugin/"
  settled_monitor = "/home/opvis/utils/plugin/shell_scripts/"

  if not os.path.exists("/home/opvis/utils"):
    os.makedirs("/home/opvis/utils")
    os.makedirs("/home/opvis/utils/log")
  if not os.path.exists("/home/opvis/utils/pm"):
    os.makedirs("/home/opvis/utils/pm")
  if not os.path.exists("/home/opvis/utils/cron"):
    os.makedirs("/home/opvis/utils/cron")
  if not os.path.exists("/home/opvis/utils/plugin/shell_scripts"):
    os.makedirs("/home/opvis/utils/plugin/shell_scripts")
  try:
    address = ("0.0.0.0", 9997)
    udpsocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udpsocket.bind(address)
  except Exception as e:
    logging.info("Udp connection error: " + str(e))
  # iplist = ["10.181.45.6:18382"]
  iplist = ["172.30.130.137:18382", "172.30.130.126:18382", "10.124.5.163:18382", "10.144.2.248:18382",
            "10.123.30.177:18382", "172.30.194.121:18382", "172.16.5.20:18382", "10.181.1.0:18382"]

  for ip in iplist:
    try:
      so = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      so.settimeout(2)
      so.connect((ip.split(":")[0], 18382))
      currentip = ip
      with open("/home/opvis/utils/agent.lock", "wb") as fd:
        fd.write(currentip)
      so.close()
    except Exception as e:
      logging.info("Determine which area the machine belongs to error: " + str(e))
  jifangip = currentip
  daemon_process()
  post_md5(jifangip)
  pid = os.fork()
  if pid==0:
    pid2 =os.fork()
    if pid2 == 0:
      if os.path.exists(pid_of_process):
        os.remove(pid_of_process)
      get_Old_cycle()
    else:
      os._exit(0)
  else:
    os.wait()
    main()
