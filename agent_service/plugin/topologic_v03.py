#!/usr/bin/python
# -*- coding:utf-8 -*-
import json
import logging
import os
import socket
import urllib2
from logging.handlers import TimedRotatingFileHandler

import fcntl
import struct
import array
import sys
import time
import getopt
from datetime import datetime
import ConfigParser

# log
LOG_FILE = "/home/opvis/opvis_agent/agent_service/log/update.log"
logger = logging.getLogger()
logger.setLevel(logging.INFO)
fh = TimedRotatingFileHandler(LOG_FILE, when='D', interval=1, backupCount=30)
datefmt = '%Y-%m-%d %H:%M:%S'
format_str = '%(asctime)s %(levelname)s %(message)s '
formatter = logging.Formatter(format_str, datefmt)
fh.setFormatter(formatter)
logger.addHandler(fh)

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
def read_port(port):
  return str(int(port,16))
# format ip from char
def format_ip(addr):
  return str(ord(addr[0])) + '.' + \
         str(ord(addr[1])) + '.' + \
         str(ord(addr[2])) + '.' + \
         str(ord(addr[3]))
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

# unique the list
def unique(list):  
  newlist = []  
  for x in list:  
    if x not in newlist:  
      newlist.append(x)  
  return newlist 
# print usage info  
def usage():  
  print "usage: netlink [-tuvh] (this tool should run with root privilege)"
  print "-t    provide tcp protocol only(both tcp and udp will provided without specifying -t nor -u)"
  print "-u    provide udp protocol only"
  print "-v    show version"
  print "-h    show help"  

# print version info  
def version():
  print "netlink v0.9 by lintelwang(www.lintel.wang||lintelwang@163.com)"  

# get link info function   
def get_links(tflag,uflag,allips):  
  nets = {}
  tcpinfo = {}
  udpinfo = {}
  tcpinfo['LISTEN'] = []
  tcpinfo['SERVER'] = []
  tcpinfo['CLIENT'] = []
  tcpinfo['OTHERS'] = []
  udpinfo['LISTEN'] = []
  udpinfo['SERVER'] = []
  udpinfo['CLIENT'] = []
  udpinfo['OTHERS'] = []
  tcplisten = []
  udplisten = []
  # load tcp info  
  if tflag:
    try:
      tcpf = open('/proc/net/tcp')
      tcpinfos = tcpf.readlines(65536)
      tcpf.close()
      for tinfo in tcpinfos:
        tmparray = []
        for item in tinfo.split(' '):
          if item:
            tmparray.append(item)
        nets[tmparray[9]] = ['tcp',tmparray[1],tmparray[2],tmparray[3]]    
    except Exception,e:
      print '/proc/net/tcp open failed!'
      sys.exit(-1)
      
  # load udp info
  if uflag:
    try:
      udpf = open('/proc/net/udp')
      udpinfos = udpf.readlines(65536)
      udpf.close()
      for uinfo in udpinfos:
        tmparray = []
        for item in uinfo.split(' '):
          if item:
            tmparray.append(item)
        nets[tmparray[9]] = ['udp',tmparray[1],tmparray[2],tmparray[3]]
    except Exception,e:
      print '/proc/net/udp open failed!'
      sys.exit(-1)  
    
  # drop the table-head
  nets.pop('uid')
        
  # get all sub-dir in /proc 
  proc = os.listdir('/proc')
  procs = []    
  for item in proc:
    try:
      tmp = long(item)
      # get cmdlines[0] of pid
      cmdf = open('/proc/' + item + '/cmdline')
      cmdlines = []
      while True:
        cmdlines = cmdf.readlines(1)
        break
      cmdf.close()  
      # get all sockets
      tmpsocks = []
      for element in os.listdir('/proc/'+item+'/fd/'):   
        try:
          tmplink = os.readlink('/proc/'+item+'/fd/'+element)
          if tmplink[0:8] == 'socket:[':
            procs.append([long(item),cmdlines[0].replace('\0',' ').strip(),tmplink.split('[')[1].split(']')[0]])
        except Exception,e:
          pass
    except Exception,e:
      pass

  # get all infos    
  for i in procs:
    try:
      ninfo = nets[i[2]]
      if ninfo[0] == 'tcp':
        if ninfo[3] == '0A':
          tcpinfo['LISTEN'].append([ninfo[1].split(':')[0],ninfo[1].split(':')[1],ninfo[1],'-','-',i[1]])
        elif ninfo[3] == '01' or ninfo[3] == '02' or ninfo[3] == '03' or ninfo[3] == '04' or ninfo[3] == '05' or ninfo[3] == '06':
          tcpinfo['OTHERS'].append([ninfo[1].split(':')[0],ninfo[1].split(':')[1],ninfo[1],ninfo[2].split(':')[0],ninfo[2].split(':')[1],i[1]])
      if ninfo[0] == 'udp':
        if ninfo[3] == '07':
          udpinfo['LISTEN'].append([ninfo[1].split(':')[0],ninfo[1].split(':')[1],ninfo[1],'-','-',i[1]])
        elif ninfo[3] == '01':
          udpinfo['OTHERS'].append([ninfo[1].split(':')[0],ninfo[1].split(':')[1],ninfo[1],ninfo[2].split(':')[0],ninfo[2].split(':')[1],i[1]])
    except Exception,e:
      pass
  # judge listen items    
  if tflag:      
    for item in tcpinfo['LISTEN']:
      if item[0] == '00000000':
        for element in allips:
          tcpinfo['LISTEN'].append([element,item[1],element + item[1],'-','-',item[5]])
          tcplisten.append(element.upper() + ":" + item[1].upper())
      else:
        tcplisten.append(item[2]) 
  if uflag:        
    for item in udpinfo['LISTEN']:
      if item[0] == '00000000':
        for element in allips:
          udpinfo['LISTEN'].append([element,item[1],element + item[1],'-','-',item[5]])  
          udplisten.append(element.upper() + ":" + item[1].upper())
      else:
        udplisten.append(item[2]) 
  # judge server and client items        
  if tflag: 
    for item in tcpinfo['OTHERS']:  
      if item[2] in tcplisten:
        tcpinfo['SERVER'].append([item[0],item[1],item[3],item[4],item[5]])
      else:
        tcpinfo['CLIENT'].append([item[0],item[1],item[3],item[4],item[5]])
    tcpinfo.pop('OTHERS')
  if uflag:
    for item in udpinfo['OTHERS']:     
      if item[2] in udplisten:
        udpinfo['SERVER'].append([item[0],item[1],item[3],item[4],item[5]])
      else:
        udpinfo['CLIENT'].append([item[0],item[1],item[3],item[4],item[5]])
    udpinfo.pop('OTHERS')
  # output final result the format is : protocol||role||local ip||local port||remote ip||remote port||local cmdline  
  if tflag:
    for ele in ['LISTEN','SERVER','CLIENT']:
      for row in unique(tcpinfo[ele]):
        if ele == 'LISTEN':
          if row[0] != '00000000':
            print "TCP||" + ele +"||" + read_ip(row[0]) + "||" + read_port(row[1]) + "||" + row[3] + "||" + row[4] + "||" + row[5]
        else:
          print "TCP||" + ele +"||" + read_ip(row[0]) + "||" + read_port(row[1]) + "||" + read_ip(row[2]) + "||" + read_port(row[3]) + "||" + row[4]
  if uflag:    
    for ele in ['LISTEN','SERVER','CLIENT']:
      for row in unique(udpinfo[ele]):
        if ele == 'LISTEN':
          if row[0] != '00000000':
            print "UDP||" + ele +"||" + read_ip(row[0]) + "||" + read_port(row[1]) + "||" + row[3] + "||" + row[4] + "||" + row[5]  
        else:
          print "UDP||" + ele +"||" + read_ip(row[0]) + "||" + read_port(row[1]) + "||" + read_ip(row[2]) + "||" + read_port(row[3]) + "||" + row[4]
    
if __name__ == '__main__':
  allip = get_all_ips()
  allips = []
  with open("/home/opvis/opvis_agent/agent_service/agent.lock", "r") as fd:
    jifangip = fd.read()
  requrl = "http://" + jifangip + "/umsproxy/hostPlugInOperation/uploadPlugLog"
  for item in allip:
    allips.append(re_format_ip(item))
  if os.getuid() != 0:
    usage()
    sys.exit(-1)
  try:
    opts, args = getopt.getopt(sys.argv[1:], "tuvh")
    ftcp = 0
    fudp = 0
    for opt,arg in opts:
      if opt in ("-h"):  
        usage()
        sys.exit(1)
      elif opt in ("-v"):
        version()
        sys.exit(1)
      else:
        if opt in ("-t"):
          ftcp = 1
        if opt in ("-u"):
          fudp = 1
    if ftcp == 0 and fudp == 0 :
      get_links(1,1,allips)
    else:
      get_links(ftcp,fudp,allips)
    plug_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    data = {}
    data["plug_name"] = sys.argv[0].split("/")[-1]
    data["plug_time"] = plug_time
    data["plug_status"] = "0"
    data = json.dumps(data)
    headers = {"Content-Type": "application/json"}
    req = urllib2.Request(url=requrl, headers=headers, data=data.encode())
    response = urllib2.urlopen(req)
    result = response.read()
    logging.info("Interface feedback successfully: " + str(result))
  except getopt.GetoptError as err:
    plug_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    data = {}
    data["plug_name"] = sys.argv[0].split("/")[-1]
    data["plug_time"] = plug_time
    data["plug_status"] = "0"
    data = json.dumps(data)
    headers = {"Content-Type": "application/json"}
    req = urllib2.Request(url=requrl, headers=headers, data=data.encode())
    response = urllib2.urlopen(req)
    result = response.read()
    logging.info("Failed!")
    logging.info("Interface feedback failed: " + str(result))
    usage()
    sys.exit(-1)  
