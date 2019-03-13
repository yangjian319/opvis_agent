#!/bin/bash
time=`date +%Y%m%d%H%M%S`
ps aux|grep agent_udp|grep -v grep|awk '{print $2}'|xargs kill -9
rm -rf  /home/opvis/opvis_agent
tar zxf /home/opvis/opvis_agent_v*.tar.gz -C /home/opvis/
mv /home/opvis/opvis_agent_v*.tar.gz /home/opvis/$1.$time
cd /home/opvis/opvis_agent/agent_service
sh start.sh
