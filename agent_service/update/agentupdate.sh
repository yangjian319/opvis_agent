#!/bin/bash
time=`date +%Y%m%d%H%M%S`
ps aux|grep agent_udp.py|grep -v grep|awk '{print $2}'|xargs kill -9
rm -rf  /home/opvis/opvis_agent
tar zxf /home/opvis/opvis_agent.tar.gz -C /home/opvis/
mv /home/opvis/opvis_agent.tar.gz /home/opvis/opvis_agent.tar.gz.$time
python /home/opvis/utils/agent_udp.py