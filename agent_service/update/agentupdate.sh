#!/bin/bash
date=`date +%Y%m%d`
mv /home/opvis/opvis_agent/agent_service/agent_udp.py /home/opvis/opvis_agent/agent_service/temp/agent_udp.py.$date
cp /home/opvis/opvis_agent/agent_service/temp/agent_udp.py /home/opvis/opvis_agent/agent_service/
ps aux|grep agent_udp.py|grep -v grep|awk '{print $2}'|xargs kill -9
python /home/opvis/opvis_agent/agent_service/agent_udp.py