#!/bin/bash
date=`date +%Y%m%d`
mv /home/opvis/opvis_agent/agent_service/agent.py /home/opvis/opvis_agent/agent_service/temp/agent.py.$date
cp /home/opvis/opvis_agent/agent_service/temp/agent.py /home/opvis/opvis_agent/agent_service/
ps aux|grep agent.py|grep -v grep|awk '{print $2}'|xargs kill -9
python /home/opvis/opvis_agent/agent_service/agent.py