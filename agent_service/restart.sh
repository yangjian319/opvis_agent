#!/bin/bash
ps aux|grep agent_udp.py|grep -v grep|awk '{print $2}'|xargs kill -9
/usr/bin/nohup /usr/bin/python -u /home/opvis/opvis_agent/agent_service/agent_udp.py >> /home/opvis/utils/log/agent.log 2>&1 &