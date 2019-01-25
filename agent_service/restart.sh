#!/bin/bash
ps aux|grep agent_udp|grep -v grep|awk '{print $2}'|xargs kill -9
/usr/bin/nohup /home/opvis/opvis_agent/agent_service/agent_udp >> /home/opvis/utils/log/agent.log 2>&1 &