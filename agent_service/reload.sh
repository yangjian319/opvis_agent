ps -ef | grep -v grep | grep agent_udp| awk '{print $2}'|xargs kill -9
/usr/bin/nohup /home/opvis/opvis_agent/agent_service/agent_udp >> /home/opvis/utils/log/agent.log 2>&1 &