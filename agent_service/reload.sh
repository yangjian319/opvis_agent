ps -ef | grep -v grep | grep agent_udp.py| awk '{print $2}'|xargs kill -9
/usr/bin/nohup /usr/bin/python -u /home/opvis/opvis_agent/agent_service/agent_udp.py >> /home/opvis/opvis_agent/agent_service/log/agent.log 2>&1 &