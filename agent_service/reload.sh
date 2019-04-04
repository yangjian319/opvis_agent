ps -ef | grep -v grep | grep agent_udp| awk '{print $2}'|xargs kill -9 >/dev/null 2>&1
netstat -ntulp|grep 9997|grep -v grep|awk -F ' ' '{print $6}'|awk -F '/' '{print $1}'|xargs kill -9 >/dev/null 2>&1
/usr/bin/nohup /home/opvis/opvis_agent/agent_service/agent_udp >> /home/opvis/utils/log/agent.log 2>&1 &