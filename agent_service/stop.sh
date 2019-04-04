#!/bin/bash
ps -ef | grep -v grep | grep agent_udp| awk '{print $2}'|xargs kill -9
netstat -ntulp|grep 9997|grep -v grep|awk -F ' ' '{print $6}'|awk -F '/' '{print $1}'|xargs kill -9 >/dev/null 2>&1