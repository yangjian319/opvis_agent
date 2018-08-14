#!/bin/bash
ps aux|grep agent_udp.py|grep -v grep|awk '{print $2}'|xargs kill -9
python agent_udp.py