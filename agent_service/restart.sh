#!/bin/bash
ps aux|grep agent.py|grep -v grep|awk '{print $2}'|xargs kill -9
python agent.py