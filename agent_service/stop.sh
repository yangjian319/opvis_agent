#!/bin/bash
ps -ef | grep -v grep | grep agent_udp.py| awk '{print $2}'|xargs kill -9