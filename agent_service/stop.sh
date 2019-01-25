#!/bin/bash
ps -ef | grep -v grep | grep agent_udp| awk '{print $2}'|xargs kill -9