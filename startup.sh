#!/bin/bash
SCRIPT_DIR="$(dirname "$0")"
_app_id_=deploy_agent
if [[ -z $(ps -ef| grep $_app_id_| grep -v grep) ]]; then
 	echo "$_app_id_ is not running,start directly"
else
	echo "$_app_id_ is running,kill the previous"
  ps -ef|grep $_app_id_ |grep -v grep|awk {'print $2'}|xargs kill -9;
fi
echo "start...$_app_id_"
nohup $SCRIPT_DIR/bin/deploy_agent $SCRIPT_DIR/config.yml  >> $SCRIPT_DIR/deploy_agent.log 2>&1 &