#!/bin/bash
_app_id_=deploy_agent
echo "shutdown...$_app_id_"
if [[ -z $(ps -ef| grep $_app_id_| grep -v grep) ]]; then
 	echo "$_app_id_ is not running,start directly"
else
	echo "$_app_id_ is running,killed"
  ps -ef|grep $_app_id_ |grep -v grep|awk {'print $2'}|xargs kill -9;
fi