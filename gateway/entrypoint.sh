#!/bin/bash

set -e

host="config-server"
port="8888"
cmd="$@"

>&2 echo "!!!!!!!! Check config-server for available !!!!!!!!"

until curl http://"$host":"$port"; do
  >&2 echo "Config-server is unavailable - sleeping"
  sleep 1
done

>&2 echo "Config-server is up - executing command"

exec $cmd