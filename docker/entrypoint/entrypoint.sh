#!/bin/sh

if [ "$1" = 'help' ]
then
  printf 'Available commands: \n- pre-run\n- post-run'
fi

if [ "$1" = 'pre-run' ]
then
  shift
  python /opt/protocol/docker/entrypoint/run_protocol.py pre-run "$@";
elif [ "$1" = 'post-run' ]
then
  shift
  python /opt/protocol/docker/entrypoint/run_protocol.py post-run "$@";
else
  exec "$@";
fi
