#!/bin/sh

if [ "$1" = 'help' ]
then
  printf 'Available commands: \n- pre-run\n- post-run'
fi

if [ "$1" = 'pre-run' ]
then
  python /opt/security/security_protocol.py pre-run;
fi
if [ "$1" = 'post-run' ]
then
  python /opt/security/security_protocol.py post-run;
else
  exec "$@";
fi
