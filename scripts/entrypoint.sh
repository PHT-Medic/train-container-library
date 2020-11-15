#!/bin/sh
if [ "$1" = 'pre-run' ]; then
  python /opt/security/security_protocol.py pre-run;
elif [ "$1" = 'post-run' ]; then
  python /opt/security/security_protocol.py post-run;
else
  echo "$@"
fi
