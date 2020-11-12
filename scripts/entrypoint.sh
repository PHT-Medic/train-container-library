#!/bin/bash
set -e

if [ "$1" = 'pre-run' ]; then
  python /opt/security/SecurityProtocoly.py pre-run

elif [ "$1" = 'post-run' ]; then
  python /opt/security/SecurityProtocoly.py post-run

else
  "$@"
fi
