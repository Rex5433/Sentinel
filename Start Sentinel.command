#!/bin/sh
cd "$(dirname "$0")" || exit 1
if [ -x .venv/bin/python ]; then
  .venv/bin/python scripts/launch.py "$@"
else
  python3 scripts/launch.py "$@"
fi
sentinel_exit=$?
if [ "$sentinel_exit" -ne 0 ]; then
  printf '\nSentinel could not start. Review the error above. Press Enter to close.\n'
  read -r sentinel_reply
fi
exit "$sentinel_exit"
