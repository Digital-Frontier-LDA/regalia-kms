#!/bin/busybox sh
if [ "$(/bin/busybox cat /marker)" = disposable-encrypted-root ]; then
  echo REGALIA_ENCRYPTED_ROOT_BOOTED
fi
/bin/busybox sync
/bin/busybox poweroff -f
