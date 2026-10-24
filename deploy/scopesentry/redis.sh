#!/bin/sh
set -eu
umask 077
# A private runtime config avoids putting the password in process arguments.
password=$(cat /run/scopesentry-secrets/redis-password)
case "$password" in ''|*[!a-f0-9]*) echo 'Invalid Redis password file' >&2; exit 1;; esac
printf 'bind 0.0.0.0\nprotected-mode yes\nappendonly yes\nrequirepass %s\n' "$password" > /data/artex-redis.conf
exec /usr/local/bin/docker-entrypoint.sh redis-server /data/artex-redis.conf
