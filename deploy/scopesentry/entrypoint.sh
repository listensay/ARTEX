#!/bin/sh
set -eu
# Official images accept passwords through environment variables. Read the
# mounted files here so Compose config and command arguments contain no keys.
MONGODB_PASSWORD=$(cat /run/scopesentry-secrets/mongo-password)
REDIS_PASSWORD=$(cat /run/scopesentry-secrets/redis-password)
export MONGODB_PASSWORD REDIS_PASSWORD
if [ "$1" = /opt/ScopeSentry/ScopeSentry ]; then
    ln -sf /opt/ScopeSentry/login/PASSWORD /opt/ScopeSentry/PASSWORD
fi
exec "$@"
