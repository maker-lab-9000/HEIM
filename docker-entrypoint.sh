#!/bin/sh
# Start as root just long enough to make the data directory writable, then drop
# to the unprivileged `heim` user for the actual run.
#
# Why this exists: /data is a bind mount from the host. Docker creates a missing
# bind-mount source as root:root, and a mount always overrides the image's own
# ownership — so the uid-1000 `heim` user cannot create heim.sqlite3 there. On
# Docker Desktop (macOS/Windows) the file-sharing layer hides this; on Linux it
# is a hard failure. Fixing it here keeps `docker compose up` working on a fresh
# host with no manual mkdir/chown, and keeps the process itself non-root.
set -e

if [ "$(id -u)" = "0" ]; then
    mkdir -p /data
    # Only chown when it is actually needed: on a large existing /data a blanket
    # recursive chown is slow, and on an NFS/SMB mount it can fail outright —
    # neither should stop a container whose directory is already usable.
    if [ ! -O /data ] || [ ! -w /data ]; then
        chown heim:heim /data 2>/dev/null || true
        chown -R heim:heim /data 2>/dev/null || true
    fi
    if ! su heim -s /bin/sh -c 'test -w /data'; then
        echo "heim: /data is not writable by the heim user (uid 1000) and could not be fixed." >&2
        echo "      Give the host directory to uid 1000, e.g.: sudo chown -R 1000:1000 ./data" >&2
        exit 1
    fi
    exec setpriv --reuid=heim --regid=heim --init-groups heim "$@"
fi

exec heim "$@"
