# Requires MUNGED.

##
# Create smallest-allowable key [$1] for munged if it does not already exist.
# FIXME: Creating the munged key via dd is a lousy cmdline interface.
##
munged_create_key()
{
    local KEY=$1 &&
    if test ! -r "${KEY}"; then
        dd if="/dev/urandom" of="${KEY}" bs=32 count=1 >/dev/null 2>&1
    fi &&
    chmod 400 "${KEY}"
}

##
# Start munged and set env vars.
# The socket is placed in TMPDIR since NFS can cause problems for the lockfile.
#   Debian 3.1 returns an incorrect PID for the process holding the lock across
#   an NFS mount.  FreeBSD cannot create a lockfile across an NFS mount.
# The first argument (if specified) is used to exec the daemon
#   (e.g., for running under valgrind and passing in its options).
# Additional arguments will be appended to the munged command-line options.
##
munged_start_daemon()
{
    local EXEC MASK=$(umask) SOCKET KEYFILE PIDFILE &&
    if test $# -gt 0; then
        EXEC=$1
        shift
    fi &&
    SOCKET="${TMPDIR:-"/tmp"}/munged.sock.$$" &&
    KEYFILE="munged.key.$$" &&
    PIDFILE="munged.pid.$$" &&
    umask 022 &&
    munged_create_key "${KEYFILE}" &&
    ${EXEC} "${MUNGED}" \
        --socket="${SOCKET}" \
        --key-file="$(pwd)/${KEYFILE}" \
        --pid-file="$(pwd)/${PIDFILE}" \
        --syslog \
        --force \
        "$@" &&
    umask "${MASK}" &&
    MUNGE_PIDFILE="${PIDFILE}" &&
    MUNGE_SOCKET="${SOCKET}"
}

##
# Stop munged and clear env vars.
# FIXME: The "while kill -s" loop busy-waits until the daemon exits.
##
munged_stop_daemon()
{
    local PID &&
    if test -r "${MUNGE_PIDFILE}"; then
        PID=$(cat "${MUNGE_PIDFILE}") &&
        while kill -s TERM "${PID}" 2>/dev/null; do :; done
    fi &&
    unset MUNGE_SOCKET &&
    unset MUNGE_PIDFILE
}
