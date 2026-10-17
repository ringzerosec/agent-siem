#!/usr/bin/env bash
# Feed the wall from the two real daemons (Lima VM "rgs" on :7700, VirtualBox "ubuntu1" on :7701).
export PATH="$HOME/.local/bin:$PATH"
T1=$(~/.local/lima-2.2.0/bin/limactl shell rgs -- cat /tmp/rz-ro.token | tr -d '\r\n')
T2=$(ssh -o BatchMode=yes -p 2222 vboxuser@localhost 'sudo cat /var/lib/ringzero/api-token-readonly' | tr -d '\r\n')
RZS="lima-rgs=http://localhost:7700,ubuntu1=http://localhost:7701" RZS_TOKEN_lima_rgs="$T1" RZS_TOKEN_ubuntu1="$T2" RZS_SINCE_HOURS=${RZS_SINCE_HOURS:-240} exec node src/adapter-rzs.js
