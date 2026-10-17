#!/usr/bin/env bash
# Feed the wall from the two real daemons: BLD-LNX-0001 = Lima VM "rgs" (:7700), LAB-LNX-0002 = VirtualBox "ubuntu1" (:7701).
export PATH="$HOME/.local/bin:$PATH"
T1=$(~/.local/lima-2.2.0/bin/limactl shell rgs -- cat /tmp/rz-ro.token | tr -d '\r\n')
A1=$(~/.local/lima-2.2.0/bin/limactl shell rgs -- sudo cat /var/lib/ringzero/api-token | tr -d '\r\n')
T2=$(ssh -o BatchMode=yes -p 2222 vboxuser@localhost 'sudo cat /var/lib/ringzero/api-token-readonly' | tr -d '\r\n')
RZS="BLD-LNX-0001=http://localhost:7700,LAB-LNX-0002=http://localhost:7701" RZS_TOKEN_BLD_LNX_0001="$T1" RZS_ADMIN_TOKEN_BLD_LNX_0001="$A1" RZS_TOKEN_LAB_LNX_0002="$T2" RZS_TEAM_BLD_LNX_0001="Build Infrastructure" RZS_TEAM_LAB_LNX_0002="Security Lab" RZS_SINCE_HOURS=${RZS_SINCE_HOURS:-240} exec node src/adapter-rzs.js
