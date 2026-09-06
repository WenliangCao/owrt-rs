#!/bin/sh
# Runs as /etc/rc.local at the end of boot, with procd as PID 1.
{
echo "=====R43 BEGIN"
echo "pid1_exe: $(readlink /proc/1/exe)"
echo "pid1_comm: $(cat /proc/1/comm)"
bp=$(pgrep -f '^/sbin/ubusd' | head -1)
echo "bus_binary: $(readlink /proc/$bp/exe 2>/dev/null)"
# The path is the same either way, so identify the binary that is actually
# running: only the candidate is statically linked and carries this string.
echo "bus_is_candidate: $(grep -qa 'ubusd-rs' /proc/$bp/exe 2>/dev/null && echo yes || echo no)"
echo "bus_size: $(wc -c < /proc/$bp/exe 2>/dev/null)"
echo "original_kept: $([ -f /sbin/ubusd.orig ] && echo yes || echo no)"
echo "objects: [$(ubus list | sort | tr '\n' ' ')]"
echo "procd_service_list_rc: $(ubus -S call service list '{}' >/dev/null 2>&1; echo $?)"
echo "procd_system_board_rc: $(ubus -S call system board '{}' >/dev/null 2>&1; echo $?)"
echo "network_dump_rc: $(ubus -S call network.interface dump >/dev/null 2>&1; echo $?)"
echo "running_services: $(ubus -S call service list '{}' 2>/dev/null | grep -o '"[a-z_-]*":{"instances"' | wc -l)"
echo "socket_mode: $(ls -l /var/run/ubus/ubus.sock | awk '{print $1, $3, $4}')"
echo "bus_uid: $(awk '/^Uid:/{print $2}' /proc/$(pgrep -f 'ubusd' | head -1)/status 2>/dev/null)"
echo "--- procd itself is a bus client: does it survive a bus restart?"
before=$(ubus list | sort | tr '\n' ' ')
kill $(pgrep -f '^/sbin/ubusd' | head -1) 2>/dev/null
sleep 6
echo "bus_back: $([ -S /var/run/ubus/ubus.sock ] && echo yes || echo no)"
echo "procd_alive: $([ -d /proc/1 ] && cat /proc/1/comm)"
echo "procd_service_after_restart_rc: $(ubus -S call service list '{}' >/dev/null 2>&1; echo $?)"
echo "procd_system_after_restart_rc: $(ubus -S call system board '{}' >/dev/null 2>&1; echo $?)"
echo "objects_after_restart: [$(ubus list | sort | tr '\n' ' ')]"
echo "objects_recovered: $([ "$before" = "$(ubus list | sort | tr '\n' ' ')" ] && echo all || echo partial)"
echo "=====R43 END"
} > /dev/console 2>&1
sleep 2
poweroff -f
