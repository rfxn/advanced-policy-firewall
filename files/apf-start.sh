#!/bin/bash
/usr/local/sbin/apf --start
sleep 1
if tail -n 4 /var/log/messages | egrep 'unable to load iptables module|timed out while attempting to gain lock|could not process allow_hosts|could not process deny_hosts|apf does not appear to have rules loaded|could not verify that interface|trust rules unchanged since last refresh|wget binary not found|route: No such file or directory'; then
        /usr/local/sbin/apf --stop
        echo "APF Aborted"
        exit 1
else
        echo "All ok"
fi
exit 0
