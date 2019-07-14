#!/bin/bash
cd /root
exec 1> >(logger -s -t $(basename $0)) 2>&1
wget -N -d --user-agent="Mozilla/5.0 (Windows NT x.y; rv:10.0) Gecko/20100101 Firefox/10.0" https://tomsdomain.co.uk/apf-systemd/apf-current-systemd.tar.gz
sleep 1
if tail -n 4 /var/log/messages | egrep "‘apf-current-systemd.tar.gz’ saved"; then
	echo "Updating"
	systemctl stop apf
	tar xvzf apf-current-systemd.tar.gz
	cp {/etc/apf/conf.apf,/etc/apf/allow_hosts.rules,/etc/apf/deny_hosts.rules,/etc/apf/glob_allow.rules,/etc/apf/glob_deny.rules} /root/
	rm -rf /etc/apf/
	mv /root/apf/files/ /etc/apf/
	mv -f {/root/conf.apf,/root/allow_hosts.rules,/root/deny_hosts.rules,/root/glob_allow.rules,/root/glob_deny.rules} /etc/apf
	chmod -R 640 /etc/apf/
	chmod 750 /etc/apf/apf
	chmod 750 /etc/apf/apf-start.sh
	chmod 750 /etc/apf/firewall
	chmod 750 /etc/apf/vnet/vnetgen
	chmod 750 /etc/apf/extras/get_ports
	chmod 750 /etc/apf/
	chmod 750 /etc/apf/auto-update.sh
		if [ -d "/lib/systemd/system" ]; then
			cp /root/apf/apf-restart.sh /etc/apf/
			chmod 755 /etc/apf/apf-restart.sh
		elif [ -d "/etc/rc.d/init.d" ]; then       
			chmod 755 /etc/cron.daily/apf
		elif [ -d "/etc/init.d" ]; then
        		chmod 755 /etc/cron.daily/apf
		fi
	systemctl start apf
	rm -rf /root/apf/
	exit
else
	echo No Updates
fi
exit
