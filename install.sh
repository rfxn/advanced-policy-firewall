#!/bin/bash
#
##
# Advanced Policy Firewall (APF) v2.0.1
#             (C) 2002-2026, R-fx Networks <proj@rfxn.com>
#             (C) 2026, Ryan MacDonald <ryan@rfxn.com>
# This program may be freely redistributed under the terms of the GNU GPL v2
##
#
INSTALL_PATH=${INSTALL_PATH:-"/etc/apf"}
BINPATH=${BINPATH:-"/usr/local/sbin/apf"}
COMPAT_BINPATH=${COMPAT_BINPATH:-"/usr/local/sbin/fwmgr"}

install() {
        mkdir -p "$INSTALL_PATH"
        cp -fR files/* "$INSTALL_PATH"
        if [ "$INSTALL_PATH" != "/etc/apf" ]; then
                find "$INSTALL_PATH" -type f -exec sed -i "s:/etc/apf:$INSTALL_PATH:g" {} \;
        fi
        chmod -R 640 "$INSTALL_PATH"/*
        chmod 750 "$INSTALL_PATH/apf"
        chmod 750 "$INSTALL_PATH/firewall"
        chmod 750 "$INSTALL_PATH/vnet/vnetgen"
	chmod 750 "$INSTALL_PATH/extras/get_ports"
	chmod 750 "$INSTALL_PATH"
	cp -pf .ca.def importconf "$INSTALL_PATH/extras/"
	mkdir -p "$INSTALL_PATH/doc"
	cp README CHANGELOG COPYING.GPL "$INSTALL_PATH/doc"
        ln -fs "$INSTALL_PATH/apf" "$BINPATH"
        ln -fs "$INSTALL_PATH/apf" "$COMPAT_BINPATH"
	rm -f /etc/cron.hourly/fw /etc/cron.daily/fw /etc/cron.d/fwdev "$INSTALL_PATH/cron.fwdev"
        rm -f /etc/cron.daily/apf
        cp cron.daily /etc/cron.daily/apf
        chmod 755 /etc/cron.daily/apf
	if [ "$INSTALL_PATH" != "/etc/apf" ]; then
		sed -i "s:/etc/apf:$INSTALL_PATH:g" /etc/cron.daily/apf
	fi
	# Service installation: prefer systemd, then SysV init, then rc.local
	if [ -d "/run/systemd/system" ]; then
		cp -f apf.service /etc/systemd/system/apf.service
		if [ "$INSTALL_PATH" != "/etc/apf" ]; then
			sed -i "s:/etc/apf:$INSTALL_PATH:g" /etc/systemd/system/apf.service
		fi
		systemctl daemon-reload
		systemctl enable apf.service >> /dev/null 2>&1
	elif [ -d "/etc/rc.d/init.d" ]; then
		cp -f apf.init /etc/rc.d/init.d/apf
		if [ "$INSTALL_PATH" != "/etc/apf" ]; then
			sed -i "s:/etc/apf:$INSTALL_PATH:g" /etc/rc.d/init.d/apf
		fi
		if [ -f "/sbin/chkconfig" ]; then
			/sbin/chkconfig --add apf
			/sbin/chkconfig --level 345 apf on
		fi
	elif [ -d "/etc/init.d" ]; then
		cp -f apf.init /etc/init.d/apf
		if [ "$INSTALL_PATH" != "/etc/apf" ]; then
			sed -i "s:/etc/apf:$INSTALL_PATH:g" /etc/init.d/apf
		fi
	else
		if [ -f "/etc/rc.local" ]; then
			val=$(grep -i apf /etc/rc.local)
			if [ -z "$val" ]; then
				echo "$INSTALL_PATH/apf -s >> /dev/null 2>&1" >> /etc/rc.local
			fi
		fi
	fi
	if [ -d "/etc/cron.d" ] && [ -f "cron.d.apf_ipset" ]; then
		cp cron.d.apf_ipset /etc/cron.d/apf_ipset
		chmod 644 /etc/cron.d/apf_ipset
		if [ "$INSTALL_PATH" != "/etc/apf" ]; then
			sed -i "s:/etc/apf:$INSTALL_PATH:g" /etc/cron.d/apf_ipset
		fi
	fi
	if [ -f "/var/log/apf_log" ]; then
		mv -f /var/log/apf_log /var/log/apf_log.prev
	fi
	rm -f /var/log/apfados_log
	if [ -d "/etc/logrotate.d" ] && [ -f "logrotate.d.apf" ]; then
		cp logrotate.d.apf /etc/logrotate.d/apf
	fi
	"$INSTALL_PATH/vnet/vnetgen"
	if [ -f "/usr/bin/dialog" ] && [ -d "$INSTALL_PATH/extras/apf-m" ]; then
		last=$(pwd)
		cd "$INSTALL_PATH/extras/apf-m/"
		sh install -i
		cd "$last"
	fi
	chmod 750 "$INSTALL_PATH"
}

VER=$(awk '/version/ {print$2}' files/VERSION)
if [ -d "$INSTALL_PATH" ]; then
	DVAL=$(date +"%d%m%Y-%s")
	cp -R "$INSTALL_PATH" "$INSTALL_PATH.bk$DVAL" || { echo "Backup failed, aborting."; exit 1; }
	rm -f "$INSTALL_PATH.bk.last"
	ln -fs "$INSTALL_PATH.bk$DVAL" "${INSTALL_PATH}.bk.last"
	rm -rf "$INSTALL_PATH"
	echo -n "Installing APF $VER: "
	install
else
        echo -n "Installing APF $VER: "
	install
fi

sleep 1
echo "Completed."
echo ""
echo "Installation Details:"
echo "  Install path:         $INSTALL_PATH/"
echo "  Config path:          $INSTALL_PATH/conf.apf"
echo "  Executable path:      $BINPATH"
echo ""
echo "Other Details:"
if [ -d "$INSTALL_PATH.bk.last" ]; then
	./importconf
	echo "  Note: Please review $INSTALL_PATH/conf.apf for consistency, install default backed up to $INSTALL_PATH/conf.apf.orig"
else
. "$INSTALL_PATH/extras/get_ports"
	echo "  Note: These ports are not auto-configured; they are simply presented for information purposes. You must manually configure all port options."
fi

rm -f .conf.apf
