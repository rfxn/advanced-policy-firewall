#!/bin/bash
#
# APF 9.7 [apf@r-fx.org]
###
# Copyright (C) 2002-2011, R-fx Networks <proj@r-fx.org>
# Copyright (C) 2011, Ryan MacDonald <ryan@r-fx.org>
#
#    This program is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation; either version 2 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program; if not, write to the Free Software
#    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
###
#
INSTALL_PATH="/etc/apf"
BINPATH="/usr/local/sbin/apf"
COMPAT_BINPATH="/usr/local/sbin/fwmgr"

install() {
        mkdir $INSTALL_PATH
        cp -fR files/* $INSTALL_PATH
        chmod -R 640 $INSTALL_PATH/*
        chmod 750 $INSTALL_PATH/apf
        chmod 750 $INSTALL_PATH/firewall
        chmod 750 $INSTALL_PATH/vnet/vnetgen
	chmod 750 $INSTALL_PATH/extras/get_ports
	chmod 750 $INSTALL_PATH/extras/dshield/install
	chmod 750 $INSTALL_PATH
	cp -pf .ca.def importconf $INSTALL_PATH/extras/
	cp README CHANGELOG COPYING.GPL $INSTALL_PATH/doc
        ln -fs $INSTALL_PATH/apf $BINPATH
        ln -fs $INSTALL_PATH/apf $COMPAT_BINPATH
	rm -f /etc/cron.d/fwdev
	rm -f /etc/apf/cron.fwdev
        if [ -f "/etc/cron.hourly/fw" ]; then
		rm -f /etc/cron.hourly/fw
        fi
	if [ -f "/etc/cron.daily/fw" ]; then
		rm -f /etc/cron.daily/fw
	fi
        if [ -f "/etc/cron.daily/apf" ]; then
                rm -f /etc/cron.daily/apf
                cp cron.daily /etc/cron.daily/apf
                chmod 755 /etc/cron.daily/apf
        else
                cp cron.daily /etc/cron.daily/apf
                chmod 755 /etc/cron.daily/apf
        fi
	if [ -d "/etc/rc.d/init.d" ]; then
                cp -f apf.init /etc/rc.d/init.d/apf
	elif [ -d "/etc/init.d" ]; then
		cp -f apf.init /etc/init.d/apf
        else
		if [ -f "/etc/rc.local" ]; then
			val=`grep -i apf /etc/rc.local`
			if [ "$val" == "" ]; then
				echo "/etc/apf/apf -s >> /dev/null 2>&1" >> /etc/rc.local
			fi
		fi
        fi
	if [ -f "/var/log/apf_log" ] || [ -f "/var/log/apfados_log" ]; then
	rm -f /var/log/apf_log /var/log/apfados_log
	fi
	if [ -d "/etc/logrotate.d" ] && [ -f "logrotate.d.apf" ]; then
		cp logrotate.d.apf /etc/logrotate.d/apf
	fi
	if [ -f "/sbin/chkconfig" ]; then
	/sbin/chkconfig --add apf
	/sbin/chkconfig --level 345 apf on
	fi
	/etc/apf/vnet/vnetgen
	if [ -f "/usr/bin/dialog" ] && [ -d "/etc/apf/extras/apf-m" ]; then
		last=`pwd`
		cd /etc/apf/extras/apf-m/
		sh install -i
		cd $last
	fi
	chmod 750 $INSTALL_PATH
}

VER=`cat files/VERSION | grep version | awk '{print$2}'`
if [ -d "$INSTALL_PATH" ]; then
	DVAL=`date +"%d%m%Y-%s"`
	cp -R $INSTALL_PATH $INSTALL_PATH.bk$DVAL
	rm -f /etc/apf.bk.last
	ln -fs $INSTALL_PATH.bk$DVAL /etc/apf.bk.last 
	rm -rf $INSTALL_PATH
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
if [ -d "/etc/apf.bk.last" ]; then
	./importconf
	echo "  Note: Please review /etc/apf/conf.apf for consistency, install default backed up to /etc/apf/conf.apf.orig"
else
. $INSTALL_PATH/extras/get_ports
	echo "  Note: These ports are not auto-configured; they are simply presented for information purposes. You must manually configure all port options."
fi

rm -f .conf.apf
