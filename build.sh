#!/bin/bash
# ================================================================== #
# Ubuntu 10.04 web server build shell script
# ================================================================== #
# Parts copyright (c) 2012 Matt Thomas http://betweenbrain.com
# This script is licensed under GNU GPL version 2.0 or above
# ================================================================== #
#
#
#
# ================================================================== #
#          Define system specific details in this section            #
# ================================================================== #
#
HOSTNAME=
SYSTEMIP=
DOMAIN=
LANGUAGE=
CHARSET=
SSHPORT=
IGNOREIP=
USER=
ADMINEMAIL=
PUBLICKEY="ssh-rsa ... foo@bar.com"
# ================================================================== #
#                      End system specific details                   #
# ================================================================== #
#
echo
echo "System updates and basic setup"
echo "==============================================================="
echo
echo
echo
echo "First things first, let's make sure we have the latest updates."
echo "---------------------------------------------------------------"
#
aptitude update && aptitude -y safe-upgrade
#
echo
echo "Setting the hostname."
# http://library.linode.com/getting-started
echo "---------------------------------------------------------------"
echo
echo
#
echo "$HOSTNAME" > /etc/hostname
hostname -F /etc/hostname
#
echo
echo
echo
echo "Updating /etc/hosts."
echo "---------------------------------------------------------------"
#
mv /etc/hosts /etc/hosts.bak
#
echo "
127.0.0.1       localhost
$SYSTEMIP       $HOSTNAME.$DOMAIN     $HOSTNAME
::1     ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
ff02::3 ip6-allhosts
" >> /etc/hosts
#
echo
echo
echo
echo "Setting the proper timezone."
echo "---------------------------------------------------------------"
#
dpkg-reconfigure tzdata
#
echo
echo
echo
echo "Synchronize the system clock with an NTP server"
echo "---------------------------------------------------------------"
#
aptitude install -y ntp
#
echo
echo
echo
echo "Setting the language and charset"
echo "---------------------------------------------------------------"
#
locale-gen $LANGUAGE.$CHARSET
/usr/sbin/update-locale LANG=$LANGUAGE.$CHARSET
#
# ================================================================== #
#                             SSH Security                           #
#      https://help.ubuntu.com/community/SSH/OpenSSH/Configuring     #
# ================================================================== #
#
echo
echo
echo
echo "Change SSH port"
echo "---------------------------------------------------------------"
#
sed -i "s/Port 22/Port $SSHPORT/g" /etc/ssh/sshd_config
#
echo
echo
echo
echo "Instruct sshd to listen only on a specific IP address."
echo "---------------------------------------------------------------"
echo
#
sed -i "s/#ListenAddress 0.0.0.0/ListenAddress $SYSTEMIP/g" /etc/ssh/sshd_config
#
echo
echo
echo
echo "Ensure that sshd starts after eth0 is up, not just after filesystem"
# http://blog.roberthallam.org/2010/06/sshd-not-running-at-startup/
echo "---------------------------------------------------------------"
#
sed -i "s/start on filesystem/start on filesystem and net-device-up IFACE=eth0/g" /etc/init/ssh.conf
#
echo
echo
echo
echo
echo "Disabling root ssh login"
echo "---------------------------------------------------------------"
#
sed -i "s/PermitRootLogin yes/PermitRootLogin no/g" /etc/ssh/sshd_config
#
echo
echo
echo
echo "Disabling password authentication"
echo "---------------------------------------------------------------"
#
sed -i "s/#PasswordAuthentication yes/PasswordAuthentication no/g" /etc/ssh/sshd_config
#
echo
echo
echo
echo "Disabling X11 forwarding"
echo "---------------------------------------------------------------"
#
sed -i "s/X11Forwarding yes/X11Forwarding no/g" /etc/ssh/sshd_config
#
echo
echo
echo
echo "Disabling sshd DNS resolution"
echo "---------------------------------------------------------------"
#
echo "UseDNS no" >> /etc/ssh/sshd_config
#
echo
echo
echo
echo "Creating new primary user"
echo "---------------------------------------------------------------"
# -------------------------------------------------------------------------
# Script to add a user to Linux system
# -------------------------------------------------------------------------
# Copyright (c) 2007 nixCraft project <http://bash.cyberciti.biz/>
# This script is licensed under GNU GPL version 2.0 or above
# Comment/suggestion: <vivek at nixCraft DOT com>
# -------------------------------------------------------------------------
# See url for more info:
# http://www.cyberciti.biz/tips/howto-write-shell-script-to-add-user.html
# -------------------------------------------------------------------------
if [ $(id -u) -eq 0 ]; then
	# read -p "Enter username of who can connect via SSH: " USER
	read -s -p "Enter password of user who can connect via SSH: " PASSWORD
	egrep "^$USER" /etc/passwd >/dev/null
	if [ $? -eq 0 ]; then
		echo "$USER exists!"
		exit 1
	else
		pass=$(perl -e 'print crypt($ARGV[0], "password")' $PASSWORD)
		useradd -s /bin/bash -m -d /home/$USER -U -p $pass $USER
		[ $? -eq 0 ] && echo "$USER has been added to system!" || echo "Failed to add a $USER!"
	fi
else
	echo "Only root may add a user to the system"
	exit 2
fi
# -------------------------------------------------------------------------
# End script to add a user to Linux system
# -------------------------------------------------------------------------
#
echo
echo
echo
echo "Adding $USER to SSH AllowUsers"
echo "---------------------------------------------------------------"
#
echo "AllowUsers $USER" >> /etc/ssh/sshd_config
#
echo
echo
echo
echo "Adding $USER to sudoers"
echo "---------------------------------------------------------------"
#
cp /etc/sudoers /etc/sudoers.tmp
chmod 0640 /etc/sudoers.tmp
echo "$USER    ALL=(ALL) ALL" >> /etc/sudoers.tmp
chmod 0440 /etc/sudoers.tmp
mv /etc/sudoers.tmp /etc/sudoers
#
echo
echo
echo
echo "Adding ssh key"
echo "---------------------------------------------------------------"
#
mkdir /home/$USER/.ssh
touch /home/$USER/.ssh/authorized_keys
echo $PUBLICKEY >> /home/$USER/.ssh/authorized_keys
chown -R $USER:$USER /home/$USER/.ssh
chmod 700 /home/$USER/.ssh
chmod 600 /home/$USER/.ssh/authorized_keys
#
sed -i "s/#AuthorizedKeysFile/AuthorizedKeysFile/g" /etc/ssh/sshd_config
#
/etc/init.d/ssh restart
#
# ================================================================== #
#                               IPtables                             #
# ================================================================== #
#
echo "Installing IPTables firewall"
echo "---------------------------------------------------------------"
#
aptitude install -y iptables
#
echo
echo
echo
echo "Setting up basic(!) rules for IPTables. Modify as needed, with care :)"
# http://www.thegeekstuff.com/scripts/iptables-rules
# http://wiki.centos.org/HowTos/Network/IPTables
# https://help.ubuntu.com/community/IptablesHowTo
echo "---------------------------------------------------------------"
#
# Flush old rules
iptables -F

# Allow SSH connections on tcp port $SSHPORT
# This is essential when working on remote servers via SSH to prevent locking yourself out of the system
#
iptables -A INPUT -p tcp --dport $SSHPORT -j ACCEPT

# Set default chain policies
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Accept packets belonging to established and related connections
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow loopback access
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Allow incoming HTTP
iptables -A INPUT -i eth0 -p tcp --dport 80 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -o eth0 -p tcp --sport 80 -m state --state ESTABLISHED -j ACCEPT

# Allow outgoing HTTPS
iptables -A OUTPUT -o eth0 -p tcp --dport 80 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT -i eth0 -p tcp --sport 80 -m state --state ESTABLISHED -j ACCEPT

# Allow incoming HTTPS
iptables -A INPUT -i eth0 -p tcp --dport 443 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -o eth0 -p tcp --sport 443 -m state --state ESTABLISHED -j ACCEPT

# Allow outgoing HTTPS
iptables -A OUTPUT -o eth0 -p tcp --dport 443 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT -i eth0 -p tcp --sport 443 -m state --state ESTABLISHED -j ACCEPT

# Ping from inside to outside
iptables -A OUTPUT -p icmp --icmp-type echo-request -j ACCEPT
iptables -A INPUT -p icmp --icmp-type echo-reply -j ACCEPT

# Ping from outside to inside
iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT
iptables -A OUTPUT -p icmp --icmp-type echo-reply -j ACCEPT

# Allow packets from internal network to reach external network.
# if eth1 is external, eth0 is internal
iptables -A FORWARD -i eth0 -o eth1 -j ACCEPT

# Allow Sendmail or Postfix
iptables -A INPUT -i eth0 -p tcp --dport 25 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -o eth0 -p tcp --sport 25 -m state --state ESTABLISHED -j ACCEPT

# Help prevent DoS attack
iptables -A INPUT -p tcp --dport 80 -m limit --limit 25/minute --limit-burst 100 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -m limit --limit 25/minute --limit-burst 100 -j ACCEPT

# Log dropped packets
iptables -N LOGGING
iptables -A INPUT -j LOGGING
iptables -I INPUT 5 -m limit --limit 5/min -j LOG --log-prefix "Iptables denied: " --log-level 7
iptables -A LOGGING -j DROP

# Create the script to load the rules
echo "#!/bin/sh
iptables-restore < /etc/iptables.rules
" > /etc/network/if-pre-up.d/iptablesload

# Create the script to save current rules
echo "#!/bin/sh
iptables-save > /etc/iptables.rules
if [ -f /etc/iptables.downrules ]; then
   iptables-restore < /etc/iptables.downrules
fi
" > /etc/network/if-post-down.d/iptablessave

# Ensure they are executible
chmod +x /etc/network/if-post-down.d/iptablessave
chmod +x /etc/network/if-pre-up.d/iptablesload
#
/etc/init.d/networking restart
#
echo
echo
echo
echo "Establish IPTables logging, and rotation of logs"
# http://ubuntuforums.org/showthread.php?t=668148
# https://wiki.ubuntu.com/LucidLynx/ReleaseNotes#line-178
echo "---------------------------------------------------------------"
#
echo "#IPTables logging
kern.debug;kern.info /var/log/firewall.log
" > /etc/rsyslog.d/firewall.conf
#
/etc/init.d/rsyslog restart
#
mkdir /var/log/old/
#
echo "/var/log/firewall.log {
    weekly
    missingok
    rotate 13
    compress
    delaycompress
    notifempty
    create 640 syslog adm
    olddir /var/log/old/
}
" > /etc/logrotate.d/firewall
#
echo
echo
echo
echo "Adding a bit of color and formatting to the command prompt"
# http://ubuntuforums.org/showthread.php?t=810590
echo "---------------------------------------------------------------"
#
echo '
export PS1="${debian_chroot:+($debian_chroot)}\[\033[01;32m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ "
' >> /home/$USER/.bashrc
source /home/$USER/.bashrc
#
echo
echo
echo
echo "Installing debconf utilities"
echo "---------------------------------------------------------------"
#
aptitude install -y debconf-utils
#
echo
echo
echo
echo "Install and configure postfix as email gateway (send only)"
# http://library.linode.com/email/postfix/gateway-ubuntu-10.04-lucid
echo "---------------------------------------------------------------"
#
echo "postfix postfix/main_mailer_type select Internet Site" | debconf-set-selections
echo "postfix postfix/mailname string $HOSTNAME.$DOMAIN" | debconf-set-selections
echo "postfix postfix/destinations string localhost.localdomain, localhost" | debconf-set-selections
#
aptitude -y install postfix mailutils
#
ln -s /usr/bin/mail /bin/mail
#
sed -i "s/myhostname =/#myhostname =/g" /etc/postfix/main.cf
echo "myhostname = $HOSTNAME" >> /etc/postfix/main.cf
sed -i "s/#myorigin = \/etc\/mailname/myorigin = $DOMAIN/g" /etc/postfix/main.cf
#
echo
echo
echo
echo "Configure postfix to send email addressed to $USER@$HOSTNAME.$DOMAIN to $ADMINEMAIL."
# http://www.postfix.org/STANDARD_CONFIGURATION_README.html#some_local
echo "---------------------------------------------------------------"
#
echo "$USER@$HOSTNAME.$DOMAIN $ADMINEMAIL" > /etc/postfix/virtual
postmap /etc/postfix/virtual
#
/etc/init.d/postfix restart
# 
#  Setting /home directory folders
#
echo "Creating directories for $DOMAIN in $USER's home directory"
echo "--------------------------------------------------------------"
#
mkdir -p /home/$USER/$DOMAIN/{private,backup,logs,public}
echo "<?php echo '<h1>$DOMAIN works!</h1>'; ?>" > /home/$USER/$DOMAIN/index.php
#
echo
echo
echo
echo "Setting correct ownership and permissions for $DOMAIN"
echo "--------------------------------------------------------------"
#
chown -R $USER:$USER /home/$USER
find /home/$USER/$DOMAIN/ -type d -exec chmod 755 {} \;
find /home/$USER/$DOMAIN/ -type f -exec chmod 644 {} \;
#
echo
echo
echo
echo "Creating VirtualHost for $DOMAIN"
# http://www.howtoforge.com/how-to-set-up-apache2-with-mod_fcgid-and-php5-on-ubuntu-8.10
echo "--------------------------------------------------------------"
#
echo "upstream $USER {
        server unix:/tmp/php.socket;
}

server {
        ## Your website name goes here.
        server_name $DOMAIN www.$DOMAIN;
        rewrite ^/(.*) http://$DOMAIN/$1 permanent;

        ## Logs
        access_log /home/$USER/$DOMAIN/logs/access.log;
        error_log /home/$USER/$DOMAIN/logs/error.log;

        ## Your only path reference.
        root   /home/$USER/$DOMAIN/public;

        error_page 404 index.php;

        ## This should be in your http block and if it is, it's not needed here.
        index index.php;

        location = /favicon.ico {
                log_not_found off;
                access_log off;
        }

        location = /robots.txt {
                allow all;
                log_not_found off;
                access_log off;
        }

        location ~* \.(js|css|png|jpg|jpeg|gif|ico)$ {
                expires max;
                log_not_found off;
        }

        location ~* \.(eot|ttf|woff)$ {
                add_header Access-Control-Allow-Origin *;
        }

        location ~ /\.ht {
                 deny all;
         }

         location ~* (\.(tpl|ini))$ {
                 deny all;
         }

        location / {
                location ~* \.(php|inc)$ {
                fastcgi_split_path_info ^(.+\.php)(/.+)$;
                fastcgi_intercept_errors on;
                include fastcgi_params;
                fastcgi_pass $USER;
                fastcgi_param  SCRIPT_FILENAME  $document_root$fastcgi_script_name;
                fastcgi_param REDIRECT_STATUS 200;

                proxy_set_header X-Real-IP $remote_addr;
                proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
                proxy_set_header Host $http_host;
                proxy_redirect off;
                }
        }


}" > /etc/nginx/sites-available/$DOMAIN
#
echo
echo
echo
echo "Creating fcgi wrapper for $DOMAIN, making it executable and setting owner"
echo "--------------------------------------------------------------"
#
mkdir /var/www/php-fcgi-scripts/
mkdir /var/www/php-fcgi-scripts/$DOMAIN/
#
echo "#!/bin/sh
PHPRC=/etc/php5/cgi/
export PHPRC
export PHP_FCGI_MAX_REQUESTS=5000
export PHP_FCGI_CHILDREN=1
exec /usr/lib/cgi-bin/php
" > /var/www/php-fcgi-scripts/$DOMAIN/php-fcgi-starter
#
chmod 755 /var/www/php-fcgi-scripts/$DOMAIN/php-fcgi-starter
#
chown -R $USER:$USER /var/www/php-fcgi-scripts/$DOMAIN
#
echo
echo
echo
echo 
echo
echo
echo
echo
echo
echo
echo
echo
echo 
echo
echo
echo
echo 
echo
echo
echo
echo 
echo
echo
echo
echo "Install MySQL and MySQL modules"
# https://help.ubuntu.com/community/ApacheMySQLPHP
echo "--------------------------------------------------------------"
#
aptitude -y install mysql-server && mysql_secure_installation
#
#
echo
echo
echo
echo "Install fcgid, PHP, and PHP modules"
# https://help.ubuntu.com/community/ApacheMySQLPHP
echo "--------------------------------------------------------------"
#
aptitude -y install php5-cgi php5-cli php5-mysql php5-curl php5-gd php5-mcrypt php5-memcache php5-mhash php5-suhosin php5-xmlrpc php5-xsl
#
#
/etc/init.d/nginx restart
#
echo
echo
echo
echo "Fixing PHP Deprecated notice in /etc/php5/cli/conf.d/mcrypt.ini"
# http://www.asim.pk/2010/06/21/php-depreciated-errors-on-ubuntu-10-04-lts/
echo "--------------------------------------------------------------"
#
sed -i "s/# configuration for php MCrypt module/; configuration for php MCrypt module/g" /etc/php5/cli/conf.d/mcrypt.ini
#
echo
echo
echo
echo
echo
echo
echo
echo 
echo
echo
echo
echo "Tweaking PHP settings"
# http://docs.joomla.org/Security_Checklist_2_-_Hosting_and_Server_Setup#Use_PHP_disable_functions
echo "--------------------------------------------------------------"
#
sed -i "s/memory_limit = 128M/memory_limit = 48M/g" /etc/php5/cgi/php.ini
sed -i "s/upload_max_filesize = 2M/upload_max_filesize = 20M/g" /etc/php5/cgi/php.ini
sed -i "s/output_buffering = 4096/output_buffering = Off/g" /etc/php5/cgi/php.ini
# sed -i "s/allow_url_fopen = On/allow_url_fopen = Off/g" /etc/php5/cgi/php.ini
sed -i "s/expose_php = On/expose_php = Off/g" /etc/php5/cgi/php.ini
sed -i "s/disable_functions =/disable_functions = show_source, system, shell_exec, passthru, exec, phpinfo, popen, proc_open/g" /etc/php5/cgi/php.ini
#
# ================================================================== #
#                           Server Security                          #
# ================================================================== #
#
echo
echo
echo
echo "Linux kernel hardening"
# http://www.cyberciti.biz/faq/linux-kernel-etcsysctl-conf-security-hardening/
echo "--------------------------------------------------------------"
#
cp /etc/sysctl.conf /etc/sysctl.conf.bak
#
sed -i "s/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=0/g" /etc/sysctl.conf
sed -i "s/#net.ipv6.conf.all.forwarding=1/net.ipv6.conf.all.forwarding=0/g" /etc/sysctl.conf
sed -i "s/#net.ipv4.icmp_echo_ignore_broadcasts = 1/net.ipv4.icmp_echo_ignore_broadcasts = 1/g" /etc/sysctl.conf
sed -i "s/#net.ipv4.icmp_ignore_bogus_error_responses = 1/net.ipv4.icmp_ignore_bogus_error_responses = 1/g" /etc/sysctl.conf
sed -i "s/#net.ipv4.conf.all.accept_redirects = 0/net.ipv4.conf.all.accept_redirects = 0/g" /etc/sysctl.conf
sed -i "s/#net.ipv6.conf.all.accept_redirects = 0/net.ipv6.conf.all.accept_redirects = 0/g" /etc/sysctl.conf
sed -i "s/#net.ipv4.conf.all.send_redirects = 0/net.ipv4.conf.all.send_redirects = 0/g" /etc/sysctl.conf
sed -i "s/#net.ipv4.conf.all.accept_source_route = 0/net.ipv4.conf.all.accept_source_route = 0/g" /etc/sysctl.conf
sed -i "s/#net.ipv6.conf.all.accept_source_route = 0/net.ipv6.conf.all.accept_source_route = 0/g" /etc/sysctl.conf
sed -i "s/#net.ipv4.conf.all.log_martians = 1/net.ipv4.conf.all.log_martians = 1/g" /etc/sysctl.conf
#
echo "#
# Controls the use of TCP syncookies
net.ipv4.tcp_synack_retries = 2
" >> /etc/sysctl.conf
#
sysctl -p
#
echo
echo
echo
echo "Installing and configuring logwatch for log monitoring"
# https://help.ubuntu.com/community/Logwatch
echo "--------------------------------------------------------------"
#
aptitude -y install logwatch
mkdir /var/cache/logwatch
cp /usr/share/logwatch/default.conf/logwatch.conf /etc/logwatch/conf/
#
sed -i "s/MailTo = root/MailTo = $ADMINEMAIL/g" /etc/logwatch/conf/logwatch.conf
sed -i "s/Detail = Low/Detail = High/g" /etc/logwatch/conf/logwatch.conf
sed -i "s/Format = text/Format = html/g" /etc/logwatch/conf/logwatch.conf
#
cp /usr/share/logwatch/default.conf/logfiles/http.conf to /etc/logwatch/conf/logfiles
#
echo "
# Log files for $DOMAIN
LogFile = /home/$USER/$DOMAIN/logs/access.log
LogFile = /home/$USER/$DOMAIN/logs/error.log
LogFile = /home/$USER/$DOMAIN/logs/ssl_error.log
LogFile = /home/$USER/$DOMAIN/logs/ssl_access.log
" >> /etc/logwatch/conf/logfiles/http.conf
#
echo
echo
echo
echo 
echo
echo
echo "Installing Fail2ban"
# http://library.linode.com/security/fail2ban
echo "---------------------------------------------------------------"
#
aptitude -y install fail2ban
#
cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
#
sed -i "s/ignoreip = 127.0.0.1/ignoreip = 127.0.0.1 $IGNOREIP/g" /etc/fail2ban/jail.local
sed -i "s/destemail = root@localhost/destemail = $ADMINEMAIL/g" /etc/fail2ban/jail.local
sed -i "s/action = %(action_)s/action = %(action_mw)s/g" /etc/fail2ban/jail.local
#
echo
echo
echo
echo "Adding nginx monitoring to fail2ban"
# based on http://www.fail2ban.org/wiki/index.php/HOWTO_fail2ban_with_ModSecurity2.5
echo "---------------------------------------------------------------"
#
echo "[nginx]

enabled  = true
port    = http,https
filter   = apache-auth
logpath  = /var/log/nginx*/*error.log
bantime  = 600
maxretry = 3

[nginx-$DOMAIN]

enabled  = true
port    = http,https
filter   = apache-auth
logpath  = /home/$USER/$DOMAIN/logs/*error.log
bantime  = 600
maxretry = 3
" >> /etc/fail2ban/jail.local
#
echo "# Fail2Ban configuration file
#
# Author: Matt Thomas

[Definition]
# Match entries like [Mon Feb 13 10:47:12 2012] [error] [client 192.168.0.66] ModSecurity: Access denied
failregex = [[]client\s<HOST>[]]\sModSecurity\:\sAccess\sdenied*
ignoreregex =
" > /etc/fail2ban/filter.d/modsecurity.conf
#
echo
echo
echo
echo 
echo
echo
echo
echo 
echo
echo
echo
echo 
echo
echo
echo
echo 
echo
echo
echo
echo 
echo
echo
echo
echo "One final hurrah"
echo "--------------------------------------------------------------"
echo
#
aptitude update && aptitude -y safe-upgrade
#
echo
echo
echo
echo
echo
echo
echo
echo
echo
echo
echo
echo
echo
echo
echo
echo
echo
echo
echo
echo
echo "==============================================================="
echo
echo "All done!"
echo
echo "If you are confident that all went well, reboot this puppy and play."
echo
echo "If not, now is your (last?) chance to fix things."
echo
echo "==============================================================="

