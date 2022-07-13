#!/bin/bash
# Center for Internet Security (https://downloads.cisecurity.org/#/)
# Mozilla OpenSSH Modern Configuration (https://infosec.mozilla.org/guidelines/openssh)
apt update -y
echo "install cramfs /bin/true" > /etc/modprobe.d/cramfs.conf
echo "install freevxfs /bin/true" > /etc/modprobe.d/freevxfs.conf
echo "install jffs2 /bin/true" > /etc/modprobe.d/jffs2.conf
echo "install hfs /bin/true" > /etc/modprobe.d/hfs.conf
echo "install hfsplus /bin/true" > /etc/modprobe.d/hfsplus.conf
echo "install udf /bin/true" > /etc/modprobe.d/udf.conf
echo "tmpfs /tmp tmpfs defaults,rw,nosuid,nodev,noexec,relatime 0 0" >> /etc/fstab
echo "tmpfs /dev/shm tmpfs defaults,noexec,nodev,nosuid,seclabel 0 0" >> /etc/fstab
df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null | xargs -I '{}' chmod a+t '{}'
echo "install usb-storage /bin/true" > /etc/modprobe.d/usb_storage.conf
sed -ri 's/chmod\s+[0-7][0-7][0-7]\s+\$\{grub_cfg\}\.new/chmod 400 ${grub_cfg}.new/' /usr/sbin/grub-mkconfig
sed -ri 's/ && ! grep "\^password" \$\{grub_cfg\}.new >\/dev\/null//' /usr/sbin/grub-mkconfig
chown root:root /boot/grub/grub.cfg
chmod u-wx,go-rwx /boot/grub/grub.cfg
echo "* hard core 0" >> /etc/security/limits.conf
echo "* soft core 0" >> /etc/security/limits.conf
echo "fs.suid_dumpable = 0" >> /etc/sysctl.conf
sysctl -w fs.suid_dumpable=0
apt install apparmor-utils auditd audispd-plugins -y
sed -i 's/GRUB_TIMEOUT=5/GRUB_TIMEOUT=0/g' /etc/default/grub
sed -i 's/^GRUB_CMDLINE_LINUX="/&apparmor=1 security=apparmor ipv6.disable=1 audit=1 audit_backlog_limit=8192 /' /etc/default/grub
update-grub
apt upgrade -y
snap refresh
apt purge needrestart rsync telnet -y
apt autoremove -y
aa-enforce /etc/apparmor.d/*
sysctl -w net.ipv6.conf.all.disable_ipv6=1
sysctl -w net.ipv6.conf.default.disable_ipv6=1
sysctl -w net.ipv6.route.flush=1
sed -i 's/IPV6=yes/IPV6=no/g' /etc/default/ufw
ufw default deny incoming
ufw default deny outgoing
ufw default deny routed
ufw allow in on lo
ufw allow out on lo
ufw deny in from 127.0.0.0/8
ufw allow proto tcp from any to any port 22
ufw allow out from any to any proto udp port 22
ufw allow out from any to any proto udp port 53
ufw allow out from any to any proto udp port 67
ufw allow out from any to any proto tcp port 80
ufw allow out from any to any proto tcp port 443
ufw allow out from any to any proto udp port 123
ufw --force enable
echo "net.ipv4.conf.all.send_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.send_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv4.ip_forward = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.all.accept_source_route = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.accept_source_route = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.all.accept_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.accept_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.all.secure_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.secure_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.all.log_martians = 1" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.log_martians = 1" >> /etc/sysctl.conf
echo "net.ipv4.icmp_echo_ignore_broadcasts = 1" >> /etc/sysctl.conf
echo "net.ipv4.icmp_ignore_bogus_error_responses = 1" >> /etc/sysctl.conf
echo "net.ipv4.conf.all.rp_filter = 1" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.rp_filter = 1" >> /etc/sysctl.conf
echo "net.ipv4.tcp_syncookies = 1" >> /etc/sysctl.conf
sed -i '/pam_motd.so/d' /etc/pam.d/login
sed -i '/pam_motd.so/d' /etc/pam.d/sshd
chmod -x /etc/update-motd.d/*
sed -i 's/ENABLED=1/ENABLED=0/g' /etc/default/motd-news
echo "Authorized uses only. All activity may be monitored and reported." > /etc/issue
echo "Authorized uses only. All activity may be monitored and reported." > /etc/issue.net
chown root:root $(readlink -e /etc/issue)
chmod u-x,go-wx $(readlink -e /etc/issue)
chown root:root $(readlink -e /etc/issue.net)
chmod u-x,go-wx $(readlink -e /etc/issue.net)
echo "install dccp /bin/true" > /etc/modprobe.d/dccp.conf
echo "install sctp /bin/true" > /etc/modprobe.d/sctp.conf
echo "install rds /bin/true" > /etc/modprobe.d/rds.conf
echo "install tipc /bin/truee" > /etc/modprobe.d/tipc.conf
systemctl --now enable auditd
echo "-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change" > /etc/audit/rules.d/50-time-change.rules
echo "-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change" >> /etc/audit/rules.d/50-time-change.rules
echo "-a always,exit -F arch=b64 -S clock_settime -k time-change" >> /etc/audit/rules.d/50-time-change.rules
echo "-a always,exit -F arch=b32 -S clock_settime -k time-change" >> /etc/audit/rules.d/50-time-change.rules
echo "-w /etc/localtime -p wa -k time-change" >> /etc/audit/rules.d/50-time-change.rules
echo "-w /etc/group -p wa -k identity" > /etc/audit/rules.d/50-identity.rules
echo "-w /etc/passwd -p wa -k identity" >> /etc/audit/rules.d/50-identity.rules
echo "-w /etc/gshadow -p wa -k identity" >> /etc/audit/rules.d/50-identity.rules
echo "-w /etc/shadow -p wa -k identity" >> /etc/audit/rules.d/50-identity.rules
echo "-w /etc/security/opasswd -p wa -k identity" >> /etc/audit/rules.d/50-identity.rules
echo "-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale" > /etc/audit/rules.d/50-system-locale.rules
echo "-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale" >> /etc/audit/rules.d/50-system-locale.rules
echo "-w /etc/issue -p wa -k system-locale" >> /etc/audit/rules.d/50-system-locale.rules
echo "-w /etc/issue.net -p wa -k system-locale" >> /etc/audit/rules.d/50-system-locale.rules
echo "-w /etc/hosts -p wa -k system-locale" >> /etc/audit/rules.d/50-system-locale.rules
echo "-w /etc/network -p wa -k system-locale" >> /etc/audit/rules.d/50-system-locale.rules
echo "-w /etc/apparmor/ -p wa -k MAC-policy" > /etc/audit/rules.d/50-MAC-policy.rules
echo "-w /etc/apparmor.d/ -p wa -k MAC-policy" >> /etc/audit/rules.d/50-MAC-policy.rules
echo "-w /var/log/faillog -p wa -k logins" > /etc/audit/rules.d/50-logins.rules
echo "-w /var/log/lastlog -p wa -k logins" >> /etc/audit/rules.d/50-logins.rules
echo "-w /var/log/tallylog -p wa -k logins" >> /etc/audit/rules.d/50-logins.rules
echo "-w /var/run/utmp -p wa -k session" > /etc/audit/rules.d/50-session.rules
echo "-w /var/log/wtmp -p wa -k logins" >> /etc/audit/rules.d/50-session.rules
echo "-w /var/log/btmp -p wa -k logins" >> /etc/audit/rules.d/50-session.rules
echo "-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod" > /etc/audit/rules.d/50-perm_mod.rules
echo "-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/50-perm_mod.rules
echo "-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/50-perm_mod.rules
echo "-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/50-perm_mod.rules
echo "-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/50-perm_mod.rules
echo "-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/50-perm_mod.rules
echo "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access" > /etc/audit/rules.d/50-access.rules
echo "-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/rules.d/50-access.rules
echo "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/rules.d/50-access.rules
echo "-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/rules.d/50-access.rules
find / -xdev \( -perm -4000 -o -perm -2000 \) -type f | awk '{print "-a always,exit -F path=" $1 " -F perm=x -F auid>='"$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)"' -F auid!=4294967295 -k privileged" }' >> /etc/audit/rules.d/50-privileged.rules
echo "-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts" > /etc/audit/rules.d/50-mounts.rules
echo "-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts" >> /etc/audit/rules.d/50-mounts.rules
echo "-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete" > /etc/audit/rules.d/50-delete.rules
echo "-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete" >> /etc/audit/rules.d/50-delete.rules
echo "-w /etc/sudoers -p wa -k scope" > /etc/audit/rules.d/50-scope.rules
echo "-w /etc/sudoers.d/ -p wa -k scope" >> /etc/audit/rules.d/50-scope.rules
echo "-a always,exit -F arch=b64 -C euid!=uid -F euid=0 -Fauid>=1000 -F auid!=4294967295 -S execve -k actions" > /etc/audit/rules.d/50-actions.rules
echo "-a always,exit -F arch=b32 -C euid!=uid -F euid=0 -Fauid>=1000 -F auid!=4294967295 -S execve -k actions" >> /etc/audit/rules.d/50-actions.rules
echo "-w /sbin/insmod -p x -k modules" > /etc/audit/rules.d/50-modules.rules
echo "-w /sbin/rmmod -p x -k modules" >> /etc/audit/rules.d/50-modules.rules
echo "-w /sbin/modprobe -p x -k modules" >> /etc/audit/rules.d/50-modules.rules
echo "-a always,exit -F arch=b64 -S init_module -S delete_module -k modules" >> /etc/audit/rules.d/50-modules.rules
echo "-e 2" > /etc/audit/rules.d/99-finalize.rules
echo "ForwardToSyslog=yes" >> /etc/systemd/journald.conf
echo "Compress=yes" >> /etc/systemd/journald.conf
echo "Storage=persistent" >> /etc/systemd/journald.conf
find /var/log -type f -exec chmod g-wx,o-rwx "{}" + -o -type d -exec chmod g-w,o-rwx "{}" +
echo "compress" >> /etc/logrotate.conf
sed -i 's/create/create 0640 root utmp/g' /etc/logrotate.conf
chown root:root /etc/crontab
chmod og-rwx /etc/crontab
chown root:root /etc/cron.hourly/
chmod og-rwx /etc/cron.hourly/
chown root:root /etc/cron.daily/
chmod og-rwx /etc/cron.daily/
chown root:root /etc/cron.weekly/
chmod og-rwx /etc/cron.weekly/
chown root:root /etc/cron.monthly/
chmod og-rwx /etc/cron.monthly/
chown root:root /etc/cron.d/
chmod og-rwx /etc/cron.d/
touch /etc/cron.allow
chmod g-wx,o-rwx /etc/cron.allow
chown root:root /etc/cron.allow
touch /etc/at.allow
chmod g-wx,o-rwx /etc/at.allow
chown root:root /etc/at.allow
echo "Defaults logfile=\"/var/log/sudo.log\"" >> /etc/sudoers.d/99-CIS
chown root:root /etc/ssh/sshd_config
chmod og-rwx /etc/ssh/sshd_config
find /etc/ssh -xdev -type f -name 'ssh_host_*_key' -exec chown root:root {} \;
find /etc/ssh -xdev -type f -name 'ssh_host_*_key' -exec chmod u-x,go-rwx {} \;
find /etc/ssh -xdev -type f -name 'ssh_host_*_key.pub' -exec chmod u-x,go-wx {} \;
find /etc/ssh -xdev -type f -name 'ssh_host_*_key.pub' -exec chown root:root {} \;
echo "HostKey /etc/ssh/ssh_host_ed25519_key" >> /etc/ssh/sshd_config
echo "HostKey /etc/ssh/ssh_host_rsa_key" >> /etc/ssh/sshd_config
echo "HostKey /etc/ssh/ssh_host_ecdsa_key" >> /etc/ssh/sshd_config
echo "KexAlgorithms curve25519-sha256@libssh.org,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256" >> /etc/ssh/sshd_config
echo "Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr" >> /etc/ssh/sshd_config
echo "MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256" >> /etc/ssh/sshd_config
echo "AuthenticationMethods publickey" >> /etc/ssh/sshd_config
echo "AllowUsers ubuntu" >> /etc/ssh/sshd_config
echo "LogLevel VERBOSE" >> /etc/ssh/sshd_config
sed -i 's/X11Forwarding yes/X11Forwarding no/g' /etc/ssh/sshd_config
echo "MaxAuthTries 4" >> /etc/ssh/sshd_config
echo "IgnoreRhosts yes" >> /etc/ssh/sshd_config
echo "HostbasedAuthentication no" >> /etc/ssh/sshd_config
echo "PermitRootLogin no" >> /etc/ssh/sshd_config
echo "PermitEmptyPasswords no" >> /etc/ssh/sshd_config
echo "PermitUserEnvironment no" >> /etc/ssh/sshd_config
echo "LoginGraceTime 60" >> /etc/ssh/sshd_config
echo "Banner /etc/issue.net" >> /etc/ssh/sshd_config
echo "AllowTcpForwarding no" >> /etc/ssh/sshd_config
echo "MaxStartups 10:30:60" >> /etc/ssh/sshd_config
echo "MaxSessions 10" >> /etc/ssh/sshd_config
sed -i 's/PasswordAuthentication yes/PasswordAuthentication no/g' /etc/ssh/sshd_config
sed -i 's/sftp-server/sftp-server -f AUTHPRIV -l INFO/g' /etc/ssh/sshd_config
awk '$5 >= 3071' /etc/ssh/moduli > /etc/ssh/moduli.tmp
mv /etc/ssh/moduli.tmp /etc/ssh/moduli
awk -F: '$1!~/(root|sync|shutdown|halt|^\+)/ && $3<'"$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)"' && $7!~/((\/usr)?\/sbin\/nologin)/ && $7!~/(\/bin)?\/false/ {print $1}' /etc/passwd | while read -r user; do usermod -s "$(which nologin)" "$user"; done
awk -F: '($1!~/(root|^\+)/ && $3<'"$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)"') {print $1}' /etc/passwd | xargs -I '{}' passwd -S '{}' | awk '($2!~/LK?/) {print $1}' | while read -r user; do usermod -L "$user"; done
sed -i 's/UMASK           022/UMASK           027/g' /etc/login.defs
sed -i 's/USERGROUPS_ENAB yes/USERGROUPS_ENAB no/g' /etc/login.defs
groupadd sugroup
echo "auth required pam_wheel.so use_uid group=sugroup" >> /etc/pam.d/su
chown root:root /etc/passwd
chmod u-x,go-wx /etc/passwd
chown root:root /etc/passwd-
chmod u-x,go-wx /etc/passwd-
chown root:root /etc/group
chmod u-x,go-wx /etc/group
chown root:root /etc/group-
chmod u-x,go-wx /etc/group-
chown root:shadow /etc/shadow
chmod u-x,g-wx,o-rwx /etc/shadow
chown root:shadow /etc/shadow-
chmod u-x,g-wx,o-rwx /etc/shadow-
chown root:shadow /etc/gshadow
chmod u-x,g-wx,o-rwx /etc/gshadow
chown root:shadow /etc/gshadow-
chmod u-x,g-wx,o-rwx /etc/gshadow-
telinit 6
