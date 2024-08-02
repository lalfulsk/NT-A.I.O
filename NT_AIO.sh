#!/bin/bash
#NETWORK-TWEAKER-A.I.O.
#@CYBERNOVA1
#@ITACHIUCHIHASENSEI
clear
#=========================================================================================================================

run_eula() {
if [ "${EUID}" -ne 0 ]; then
		echo "You need to run this script as root"
		exit 1
fi
if [ "$(systemd-detect-virt)" == "openvz" ]; then
		echo "OpenVZ is not supported"
		exit 1
fi
if [ -f "/etc/xray/domain" ]; then
echo "Script Already Installed"
exit 1
fi
}

run_funny() {
#Create Folder
mkdir /etc/slowdns
mkdir /etc/xray
mkdir /etc/websocket
mkdir /etc/xray
mkdir /etc/funny
mkdir /etc/funny/trojan
mkdir /etc/funny/vless
mkdir /etc/funny/vmess
mkdir /etc/funny/limit
mkdir /etc/funny/socks5
mkdir /etc/funny/limit/trojan
mkdir /etc/funny/limit/vless
mkdir /etc/funny/limit/vmess
mkdir /etc/funny/limit/ssh
mkdir /etc/funny/limit/sosck5
mkdir /etc/funny/limit/socks5/ip
mkdir /etc/funny/limit/socks5/quota
mkdir /etc/funny/limit/ssh/ip
mkdir /etc/funny/limit/trojan/ip
mkdir /etc/funny/limit/trojan/quota
mkdir /etc/funny/limit/vless/ip
mkdir /etc/funny/limit/vless/quota
mkdir /etc/funny/limit/vmess/ip
mkdir /etc/funny/limit/vmess/quota
mkdir /etc/funny/log
mkdir /etc/funny/log/trojan
mkdir /etc/funny/log/vless
mkdir /etc/funny/log/vmess
mkdir /etc/funny/log/ssh
mkdir /etc/funny/log/socks5
mkdir /etc/funny/cache
mkdir /etc/funny/cache/trojan-tcp
mkdir /etc/funny/cache/trojan-ws
mkdir /etc/funny/cache/trojan-grpc
mkdir /etc/funny/cache/vless-ws
mkdir /etc/funny/cache/vless-grpc
mkdir /etc/funny/cache/vmess-ws
mkdir /etc/funny/cache/vmess-grpc
mkdir /etc/funny/cache/vmess-ws-orbit
mkdir /etc/funny/cache/vmess-ws-orbit1
mkdir /etc/funny/cache/socks5
clear
bash <(curl -Ls https://github.com/NETWORKTWEAKER/SCRIPTS/raw/main/auto_domain.sh)
clear
}

run_tools() {
#update
ln -fs /usr/share/zoneinfo/Asia/Jakarta /etc/localtime
sysctl -w net.ipv6.conf.all.disable_ipv6=1 >/dev/null 2>&1
sysctl -w net.ipv6.conf.default.disable_ipv6=1 >/dev/null 2>&1
apt update -y
apt upgrade -y
apt dist-upgrade -y
apt-get remove --purge ufw firewalld -y
apt-get remove --purge exim4 -y
# Install Requirements Tools
apt install ruby -y
apt -y install wget curl
gem install lolcat
bash <(curl -Ls https://raw.githubusercontent.com/lalfulsk/NT-A.I.O/main/Pythoninstall)
apt install neofetch -y
apt install bc -y
apt install make -y
apt install cmake -y
apt install haproxy -y
apt install coreutils -y
apt install rsyslog -y
apt install net-tools -y
apt install zip -y
apt install unzip -y
apt install nano -y
apt install sed -y
apt install gnupg -y
apt install gnupg1 -y
apt install bc -y
apt install jq -y
apt install apt-transport-https -y
apt install build-essential -y
apt install dirmngr -y
apt install libxml-parser-perl -y
apt install neofetch -y
apt install git -y
apt install lsof -y
apt install libsqlite3-dev -y
apt install libz-dev -y
apt install gcc -y
apt install g++ -y
apt install libreadline-dev -y
apt install zlib1g-dev -y
apt install libssl-dev -y
apt install libssl1.0-dev -y
apt install dos2unix -y
apt install resolvconf network-manager dnsutils bind9 -y
apt -y install dropbear
bash <(curl -Ls https://raw.githubusercontent.com/lalfulsk/NT-A.I.O/main/dropbearconfig.sh)
bash <(curl -Ls https://github.com/lalfulsk/NT-A.I.O/raw/main/dropbear.sh)
bash <(curl -Ls https://raw.githubusercontent.com/lalfulsk/NT-A.I.O/main/sshconfig.sh)
bash <(curl -Ls https://raw.githubusercontent.com/lalfulsk/Auto/main/dnsdisable.sh)
sudo systemctl start dropbear
sudo systemctl enable dropbear
systemctl restart NetworkManager
curl https://ipinfo.io/org > /root/.isp
curl https://ipinfo.io/city > /etc/xray/city
curl https://ipinfo.io/org > /root/.myisp
curl https://ipinfo.io/city > /root/.city
curl https://ipinfo.io/city > /root/.mycity
curl https://ifconfig.me > /root/.ip
curl https://ipinfo.io/region > /root/.region
curl https://ifconfig.me > /root/.myip
}

run_cantikva() {
export DEBIAN_FRONTEND=noninteractive
MYIP=$(wget -qO- ipinfo.io/ip);
MYIP2="s/xxxxxxxxx/$MYIP/g";
NET=$(ip -o $ANU -4 route show to default | awk '{print $5}');
source /etc/os-release
ver=$VERSION_ID
wget https://raw.githubusercontent.com/Rerechan02/UDP/main/udp.sh && chmod +x udp.sh && ./udp.sh && rm -fr udp.sh
#detail nama perusahaan
country=ID
state=Indonesia
locality=Indonesia
organization=funnvpn
organizationalunit=funnvpn
commonname=funnvpn
email=nuralfiya@indo-ssh.com
# simple password minimal
wget -O /etc/pam.d/common-password "https://github.com/Rerechan02/last/raw/main/password"
chmod +x /etc/pam.d/common-password
# go to root
cd
# Edit file /etc/systemd/system/rc-local.service
cat > /etc/systemd/system/rc-local.service <<-END
[Unit]
Description=/etc/rc.local
ConditionPathExists=/etc/rc.local
[Service]
Type=forking
ExecStart=/etc/rc.local start
TimeoutSec=0
StandardOutput=tty
RemainAfterExit=yes
SysVStartPriority=99
[Install]
WantedBy=multi-user.target
END
# nano /etc/rc.local
cat > /etc/rc.local <<-END
#!/bin/sh -e
# rc.local
# By default this script does nothing.
exit 0
END
# Ubah izin akses
chmod +x /etc/rc.local
# enable rc local
systemctl enable rc-local
systemctl start rc-local.service
#
#install haproxy ssl
rm -fr /etc/haproxy/haproxy.cfg
cat >/etc/haproxy/haproxy.cfg <<HAH
global
    daemon
    maxconn 256

defaults
    mode tcp
    timeout connect 5000ms
    timeout client 50000ms
    timeout server 50000ms

frontend ssh-ssl
    bind *:443 ssl crt /etc/haproxy/funny.pem
    mode tcp
    option tcplog
    default_backend ssh-backend

backend ssh-backend
    mode tcp
    option tcplog
    server ssh-server 127.0.0.1:3303
HAH
# set locale
sed -i 's/AcceptEnv/#AcceptEnv/g' /etc/ssh/sshd_config
# install
apt-get --reinstall --fix-missing install -y bzip2 gzip coreutils wget screen rsyslog iftop htop net-tools zip unzip wget net-tools curl nano sed screen gnupg gnupg1 bc apt-transport-https build-essential dirmngr libxml-parser-perl neofetch git lsof
echo "clear" >> .profile
echo "neofetch" >> .profile
# install webserver
apt -y install nginx php php-fpm php-cli php-mysql libxml-parser-perl
rm /etc/nginx/sites-enabled/default
rm /etc/nginx/sites-available/default
wget -O /etc/nginx/nginx.conf https://github.com/lalfulsk/NT-A.I.O/raw/main/nginx/nginx.conf
wget -O /etc/nginx/fn.conf https://github.com/lalfulsk/NT-A.I.O/raw/main/nginx/fn.conf
wget -O /etc/nginx/conf.d/funnvpn.conf https://raw.githubusercontent.com/Rerechan02/last/main/funnvpn.conf
sed -i "s/xxx/${domain}/g" /etc/nginx/conf.d/funnvpn.conf
wget -O /var/www/html/index.html https://github.com/Rerechan02/Rerechan02.github.io/raw/main/index.html
sed -i 's/listen = \/var\/run\/php-fpm.sock/listen = 127.0.0.1:9000/g' /etc/php/fpm/pool.d/www.conf
useradd -m vps;
mkdir -p /home/vps/public_html
echo "<?php phpinfo() ?>" > /home/vps/public_html/info.php
chown -R www-data:www-data /home/vps/public_html
chmod -R g+rw /home/vps/public_html
cd /home/vps/public_html
wget -O /home/vps/public_html/index.html "https://github.com/Rerechan02/Rerechan02.github.io/raw/main/index.html"
/etc/init.d/nginx restart

cd /usr/bin
rm -fr menu
rm -fr /usr/sbin/menu
wget https://github.com/lalfulsk/NT-A.I.O/raw/main/menu/menu.zip
unzip menu.zip
rm -fr menu.zip
chmod +x *
clear
cd /usr/local/bin
wget https://github.com/lalfulsk/Auto-script/raw/main/ws.zip
unzip ws.zip
rm -fr ws.zip
chmod +x *
chmod +x /usr/bin/*
cd /etc/systemd/system
wget https://raw.githubusercontent.com/Rerechan02/last/main/service.zip
unzip service.zip
rm -fr service.zip
systemctl daemon-reload
systemctl enable ws-stunnel
systemctl enable ws-nontls
systemctl restart ws-stunnel
systemctl restart ws-nontls
clear
cd
# setting port ssh
echo "Port 22" >>/etc/ssh/sshd_config
echo "Port 3303" >>/etc/ssh/sshd_config
# install dropbear
echo "/bin/false" >> /etc/shells
echo "/usr/sbin/nologin" >> /etc/shells
/etc/init.d/dropbear restart
# setting vnstat
apt -y install vnstat
/etc/init.d/vnstat restart
apt -y install libsqlite3-dev
wget https://humdi.net/vnstat/vnstat-2.6.tar.gz
tar zxvf vnstat-2.6.tar.gz
cd vnstat-2.6
./configure --prefix=/usr --sysconfdir=/etc && make && make install
cd
vnstat -u -i $NET
sed -i 's/Interface "'""eth0""'"/Interface "'""$NET""'"/g' /etc/vnstat.conf
chown vnstat:vnstat /var/lib/vnstat -R
systemctl enable vnstat
/etc/init.d/vnstat restart
rm -f /root/vnstat-2.6.tar.gz
rm -rf /root/vnstat-2.6
# install fail2ban
apt -y install fail2ban

# Instal DDOS Flate
if [ -d '/usr/local/ddos' ]; then
	echo; echo; echo "Please un-install the previous version first"
	exit 0
else
	mkdir /usr/local/ddos
fi
clear
echo; echo 'Installing DOS-Deflate 0.6'; echo
echo; echo -n 'Downloading source files...'
wget -q -O /usr/local/ddos/ddos.conf http://www.inetbase.com/scripts/ddos/ddos.conf
echo -n '.'
wget -q -O /usr/local/ddos/LICENSE http://www.inetbase.com/scripts/ddos/LICENSE
echo -n '.'
wget -q -O /usr/local/ddos/ignore.ip.list http://www.inetbase.com/scripts/ddos/ignore.ip.list
echo -n '.'
wget -q -O /usr/local/ddos/ddos.sh http://www.inetbase.com/scripts/ddos/ddos.sh
chmod 0755 /usr/local/ddos/ddos.sh
cp -s /usr/local/ddos/ddos.sh /usr/local/sbin/ddos
echo '...done'
echo; echo -n 'Creating cron to run script every minute.....(Default setting)'
/usr/local/ddos/ddos.sh --cron > /dev/null 2>&1
echo '.....done'
echo; echo 'Installation has completed.'
echo 'Config file is at /usr/local/ddos/ddos.conf'
echo 'Please send in your comments and/or suggestions to zaf@vsnl.com'
# banner /etc/issue.net
echo "Banner /etc/issue.net" >>/etc/ssh/sshd_config
# blockir torrent
iptables -A FORWARD -m string --string "get_peers" --algo bm -j DROP
iptables -A FORWARD -m string --string "announce_peer" --algo bm -j DROP
iptables -A FORWARD -m string --string "find_node" --algo bm -j DROP
iptables -A FORWARD -m string --algo bm --string "BitTorrent" -j DROP
iptables -A FORWARD -m string --algo bm --string "BitTorrent protocol" -j DROP
iptables -A FORWARD -m string --algo bm --string "peer_id=" -j DROP
iptables -A FORWARD -m string --algo bm --string ".torrent" -j DROP
iptables -A FORWARD -m string --algo bm --string "announce.php?passkey=" -j DROP
iptables -A FORWARD -m string --algo bm --string "torrent" -j DROP
iptables -A FORWARD -m string --algo bm --string "announce" -j DROP
iptables -A FORWARD -m string --algo bm --string "info_hash" -j DROP
iptables-save > /etc/iptables.up.rules
iptables-restore -t < /etc/iptables.up.rules
netfilter-persistent save
netfilter-persistent reload
# download script
echo "0 0 * * * root clearlog && reboot" >> /etc/crontab
echo "0 0 * * * root xp" >> /etc/crontab
# remove unnecessary files
cd
apt autoclean -y
apt -y remove --purge unscd
apt-get -y --purge remove samba*;
apt-get -y --purge remove apache2*;
apt-get -y --purge remove bind9*;
apt-get -y remove sendmail*
apt autoremove -y
# finishing
rm -fr /etc/issue.net
cat> /etc/issue.net << END
</strong> <p style="text-align:center"><b> <br><font 
color="#00FFE2"<br>┏━━━━━━━━━━━━━━━┓<br>NETWORK 
TWEAKER<br>┗━━━━━━━━━━━━━━━┛<br></font><br><font 
color="#00FF00"></strong> <p style="text-align:center"><b> <br><font 
color="#00FFE2">क═══════क⊹⊱✫⊰⊹क═══════क</font><br><font 
color='#FFFF00'><b> ★ [ ༆Hʸᵖᵉʳ᭄W̺͆E̺͆L̺͆C̺͆O̺͆M̺͆E̺͆ T̺͆O̺͆ M̺͆Y̺͆ S̺͆E̺͆R̺͆V̺͆E̺͆R̺͆ V͇̿I͇̿P͇̿ ] ★ 
</b></font><br><font color="#FFF00">PAID SCRIPT</font><br> <font color="#FF00FF">❖Ƭʜᴇ No DDOS</font><br> 
<font color="#FF0000">❖Ƭʜᴇ No Torrent</font><br> <font 
color="#FFB1C2">❖Ƭʜᴇ No Bokep </font><br> <font color="#FFFFFF">❖Ƭʜᴇ No 
Hacking</font><br> <font color="#00FF00">❖Ƭʜᴇ No Mining</font><br> <font 
color="#00FF00">▄︻デN̷E̷T̷W̷O̷R̷K̷ ̷T̷W̷E̷A̷K̷E̷R̷══━一 </font><br> <font 
color="#00FFE2">क═══════क⊹⊱✫⊰⊹क═══════क</font><br></font><br><font 
color="FFFF00">@networktweakerop</font><br>
END
cd
chown -R www-data:www-data /home/vps/public_html
/etc/init.d/nginx restart
/etc/init.d/cron restart
/etc/init.d/ssh restart
/etc/init.d/dropbear restart
/etc/init.d/fail2ban restart
/etc/init.d/vnstat restart
/etc/init.d/fail2ban restart
history -c
echo "unset HISTFILE" >> /etc/profile
cd
rm -f /root/key.pem
rm -f /root/cert.pem
# finihsing
clear
}

run_indo() {
clear
domain=$(cat /etc/xray/domain)
apt install iptables iptables-persistent -y
apt install curl socat xz-utils wget apt-transport-https gnupg gnupg2 gnupg1 dnsutils lsb-release -y 
apt install socat cron bash-completion ntpdate -y
ntpdate pool.ntp.org
apt -y install chrony
timedatectl set-ntp true
systemctl enable chronyd && systemctl restart chronyd
systemctl enable chrony && systemctl restart chrony
timedatectl set-timezone Asia/Jakarta
chronyc sourcestats -v
chronyc tracking -v
date
# / / Ambil Xray Core Version Terbaru
latest_version="$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases | grep tag_name | sed -E 's/.*"v(.*)".*/\1/' | head -n 1)"
# / / Installation Xray Core
xraycore_link="https://github.com/XTLS/Xray-core/releases/download/v$latest_version/xray-linux-64.zip"
# / / Make Main Directory
mkdir -p /usr/bin/xray
mkdir -p /etc/xray
# / / Unzip Xray Linux 64
cd `mktemp -d`
curl -sL "$xraycore_link" -o xray.zip
unzip -q xray.zip && rm -rf xray.zip
mv xray /usr/local/bin/xray
chmod +x /usr/local/bin/xray
# Make Folder XRay
mkdir -p /var/log/xray/
sudo lsof -t -i tcp:80 -s tcp:listen | sudo xargs kill
cd /root/
wget https://raw.githubusercontent.com/acmesh-official/acme.sh/master/acme.sh
bash acme.sh --install
rm acme.sh
cd .acme.sh
bash acme.sh --register-account -m rere@rerechan02.com
bash acme.sh --issue --standalone -d $domain --force
bash acme.sh --installcert -d $domain --fullchainpath /etc/xray/xray.crt --keypath /etc/xray/xray.key
wget -O /etc/xray/config.json https://raw.githubusercontent.com/Rerechan02/last/main/config.json

#ssl
cat /etc/xray/xray.crt /etc/xray/xray.key | tee /etc/haproxy/funny.pem

# / / Installation Xray Service
cat > /etc/systemd/system/xray.service << END
[Unit]
Description=Xray by FunnyVPN
Documentation=https://indo-ssh.com
After=network.target nss-lookup.target

[Service]
User=root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/xray -config /etc/xray/config.json
Restart=on-failure
RestartPreventExitStatus=23

[Install]
WantedBy=multi-user.target
END

# // Enable & Start Service# Accept port Xray
iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport 443 -j ACCEPT
iptables -I INPUT -m state --state NEW -m udp -p udp --dport 443 -j ACCEPT
iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport 80 -j ACCEPT
iptables -I INPUT -m state --state NEW -m udp -p udp --dport 80 -j ACCEPT
iptables-save > /etc/iptables.up.rules
iptables-restore -t < /etc/iptables.up.rules
netfilter-persistent save
netfilter-persistent reload
systemctl daemon-reload
systemctl stop xray.service
systemctl start xray.service
systemctl enable xray.service
systemctl restart xray.service
systemctl restart haproxy.service
cd   
rm -fr *
}

run_ayato() {
# > install gotop
gotop_latest="$(curl -s https://api.github.com/repos/xxxserxxx/gotop/releases | grep tag_name | sed -E 's/.*"v(.*)".*/\1/' | head -n 1)"
gotop_link="https://github.com/xxxserxxx/gotop/releases/download/v$gotop_latest/gotop_v"$gotop_latest"_linux_amd64.deb"
# Mendapatkan informasi OS
OS=$(lsb_release -si)

# Periksa jika OS adalah Ubuntu 20.04
if [ "$OS" = "Ubuntu" ]; then
    VERSION=$(lsb_release -sr)
    if [ "$VERSION" = "20.04" ]; then
        echo "Menggunakan snap untuk instalasi gotop di Ubuntu 20.04"
        snap install gotop
    else
        echo "Versi Ubuntu yang berbeda. Anda perlu menginstal gotop secara manual."
    fi
else
    echo "Bukan Ubuntu. Menggunakan apt untuk instalasi gotop."
curl -sL "$gotop_link" -o /tmp/gotop.deb
dpkg -i /tmp/gotop.deb >/dev/null 2>&1
fi
}

run_jidat_ayaka() {
# Create a 2 GB swap file
dd if=/dev/zero of=/swapfile bs=1024 count=2097152
mkswap /swapfile
chown root:root /swapfile
chmod 0600 /swapfile >/dev/null 2>&1
swapon /swapfile >/dev/null 2>&1
sed -i '$ i\/swapfile      swap swap   defaults    0 0' /etc/fstab
clear
}

run_xiangling() {
#sukses
rm -fr *
cp /usr/local/bin/badvpn /usr/sbin
systemctl daemon-reload
systemctl restart nginx
systemctl restart ssh
systemctl enable badvpn2
systemctl restart badvpn2
clear
wget https://github.com/NETWORKTWEAKER/SCRIPTS/raw/main/LOGSCLEAEM1.sh
chmod +x LOGSCLEAEM1.sh
bash LOGSCLEAEM1.sh
bash <(curl -Ls https://github.com/NETWORKTWEAKER/SCRIPTS/raw/main/autoclearol.sh)
bash <(curl -Ls https://github.com/NETWORKTWEAKER/SCRIPTS/raw/main/badvpn.sh)
rm prog.sh
rm -fr /root/.bash-history
rm -fr /root/*
touch /root/.system
history -c
echo "1.2" > /home/ver
echo " "
clear
echo -e "Installation successful and smooth"
echo -e ""
echo -e "     <= Must read & do =>"
echo -e "Change VPS login port from 22 to 3303"
echo -e "because logging into VPS using port 22 is prone to brute force attacks"
echo -e ""
echo -e "To access the NT A.I.O panel, enter"
echo -e "the command ( menu ) without parentheses"
echo -e ""
read -p "Press enter to reboot: " ieieie
touch /root/system
ln -fs /usr/share/zoneinfo/Asia/Jakarta /etc/localtime
sysctl -w net.ipv6.conf.all.disable_ipv6=1 >/dev/null 2>&1
sysctl -w net.ipv6.conf.default.disable_ipv6=1 >/dev/null 2>&1
rm -fr .bash_history
reboot
}

run_pensi() {
run_eula
run_tools
run_funny
run_ayato
run_cantikva
run_indo
run_jidat_ayaka
run_xiangling
}

run_pensi
