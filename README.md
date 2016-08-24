# HoCo-server
Home Control Framework - node server implementation

Three purposes at this time:
1. firmware repository for OTA firmware upgrades
2. broadcast time via mqtt
3. serves embedded node-red instance

Installation:

- execute "npm install" to load required modules
- copy "config_template.json" to "config.json" and adjust based on your needs
- run "node app.js"

Full installation on a fresh Raspberry Pi including let's encrypt certificate setup etc:

- Setup fresh SD care with latest Raspbian Jessie Lite image (there are enough tutorials out there so I won't remeat the steps here)
- Boot RPi first time and take note of the IP
- Setup port forwarding on your router for the following ports
	80/443 for letsencrypt
	1883/1884 for mosquitto (mqtt/ws)
	1885 for webserver
- Login via SSH with username "pi" and password "raspberry":
- First time RPi basic configuration
```
sudo raspi-config
	- Advanced options -> update
	- Expand filesystem
	- Change user password -> {your_password}
	- Internationalisation options -> change timezone -> {your_timezone}
	- Advanced options -> hostname -> hoco
	- Finish / reboot
```
- Login via SSH with username "pi" and password "{your_password}"
- Initial software refresh
```
sudo apt-get -y update
sudo apt-get -y upgrade
sudo apt-get -y install git
```
- Let's encrypt
```
sudo useradd -m letsencrypt
sudo su -c "echo 'letsencrypt ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers.d/letsencrypt"
sudo su - letsencrypt
git clone https://github.com/letsencrypt/letsencrypt
cd letsencrypt
sudo ./letsencrypt-auto certonly --standalone --agree-tos --email {your_email} --domains {your_domain}
sudo chmod -R 755 /etc/letsencrypt/live
sudo chmod -R 755 /etc/letsencrypt/archive
sudo ln -s /etc/letsencrypt/live/{your_domain} /etc/letsencrypt/current
sudo su -c "cat /etc/letsencrypt/current/privkey.pem /etc/letsencrypt/current/cert.pem > /etc/letsencrypt/current/certkey.pem"
sudo chmod 755 /etc/letsencrypt/current/certkey.pem
exit
```
- Node.JS and PM2
```
curl -sL https://deb.nodesource.com/setup_6.x | sudo bash -
sudo apt-get -y install nodejs
sudo npm install -g pm2
```
- This web server - part 1
```
sudo useradd -m hoco
sudo su -c "echo 'hoco ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers.d/hoco"
sudo su - hoco
git clone https://github.com/ToSa27/HoCo-server.git
```
- Copy config_template.json to config.json and update details as needed. Set ssl config like this:
```
"ssl": {
	"enabled": false,
	"keyfile": "/etc/letsencrypt/current/privkey.pem",
	"certfile": "/etc/letsencrypt/current/cert.pem" 
}
```
- This web server - part 2
```
cd HoCo-server
npm install
pm2 start /home/hoco/HoCo-server/app.js --name "hoco"
sudo pm2 startup systemd -u hoco
pm2 dump
exit
```
-Mosquitto
```
wget http://repo.mosquitto.org/debian/mosquitto-repo.gpg.key
sudo apt-key add mosquitto-repo.gpg.key
rm mosquitto-repo.gpg.key
sudo wget http://repo.mosquitto.org/debian/mosquitto-jessie.list -O /etc/apt/sources.list.d/mosquitto-jessie.list
sudo apt-get -y update
sudo apt-get -y install mosquitto
sudo systemctl enable mosquitto.service
sudo touch /etc/mosquitto/conf.d/passwd
sudo mosquitto_passwd -b /etc/mosquitto/conf.d/passwd hang {your_password}
sudo su -c "echo 'password_file /etc/mosquitto/conf.d/passwd' >> /etc/mosquitto/conf.d/login.conf"
sudo su -c "echo 'allow_anonymous false' >> /etc/mosquitto/conf.d/login.conf"
sudo su -c "echo 'listener 1883' >> /etc/mosquitto/conf.d/mqtt.conf"
sudo su -c "echo 'protocol mqtt' >> /etc/mosquitto/conf.d/mqtt.conf"
sudo su -c "echo 'certfile /etc/letsencrypt/current/cert.pem' >> /etc/mosquitto/conf.d/mqtt.conf"
sudo su -c "echo 'cafile /etc/letsencrypt/current/chain.pem' >> /etc/mosquitto/conf.d/mqtt.conf"
sudo su -c "echo 'keyfile /etc/letsencrypt/current/privkey.pem' >> /etc/mosquitto/conf.d/mqtt.conf"
sudo su -c "echo 'require_certificate false' >> /etc/mosquitto/conf.d/mqtt.conf"
sudo su -c "echo 'tls_version tlsv1' >> /etc/mosquitto/conf.d/mqtt.conf"
sudo su -c "echo 'listener 1884' >> /etc/mosquitto/conf.d/websockets.conf"
sudo su -c "echo 'protocol websockets' >> /etc/mosquitto/conf.d/websockets.conf"
sudo su -c "echo 'certfile /etc/letsencrypt/current/cert.pem' >> /etc/mosquitto/conf.d/websockets.conf"
sudo su -c "echo 'cafile /etc/letsencrypt/current/chain.pem' >> /etc/mosquitto/conf.d/websockets.conf"
sudo su -c "echo 'keyfile /etc/letsencrypt/current/privkey.pem' >> /etc/mosquitto/conf.d/websockets.conf"
sudo su -c "echo 'require_certificate false' >> /etc/mosquitto/conf.d/websockets.conf"
sudo su -c "echo 'tls_version tlsv1' >> /etc/mosquitto/conf.d/websockets.conf"
sudo systemctl restart mosquitto.service
```
- Let's Encrypt auto update
```
sudo su - letsencrypt
echo '#!/bin/sh' >> ~/renew.sh
echo 'touch renew.log' >> ~/renew.sh
echo 'rm renew.log' >> ~/renew.sh
echo 'if ! sudo ./letsencrypt/letsencrypt-auto renew -nvv --standalone > renew.log 2>&1 ; then' >> ~/renew.sh
echo '    echo Automated renewal failed:' >> ~/renew.sh
echo '    cat renew.log' >> ~/renew.sh
echo '    exit 1' >> ~/renew.sh
echo 'fi' >> ~/renew.sh
echo 'sudo su -c "cat /etc/letsencrypt/current/privkey.pem /etc/letsencrypt/current/cert.pem > /etc/letsencrypt/current/certkey.pem"' >> ~/renew.sh
echo 'sudo chmod 755 /etc/letsencrypt/current/certkey.pem' >> ~/renew.sh
echo 'sudo systemctl restart pm2' >> ~/renew.sh
echo 'sudo systemctl restart mosquitto' >> ~/renew.sh
chmod 755 ~/renew.sh
crontab -l > cron
echo "0 4 * * 1 /home/letsencrypt/renew.sh" >> cron
crontab cron
rm cron
exit
```
