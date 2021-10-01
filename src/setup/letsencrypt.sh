#!/usr/bin/env bash
# set -x
# file name: letsencrypt.sh
################################################################################
# License                                                                         #
################################################################################
function license() {
    # On MAC update bash: https://scriptingosx.com/2019/02/install-bash-5-on-macos/
    printf '%s\n' ""
    printf '%s\n' " GPL-3.0-only or GPL-3.0-or-later"
    printf '%s\n' " Copyright (c) 2021 BMC Software, Inc."
    printf '%s\n' " Author: Volker Scheithauer"
    printf '%s\n' " E-Mail: orchestrator@bmc.com"
    printf '%s\n' " Contributor: Daniel Companeetz"
    printf '%s\n' ""
    printf '%s\n' " This program is free software: you can redistribute it and/or modify"
    printf '%s\n' " it under the terms of the GNU General Public License as published by"
    printf '%s\n' " the Free Software Foundation, either version 3 of the License, or"
    printf '%s\n' " (at your option) any later version."
    printf '%s\n' ""
    printf '%s\n' " This program is distributed in the hope that it will be useful,"
    printf '%s\n' " but WITHOUT ANY WARRANTY; without even the implied warranty of"
    printf '%s\n' " MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the"
    printf '%s\n' " GNU General Public License for more details."
    printf '%s\n' ""
    printf '%s\n' " You should have received a copy of the GNU General Public License"
    printf '%s\n' " along with this program.  If not, see <https://www.gnu.org/licenses/>."
}

function ctmLogo() {
    printf '%s\n' ""
    printf '%s\n' "  @@@@@@@   @@@@@@   @@@  @@@  @@@@@@@  @@@@@@@    @@@@@@   @@@                  @@@@@@@@@@   "
    printf '%s\n' " @@@@@@@@  @@@@@@@@  @@@@ @@@  @@@@@@@  @@@@@@@@  @@@@@@@@  @@@                  @@@@@@@@@@@  "
    printf '%s\n' " !@@       @@!  @@@  @@!@!@@@    @@!    @@!  @@@  @@!  @@@  @@!                  @@! @@! @@!  "
    printf '%s\n' " !@!       !@!  @!@  !@!!@!@!    !@!    !@!  @!@  !@!  @!@  !@!                  !@! !@! !@!  "
    printf '%s\n' " !@!       @!@  !@!  @!@ !!@!    @!!    @!@!!@!   @!@  !@!  @!!       @!@!@!@!@  @!! !!@ @!@  "
    printf '%s\n' " !!!       !@!  !!!  !@!  !!!    !!!    !!@!@!    !@!  !!!  !!!       !!!@!@!!!  !@!   ! !@!  "
    printf '%s\n' " :!!       !!:  !!!  !!:  !!!    !!:    !!: :!!   !!:  !!!  !!:                  !!:     !!:  "
    printf '%s\n' " :!:       :!:  !:!  :!:  !:!    :!:    :!:  !:!  :!:  !:!   :!:                 :!:     :!:  "
    printf '%s\n' "  ::: :::  ::::: ::   ::   ::     ::    ::   :::  ::::: ::   :: ::::             :::     ::   "
    printf '%s\n' "  :: :: :   : :  :   ::    :      :      :   : :   : :  :   : :: : :              :      :    "
}

VERSION="20.21.10.00"
################################################################################
# Help                                                                         #
################################################################################
function help() {
        # Display Help
    printf '%s\n' ""
    printf '%s\n' "Apply for SSL cert from LetsEncrypt."
    printf '%s\n' ""
    printf '%s\n' "Syntax: letsencrypt.sh.sh [-f|h|v]"
    printf '%s\n' "options:"
    printf '%s\n' "h     Print this Help."
    printf '%s\n' "f     SSL Settings JSON File Name"
    printf '%s\n' "v     script version."
    printf '%s\n' "output:"
    printf '%s\n' "     script version."
    printf '%s\n' "     script version."
    printf '%s\n' "     script version."
    exit 0
}

if [ $# -eq 0 ]; then
        ctmLogo
        exit
fi


POSITIONAL=()
while [[ $# -gt 0 ]]; do
        key="$1"

        case $key in

        -f | --file)
                CFG_FILE="$2"
                shift # past argument
                shift # past value
                ;;

        -v | --version)
                echo "Version " $VERSION
                shift # past argument
                shift # past value
                ;;

        -h | --help)
                ctmLogo
                help
                exit
                ;;

        -l | --license)
                ctmLogo
                license
                exit
                ;;
        *)
                ctmLogo
                exit
                ;;

        esac
done

if [[ -f "$CFG_FILE" ]] 
then
        EMAIL=$(jq -r ".EMAIL" $CFG_FILE)
        DOMAIN=$(jq -r ".DOMAIN" $CFG_FILE)
        FQDN=$(jq -r ".FQDN" $CFG_FILE)
        VIP=$(dig +short myip.opendns.com @resolver1.opendns.com | head -1)
        PIP=$(ip addr | grep 'state UP' -A2 | tail -n1 | awk '{print $2}' | cut -f1 -d'/')
        INSTALL=$(jq -r ".INSTALL" $CFG_FILE)
        SETUP=$(jq -r ".SETUP" $CFG_FILE)
        SETUP_OPENSSL=$(jq -r ".SETUP_OPENSSL" $CFG_FILE)
        SETUP_LETSENCRYPT=$(jq -r ".SETUP_LETSENCRYPT" $CFG_FILE)


        echo "Get SSL Certificate for " $DOMAIN
        echo " e-Mail " $EMAIL
        echo " Private IP " $PIP
        echo " Public IP " $VIP
        echo " Public FDQN " $FQDN
        echo " Action Install: " $INSTALL
        echo " Action Setup: " $SETUP
        echo " Action OpenSSL: " $SETUP_OPENSSL
        echo " Action LetEncrypt: " $SETUP_LETSENCRYPT

fi

if [ $INSTALL == "true" ]
then

sudo dnf update -y
sudo dnf install -y mod_ssl openssl certbot
sudo certbot --version
sudo certbot certificates
fi

if [ $SETUP_OPENSSL == "true" ]
then
sudo openssl dhparam -out /etc/ssl/certs/dhparam.pem 4096
fi


if [ $SETUP_LETSENCRYPT == "true" ]
then

if [ ! -d "/var/lib/letsencrypt/.well-known" ]
then
sudo mkdir -p /var/lib/letsencrypt/.well-known
sudo chgrp apache /var/lib/letsencrypt
sudo chmod g+s /var/lib/letsencrypt
fi

if [ ! -f "/etc/httpd/conf.d/letsencrypt.conf" ]
then
sudo touch /etc/httpd/conf.d/letsencrypt.conf
echo 'Alias /.well-known/acme-challenge/ "/var/lib/letsencrypt/.well-known/acme-challenge/"' | sudo tee /etc/httpd/conf.d/letsencrypt.conf
echo '<Directory "/var/lib/letsencrypt/">' | sudo tee -a /etc/httpd/conf.d/letsencrypt.conf
echo '    AllowOverride None' | sudo tee -a /etc/httpd/conf.d/letsencrypt.conf
echo '    Options MultiViews Indexes SymLinksIfOwnerMatch IncludesNoExec' | sudo tee -a /etc/httpd/conf.d/letsencrypt.conf
echo '    Require method GET POST OPTIONS' | sudo tee -a /etc/httpd/conf.d/letsencrypt.conf
echo '</Directory>' | sudo tee -a /etc/httpd/conf.d/letsencrypt.conf
sudo ls -l /etc/httpd/conf.d/letsencrypt.conf
fi

if [ ! -f "/etc/httpd/conf.d/ssl-params.conf" ]
then
sudo touch /etc/httpd/conf.d/ssl-params.conf
echo 'SSLCipherSuite EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH' | sudo tee /etc/httpd/conf.d/ssl-params.conf
echo 'SSLProtocol All -SSLv2 -SSLv3 -TLSv1 -TLSv1.1' | sudo tee -a /etc/httpd/conf.d/ssl-params.conf
echo 'SSLHonorCipherOrder On' | sudo tee -a /etc/httpd/conf.d/ssl-params.conf
echo 'Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"' | sudo tee -a /etc/httpd/conf.d/ssl-params.conf
echo 'Header always set X-Frame-Options SAMEORIGIN' | sudo tee -a /etc/httpd/conf.d/ssl-params.conf
echo 'Header always set X-Content-Type-Options nosniff' | sudo tee -a /etc/httpd/conf.d/ssl-params.conf
echo 'SSLCompression off' | sudo tee -a /etc/httpd/conf.d/ssl-params.conf
echo 'SSLUseStapling on' | sudo tee -a /etc/httpd/conf.d/ssl-params.conf
echo 'SSLStaplingCache "shmcb:logs/stapling-cache(150000)"' | sudo tee -a /etc/httpd/conf.d/ssl-params.conf
echo 'SSLSessionTickets Off' | sudo tee -a /etc/httpd/conf.d/ssl-params.conf
sudo ls -l /etc/httpd/conf.d/ssl-params.conf
fi

sudo systemctl reload httpd
# sudo certbot certonly --agree-tos --email $EMAIL --webroot -w /var/lib/letsencrypt/ -d $DOMAIN -d $FQDN
sudo certbot certificates

if [ ! -d "/var/www/$DOMAIN" ]
then
sudo mkdir -p /var/www/$DOMAIN
sudo chgrp apache /var/www/$DOMAIN
sudo chmod g+s /var/www/$DOMAIN
sudo cp -R ./web/* /var/www/$DOMAIN 
sudo sed -i "s/ABCD/$FQDN/g" /var/www/$DOMAIN/index.html
fi

if [ ! -f "/etc/httpd/conf.d/$DOMAIN.conf" ]
then
sudo touch /etc/httpd/conf.d/$DOMAIN.conf
echo "<VirtualHost *:80>" | sudo tee -a /etc/httpd/conf.d/$DOMAIN.conf
echo "  ServerName $DOMAIN" | sudo tee -a /etc/httpd/conf.d/$DOMAIN.conf
echo "  ServerAlias $FQDN" | sudo tee -a /etc/httpd/conf.d/$DOMAIN.conf
echo " " | sudo tee -a /etc/httpd/conf.d/$DOMAIN.conf
echo "  Redirect permanent / https://$FQDN/" | sudo tee -a /etc/httpd/conf.d/$DOMAIN.conf
echo "</VirtualHost>" | sudo tee -a /etc/httpd/conf.d/$DOMAIN.conf
echo " " | sudo tee -a /etc/httpd/conf.d/$DOMAIN.conf
echo "<VirtualHost *:443>" | sudo tee -a /etc/httpd/conf.d/$DOMAIN.conf
echo "  ServerName $DOMAIN" | sudo tee -a /etc/httpd/conf.d/$DOMAIN.conf
echo "  ServerAlias $FQDN" | sudo tee -a /etc/httpd/conf.d/$DOMAIN.conf
echo "  Protocols h2 http/1.1" | sudo tee -a /etc/httpd/conf.d/$DOMAIN.conf
echo "  DocumentRoot /var/www/$DOMAIN/" | sudo tee -a /etc/httpd/conf.d/$DOMAIN.conf
echo "  ErrorLog /var/log/httpd/$DOMAIN-error.log" | sudo tee -a /etc/httpd/conf.d/$DOMAIN.conf
echo "  CustomLog /var/log/httpd/$DOMAIN-access.log combined" | sudo tee -a /etc/httpd/conf.d/$DOMAIN.conf
echo "  SSLEngine On" | sudo tee -a /etc/httpd/conf.d/$DOMAIN.conf
echo "  SSLCertificateFile /etc/letsencrypt/live/$DOMAIN/fullchain.pem" | sudo tee -a /etc/httpd/conf.d/$DOMAIN.conf
echo "  SSLCertificateKeyFile /etc/letsencrypt/live/$DOMAIN/privkey.pem" | sudo tee -a /etc/httpd/conf.d/$DOMAIN.conf
echo "  SSLCertificateChainFile /etc/letsencrypt/live/$DOMAIN/chain.pem" | sudo tee -a /etc/httpd/conf.d/$DOMAIN.conf
echo "</VirtualHost>" | sudo tee -a /etc/httpd/conf.d/$DOMAIN.conf


sudo systemctl reload httpd
fi

# sudo certbot certonly --manual --preferred-challenges=dns --email $EMAIL --server https://acme-v02.api.letsencrypt.org/directory --agree-tos -d $DOMAIN
fi

