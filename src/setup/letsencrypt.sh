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
        VIP=$(dig +short myip.opendns.com @resolver1.opendns.com | head -1)
        INSTALL=$(jq -r ".INSTALL" $CFG_FILE)
        SETUP=$(jq -r ".SETUP" $CFG_FILE)
        SETUP_OPENSSL=$(jq -r ".SETUP_OPENSSL" $CFG_FILE)
        SETUP_LETSENCRYPT=$(jq -r ".SETUP_LETSENCRYPT" $CFG_FILE)

        echo "Get SSL Certificate for " $DOMAIN
        echo " e-Mail " $EMAIL
        echo " Public IP " $VIP
        echo " Action Install: " $INSTALL
        echo " Action Setup: " $SETUP
        echo " Action OpenSSL: " $SETUP_OPENSSL
        echo " Action LetEncrypt: " $SETUP_LETSENCRYPT

fi

if [ $INSTALL == 'true' ]
then

sudo dnf update -y
sudo dnf install -y mod_ssl openssl certbot
sudo certbot --version
sudo certbot certificates
fi

if [ $SETUP_OPENSSL == 'true' ]
then
sudo openssl dhparam -out /etc/ssl/certs/dhparam.pem 4096
fi


if [ $SETUP_LETSENCRYPT == 'true' ]
then
sudo chmod g+s /var/lib/letsencrypt
sudo mkdir -p /var/lib/letsencrypt/.well-known
sudo chgrp apache /var/lib/letsencrypt
sudo chmod g+s /var/lib/letsencrypt

echo 'Alias /.well-known/acme-challenge/ "/var/lib/letsencrypt/.well-known/acme-challenge/"' | sudo tee /etc/httpd/conf.d/letsencrypt.conf
echo '<Directory "/var/lib/letsencrypt/">' | sudo tee -a /etc/httpd/conf.d/letsencrypt.conf
echo '    AllowOverride None' | sudo tee -a /etc/httpd/conf.d/letsencrypt.conf
echo '    Options MultiViews Indexes SymLinksIfOwnerMatch IncludesNoExec' | sudo tee -a /etc/httpd/conf.d/letsencrypt.conf
echo '    Require method GET POST OPTIONS' | sudo tee -a /etc/httpd/conf.d/letsencrypt.conf
echo '</Directory>' | sudo tee -a /etc/httpd/conf.d/letsencrypt.conf
sudo ls -l /etc/httpd/conf.d/letsencrypt.conf

sudo touch /etc/httpd/conf.d/ssl-params.conf
echo 'SSLCipherSuite EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH' | sudo tee /etc/httpd/conf.d/ssl-params.conf
echo 'SSLProtocol All -SSLv2 -SSLv3 -TLSv1 -TLSv1.1 | sudo tee -a /etc/httpd/conf.d/ssl-params.conf
echo 'SSLHonorCipherOrder On' | sudo tee -a /etc/httpd/conf.d/ssl-params.conf
echo 'Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"' | sudo tee -a /etc/httpd/conf.d/ssl-params.conf
echo 'echo 'Header always set X-Frame-Options SAMEORIGIN' | sudo tee -a /etc/httpd/conf.d/ssl-params.conf
echo 'Header always set X-Content-Type-Options nosniff' | sudo tee -a /etc/httpd/conf.d/ssl-params.conf
echo '# Requires Apache >= 2.4' | sudo tee -a /etc/httpd/conf.d/ssl-params.conf
echo 'SSLCompression off' | sudo tee -a /etc/httpd/conf.d/ssl-params.conf
echo 'SSLUseStapling on' | sudo tee -a /etc/httpd/conf.d/ssl-params.conf
echo 'SSLStaplingCache "shmcb:logs/stapling-cache(150000)"' | sudo tee -a /etc/httpd/conf.d/ssl-params.conf
echo '# Requires Apache >= 2.4.11' | sudo tee -a /etc/httpd/conf.d/ssl-params.conf
echo 'SSLSessionTickets Off' | sudo tee -a /etc/httpd/conf.d/ssl-params.conf

sudo ls -l /etc/httpd/conf.d/ssl-params.conf
sudo systemctl reload httpd

# sudo certbot certonly --manual --preferred-challenges=dns --email $EMAIL --server https://acme-v02.api.letsencrypt.org/directory --agree-tos -d $DOMAIN
fi

