#!/usr/bin/env bash

source /etc/apache2/envvars
a2ensite location
apachectl -D FOREGROUND