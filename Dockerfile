FROM selenium/standalone-chrome:117.0

USER root

ADD /deploy/init.sh /usr/src/location/

RUN sed -i 's@//.*archive.ubuntu.com@//mirrors.ustc.edu.cn@g' /etc/apt/sources.list \
    && apt -y update \
    && apt -y install python3-pip apache2 apache2-utils libapache2-mod-wsgi-py3
RUN sh /usr/src/location/init.sh && \
    pip3 install pip==20.3.4 && \
    pip3 install setuptools -U && \
    pip3 install flask environs selenium selenium-requests

RUN rm -rf /etc/apache2/sites-available/000-default.conf

# Add everything
COPY /location_web /var/www/location_web
ADD /deploy/httpd /etc/apache2/sites-available/location.conf
ADD /deploy/wsgi /var/www/location_web/location.wsgi
ADD /deploy/entrypoints.sh /var/www/location_web/entrypoints.sh

RUN chmod 777 -R /var/www/location_web

CMD ["/var/www/location_web/entrypoints.sh"]