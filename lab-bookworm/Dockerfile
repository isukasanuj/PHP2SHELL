# Reference-calibrated target: php:8.4.26-apache (Debian bookworm) + the reference lab configs.
# This is the environment the php2shell remote chain is calibrated for (bookworm profile).
FROM php:8.4.26-apache
COPY php.ini    /usr/local/etc/php/conf.d/zz-php2shell.ini
COPY apache.conf /etc/apache2/conf-enabled/zz-php2shell.conf
COPY index.php  /var/www/html/index.php
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends python3 gdb binutils; \
    rm -rf /var/lib/apt/lists/*; \
    mkdir -p /out; chown -R www-data:www-data /out; \
    php -v
EXPOSE 80
