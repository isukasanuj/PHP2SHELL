# Real vulnerable target matching the php2shell tool's "ubuntu2604-php85" profile:
# Ubuntu 26.04 (resolute) + distro PHP 8.5.4-0ubuntu1 (pre-fix; fix landed in 0ubuntu1.5)
# + Apache prefork/mod_php, forced to a SINGLE persistent worker for deterministic cross-request grooming.
FROM ubuntu:26.04
ENV DEBIAN_FRONTEND=noninteractive

# Pin every php8.5* package to the vulnerable release build 8.5.4-0ubuntu1 (resolute/main),
# so apt won't pull the patched 0ubuntu1.5 from resolute-updates/-security.
RUN set -eux; \
    printf 'Package: php8.5* libapache2-mod-php8.5*\nPin: version 8.5.4-0ubuntu1\nPin-Priority: 1001\n' \
      > /etc/apt/preferences.d/99-php-pin; \
    apt-get update; \
    apt-get install -y --no-install-recommends --allow-downgrades \
        apache2 libapache2-mod-php8.5 php8.5-cli php8.5-common \
        gdb ca-certificates curl less procps; \
    dpkg -l | grep -E '^ii\s+(php8.5|libapache2-mod-php8.5)' ; \
    php8.5 -v; \
    rm -rf /var/lib/apt/lists/*

# Apache: prefork + mod_php, single worker (deterministic worker reuse across requests)
RUN set -eux; \
    a2dismod mpm_event mpm_worker 2>/dev/null || true; \
    a2enmod mpm_prefork php8.5; \
    printf 'ServerName localhost\n<IfModule mpm_prefork_module>\n  StartServers 1\n  MinSpareServers 1\n  MaxSpareServers 1\n  MaxRequestWorkers 1\n  MaxConnectionsPerChild 0\n</IfModule>\n' \
      > /etc/apache2/conf-available/single-worker.conf; \
    a2enconf single-worker; \
    sed -ri 's!AllowOverride None!AllowOverride All!' /etc/apache2/apache2.conf

# Lab php.ini overlay (tunable per-test via .htaccess php_admin_value since AllowOverride All)
RUN printf 'memory_limit = 8M\ndisplay_errors = On\nhtml_errors = On\nsession.upload_progress.enabled = On\nsession.save_path = "/tmp"\npost_max_size = 256M\nmax_input_vars = 50\nfile_uploads = On\nmax_file_uploads = 20000\n' \
      > /etc/php/8.5/apache2/conf.d/99-lab.ini

RUN printf '<?php echo "OK\\n";' > /var/www/html/index.php
EXPOSE 80
# SYS_PTRACE added at run time for gdb; run foreground
CMD ["sh","-c","rm -f /var/run/apache2/apache2.pid; exec apachectl -D FOREGROUND"]
