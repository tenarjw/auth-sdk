FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    syslog-ng \
    postfix \
    sasl2-bin libsasl2-modules \
    spamassassin \
    clamav \
    clamav-daemon \
    clamav-freshclam \
    supervisor \
    certbot \
    curl \
    gnupg \
    amavisd-new \
    opendkim \
    opendkim-tools \
    gettext \
    arj cabextract lhasa lzop nomarch p7zip rpm unzip zip \
    cron \
    && apt-get install --reinstall amavisd-new \
    && rm -rf /var/lib/apt/lists/*

# debug
RUN apt-get update && apt-get install -y \
    net-tools \
    telnet \
    openssl \
    mc \
    && rm -rf /var/lib/apt/lists/*

# Konfiguracja SpamAssassin
RUN sa-update


# Katalogi i prawa
RUN useradd -r -g adm syslog


RUN freshclam && \
    mkdir -p /var/run/clamav && \
    chown clamav:clamav /var/run/clamav
    

# Konfiguracja katalogów certyfikatów i logów (usunięto hardkodowaną domenę)
RUN mkdir -p /etc/letsencrypt/live /var/log && \
    touch /var/log/mail.log && \
    chown syslog:adm /var/log/mail.log && \
    chmod 640 /var/log/mail.log

# Skrypty i konfiguracje
COPY scripts/start.sh scripts/update-certs.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/*.sh
COPY postfix/main.cf.template postfix/main.cf.template.test postfix/master.cf postfix/transport /etc/postfix/
RUN mkdir -p /etc/postfix/sasl
COPY postfix/sasl/smtpd.conf /etc/postfix/sasl/
COPY amavis/15-content_filter_mode /etc/amavis/conf.d/
COPY supervisord.conf /etc/supervisor/conf.d/
COPY crontab /etc/cron.d/certbot-renew

# Ustawienie właściciela i uprawnień dla konfiguracji Postfix
RUN chown -R root:root /etc/postfix && \
    chmod 644 /etc/postfix/main.cf.template /etc/postfix/master.cf && \
    chmod 755 /etc/postfix

COPY opendkim/opendkim.conf /etc/opendkim.conf
# Katalog z kluczami DKIM
COPY opendkim/keys /etc/opendkim/keys/
# Zapewnienie uprawnień dla OpenDKIM
RUN mkdir -p /var/run/opendkim && \
    chown opendkim:opendkim /var/run/opendkim && \
    chmod 750 /var/run/opendkim
# Upewnij się, że opendkim jest w grupie postfix (jeśli używasz socketów plikowych)
RUN usermod -a -G opendkim postfix

# Konfiguracja syslog-ng
COPY syslog-ng.conf /etc/syslog-ng/syslog-ng.conf
RUN mkdir -p /var/log/syslog-ng && \
    chown syslog:adm /var/log/syslog-ng && \
    chmod 750 /var/log/syslog-ng

# do testów - własny certyfikat
COPY certs/mail.pem /etc/postfix/
# root - domyślny, ale można zmienić na specyficznego usera dla procesów
# wskazane ze względów bezpieczeństwa

USER root

EXPOSE 25 587 465 80

# Dodano: HEALTHCHECK dla monitorowania (sugestia)
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:80/ || exit 1

#postfix check
#postfix reload || true

ENTRYPOINT ["/usr/local/bin/start.sh"]
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]
