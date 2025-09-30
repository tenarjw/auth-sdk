FROM debian:bookworm-slim

USER root

# Instalacja pakietów: Samba, SSH oraz narzędzia do integracji z LDAP (sssd)
RUN apt-get update && apt-get install -y \
    samba \
    smbclient \
    openssh-server \
    supervisor \
    sssd \
    sssd-tools \
    ldap-utils \
    libnss-sss \
    libpam-sss \
    slapd \
    sasl2-bin \
    libsasl2-2 \
    libsasl2-modules-ldap \
    iputils-ping \
    netcat-traditional \
    net-tools \
    locales \
    dialog \
    dnsutils \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Konfiguracja SSH
RUN mkdir -p /var/run/sshd && \
    ssh-keygen -A && \
    echo 'root:Haslo123!' | chpasswd && \
    sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/UsePAM yes/UsePAM yes/' /etc/ssh/sshd_config # Upewniamy się, że PAM jest włączony

# Kopiowanie plików konfiguracyjnych
COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf
COPY sssd.conf /etc/sssd/sssd.conf
COPY smb.conf /etc/samba/smb.conf
COPY entrypoint.sh /entrypoint.sh

# Nadanie uprawnień
RUN chmod 600 /etc/sssd/sssd.conf && \
    chmod +x /entrypoint.sh

# Tworzenie udziału
RUN mkdir -p /srv/samba/share

# Przykładowe skrypty
COPY examples /examples
RUN chmod +x /examples/*.sh

CMD ["/entrypoint.sh"]
