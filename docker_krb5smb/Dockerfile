FROM debian:bookworm

USER root

# Instalacja potrzebnych pakietów
RUN apt-get update && apt-get install -y \
    samba \
    smbclient \
    winbind \
    ldb-tools \
    samba-dsdb-modules \
    python3-samba \
    libnss-winbind \
    libpam-winbind \
    krb5-user \
    openssh-server \
    supervisor \
    locales \
    dialog \
    dnsutils \
    attr \
    acl \
    libpam-krb5 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Ustaw hostname
RUN echo "smb4" > /etc/hostname \
 && echo "127.0.0.1 smb4 localhost smb4.example.com" >> /etc/hosts

# Konfiguracja NSS dla Winbind
RUN echo "passwd: files winbind" > /etc/nsswitch.conf && \
    echo "group: files winbind" >> /etc/nsswitch.conf && \
    echo "shadow: files" >> /etc/nsswitch.conf && \
    echo "hosts: files dns" >> /etc/nsswitch.conf && \
    echo "networks: files" >> /etc/nsswitch.conf && \
    echo "protocols: db files" >> /etc/nsswitch.conf && \
    echo "services: db files" >> /etc/nsswitch.conf && \
    echo "ethers: db files" >> /etc/nsswitch.conf && \
    echo "rpc: db files" >> /etc/nsswitch.conf

# Kopiowanie konfiguracji Samby
COPY smb.conf /etc/samba/smb.conf
COPY krb5.conf /etc/krb5.conf

# Tworzenie katalogów z bezpiecznymi uprawnieniami (Samba ustawi własne ACL)
RUN mkdir -p /var/lib/samba/sysvol /var/lib/samba/private /srv/samba/share /var/log/samba /home/EXAMPLE/administrator
RUN chmod 755 /var/lib/samba && \
    chmod 700 /var/lib/samba/private && \
    chown -R root:root /var/lib/samba /home/EXAMPLE/administrator

# Test wsparcia ACL – na etapie budowy, aby w logach było widać brak
RUN touch /tmp/acltest && setfacl -m u:root:rwx /tmp/acltest && rm /tmp/acltest

# Konfiguracja PAM dla SSH
RUN echo "auth sufficient pam_krb5.so try_first_pass" > /etc/pam.d/sshd && \
    echo "auth required pam_unix.so try_first_pass" >> /etc/pam.d/sshd && \
    echo "account sufficient pam_krb5.so" >> /etc/pam.d/sshd && \
    echo "account required pam_unix.so" >> /etc/pam.d/sshd && \
    echo "session required pam_mkhomedir.so skel=/etc/skel/ umask=0077" >> /etc/pam.d/sshd && \
    echo "session required pam_limits.so" >> /etc/pam.d/sshd

# Konfiguracja SSH
RUN mkdir -p /var/run/sshd && chmod 755 /var/run/sshd && \
    ssh-keygen -A && \
    PASSWORD=$(openssl passwd -6 password) && usermod --password "$PASSWORD" root && \
    sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    sed -i 's/#GSSAPIAuthentication no/GSSAPIAuthentication yes/' /etc/ssh/sshd_config && \
    sed -i 's/#GSSAPICleanupCredentials yes/GSSAPICleanupCredentials yes/' /etc/ssh/sshd_config && \
    echo "UsePAM yes" >> /etc/ssh/sshd_config && \
    echo "KerberosAuthentication yes" >> /etc/ssh/sshd_config && \
    echo "KerberosOrLocalPasswd yes" >> /etc/ssh/sshd_config && \
    echo "KerberosTicketCleanup yes" >> /etc/ssh/sshd_config && \
    echo "LogLevel DEBUG3" >> /etc/ssh/sshd_config

# Konfiguracja supervisord
COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf

# Skrypt startowy
COPY start.sh /start.sh
RUN chmod +x /start.sh

# Strefa czasowa
ENV TZ=Europe/Warsaw
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

# Porty usług Samby/SSH/AD (bez DNS, bo wyłączony)
EXPOSE 22 88 135 137-139 445 389 636 464 3268-3269

# Przykładowe skrypty
COPY examples /examples
RUN chmod +x /examples/*.sh

# WAŻNE:
#  - Uruchamiaj kontener z bind-mountem na /var/lib/samba z systemu plików
#    hosta z włączonym ACL (ext4/xfs) oraz z uprawnieniami:
#    docker run --cap-add SYS_ADMIN --security-opt apparmor:unconfined \
#       -v /srv/samba-data:/var/lib/samba your-image
#
CMD ["/start.sh"]