FROM debian:bookworm-slim


# Install required system packages and dependencies

## for apt to be noninteractive
ENV DEBIAN_FRONTEND noninteractive
ENV DEBCONF_NONINTERACTIVE_SEEN true

## preesed tzdata, update package index, upgrade packages and install needed software
RUN echo "tzdata tzdata/Areas select Europe" > /tmp/preseed.txt; \
    echo "tzdata tzdata/Zones/Europe select Warsaw" >> /tmp/preseed.txt; \
    debconf-set-selections /tmp/preseed.txt && \
    apt-get update && \
    apt-get install -y tzdata


RUN apt-get update && apt-get install -y \
    acl ca-certificates curl gzip libc6 libgcc1 libltdl7 liblz4-1 \
    libnss3-tools libsasl2-2 libsnappy1v5 libstdc++6 libwiredtiger0 \
    libwrap0 libzstd1 lsof mdbtools procps tar zlib1g locales

# fix locale
RUN  echo "pl_PL.UTF-8 UTF-8" >> /etc/locale.gen \
  &&  apt install -y locales \
  &&  locale-gen pl_PL  \
  &&  update-locale LANG=pl_PL.UTF-8 LC_CTYPE=pl_PL.UTF-8  

RUN apt-get update && apt-get install -y \
    ldap-utils libsasl2-modules libsasl2-modules-db \
    libsasl2-modules-gssapi-mit  libsasl2-modules-ldap  libsasl2-modules-otp \
    libsasl2-modules-sql openssl slapd slapd-contrib

COPY rootfs /

# Expose default ldap and ldaps ports
EXPOSE 389 636


ADD entrypoint.sh /
ENTRYPOINT [ "/entrypoint.sh" ]
