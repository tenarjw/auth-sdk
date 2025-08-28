FROM alpine

# install openssl
RUN apk add --update openssl sed && \
    rm -rf /var/cache/apk/* && \
    mkdir -p ca/certs/

VOLUME /ca
VOLUME /req

ADD secret.txt /
ADD entrypoint.sh /

#COPY rootfs /

ENTRYPOINT [ "/entrypoint.sh" ]
