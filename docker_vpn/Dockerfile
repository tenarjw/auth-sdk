# Użycie nowszej, stabilniejszej wersji Debiana
FROM debian:bookworm-slim

# Instalacja pakietów w jednej warstwie, co zmniejsza rozmiar obrazu
RUN apt-get update && apt-get install -y --no-install-recommends \
    openvpn \
    easy-rsa \
    openssl \
    && rm -rf /var/lib/apt/lists/*

# Kopiowanie plików konfiguracyjnych do tymczasowego katalogu
COPY server.conf /tmp/server.conf
COPY vars /tmp/vars

# Kopiowanie skryptu startowego
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# Definicja portu, na którym działa OpenVPN
EXPOSE 1194/udp

# Definicja punktu montowania, co pozwala na trwałe przechowywanie danych
VOLUME ["/etc/openvpn"]

# Definicja domyślnej komendy przy starcie kontenera
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]