### Budowanie obrazu kontenera

Dokumentacja polecenia `docker build`: [https://docs.docker.com/engine/reference/commandline/build/](https://docs.docker.com/engine/reference/commandline/build/)

Najczęściej wykonujemy komendę w katalogu w którym znajduje się plik Dockerfile z definicją kontenera. Wówczas komenda budowania wygląda następująco:

```
docker build -t <identyfikator> .
```

gdzie &lt;identyfikator&gt; jest nazwą, której można później używać w operacjach na obrazie.

**Przykład Dockerfile**
```
FROM python:3.10-slim
WORKDIR /app
COPY . .
RUN pip install -r requirements.txt
CMD ["python", "app.py"]
```

### Lista obrazów w systemie

```
docker images
```

[https://docs.docker.com/engine/reference/commandline/images/](https://docs.docker.com/engine/reference/commandline/images/)

### Uruchomienie nowego kontenera

Docker tworzy kontener na podstawie wskazanego obrazu i uruchamia w nim wskazaną komendę \(CMD/ENTRYPOINT\). Kontener kończy działanie, gdy zakończy się proces główny uruchomiony powyższą komendą. Można to wymusić komendą `docker stop`.

```
docker run <image>
docker run --name <name> <image>
```

[https://docs.docker.com/engine/reference/commandline/run/](https://docs.docker.com/engine/reference/commandline/run/)

Jeśli podamy nazwę – łatwiej nam będzie odwoływać się do uruchomionego kontenera poprzez tą nazwę. Jednak nazwa ta musi być jednoznaczna \(nie możesz uruchomić dwóch kontenerów z taką samą nazwą\). Zamiast nazwą możemy operować identyfikatorem \(ID\), który Docker generuje w sposób jednoznaczny.

Kontener uruchamiamy w tle \(jako demon – parametr -d\) albo  trybie interaktywnym \(-i\). Gdy chcemy  coś wykonać w terminalu do parametru `-i` dodajemy `t` \(-it\). W trybie interaktywnym najczęściej chcemy, aby usunąć kontener  po zakończeniu \(`docker ps -a` go nie wykaże\). Wtedy  uruchamiamy go z parametrem `--rm`.

Przykład:

```
docker run -it --rm test /bin/bash
```
W tym przykładzie `/bin/bash` uruchamia interaktywną powłokę w kontenerze, co jest przydatne do debugowania.

Inne ważne parametry:

`--env` – ustawianie zmiennych środowiska wewnątrz kontenera

`--volume` – mapowanie wolumenów

`--port` – mapowanie portów

Mapowanie polega na utożsamieniu wolumenów lub portów wewnątrz kontenera  z odpowiednim folderem lub portem serwera.

### Zatrzymanie kontenera

```
docker stop <container>
```

gdzie &lt;container&gt; to nazwa lub identyfikator kontenera.

[https://docs.docker.com/engine/reference/commandline/stop/](https://docs.docker.com/engine/reference/commandline/stop/)

### Lista kontenerów obecnych w systemie.

[https://docs.docker.com/engine/reference/commandline/ps/](https://docs.docker.com/engine/reference/commandline/ps/)

Tylko kontenery uruchomione:

```
docker ps
```

Wszystkie \(także zatrzymane\) kontenery:

```
docker ps -a
```

### Pobierz obraz z rejestru

```
docker pull <image>
```

[https://docs.docker.com/engine/reference/commandline/pull/](https://docs.docker.com/engine/reference/commandline/pull/)

Rejestr może być prywatny \(wtedy podajemy jego adres url w parametrze\), albo \(domyślnie\) publiczny : [https://hub.docker.com/](https://hub.docker.com/)

**Usunięcie kontenera**

```
docker rm <container>
```

Jeśli kontener nie jest zatrzymany – wymuś jego zatrzymanie

```
docker rm <container> -f
```

[https://docs.docker.com/engine/reference/commandline/rm/](https://docs.docker.com/engine/reference/commandline/rm/)

### Usunięcie obrazu

```
docker rmi <image>
docker image rm <image>
```

[https://docs.docker.com/engine/reference/commandline/rmi/](https://docs.docker.com/engine/reference/commandline/rmi/)

## Tworzenie sieci

Jeśli kilka kontenerów współpracuje ze sobą, muszą się komunikować przez wspólną sieć. Wspólną sieć deklarujemy poleceniem:

```
docker network create <nazwa sieci>
```

[https://docs.docker.com/engine/reference/commandline/network/](https://docs.docker.com/engine/reference/commandline/network/)

Przykład – wspólna sieć dla kontenerów mariadb i phpmyadmin:

```
# obrazy dla bazy danych i phpMyAdmin
docker pull mariadb
docker pull phpmyadmin:latest

# wspólna sieć
docker network create my-network

# mysql
docker run --name mariadb --network my-network -p 3306:3306 -e MARIADB_ROOT_PASSWORD=secret -d mariadb:latest

# phpMyAdmin
docker run --name phpmyadmin --network my-network -p 8080:80 -d phpmyadmin:latest
```
W powyższym przykładzie `phpmyadmin` automatycznie wykryje `mariadb` w tej samej sieci po nazwie \(mariadb jako alias DNS\).

Czasem musimy przy uruchomieniu ustawić parametry systemu przy starcie kontenera \(docker run\).  Użyteczne mogą być do tego opcje:

`--sysctl` – odpowiednik sysctl w Linux

`--device` – definicja urządzenia

`--cap-add` – uprawnienia

Przykład:

```
sudo docker run -it --cap-add=NET_ADMIN --device /dev/net/tun kontener start
```
