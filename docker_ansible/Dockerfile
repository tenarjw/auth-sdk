# Dockerfile: ansible-runner:custom
FROM python:3.11-slim

# metadata
LABEL maintainer="you@example.com"
ENV ANSIBLE_DEVEL_WARNING=False \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# instalacja system deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    ssh-client \
    git \
    build-essential \
    gcc \
    libffi-dev \
    libssl-dev \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# utwórz użytkownika nie-root
RUN useradd -m -s /bin/bash ansible

# zainstaluj ansible-core i ansible-runner i kolekcje społecznościowe
RUN pip install --no-cache-dir pip setuptools wheel \
    && pip install --no-cache-dir "ansible-core>=2.15" ansible-runner ansible-lint \
    && ansible-galaxy collection install community.docker

# dodaj katalogi runtime
RUN mkdir -p /runner/project /runner/inventory /runner/artifacts /home/ansible/.ssh \
    && chown -R ansible:ansible /runner /home/ansible

WORKDIR /runner/project
USER ansible

# ENTRYPOINT: uruchom ansible-runner lub ansible-playbook bezpośrednio
#ENTRYPOINT ["ansible-playbook"]

CMD []
ENTRYPOINT ["bash","-lc"]
