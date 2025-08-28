# Using Debian 12 (Bookworm) as the base image
FROM debian:12

# Installing build dependencies for Python 3.12, libprimesieve-dev, curl, and locales
RUN apt-get update && apt-get install -y \
    libprimesieve-dev \
    curl \
    wget \
    build-essential \
    libreadline-dev \
    libncursesw5-dev \
    libssl-dev \
    libsqlite3-dev \
    tk-dev \
    libgdbm-dev \
    libc6-dev \
    libbz2-dev \
    libffi-dev \
    zlib1g-dev \
    locales \
    dialog \
    && rm -rf /var/lib/apt/lists/*

# Configuring UTF-8 locale with Polish support
RUN echo "pl_PL.UTF-8 UTF-8" > /etc/locale.gen \
    && locale-gen pl_PL.UTF-8 \
    && update-locale LANG=pl_PL.UTF-8 LC_ALL=pl_PL.UTF-8

# Setting environment variables for locale
ENV LANG=pl_PL.UTF-8 \
    LC_ALL=pl_PL.UTF-8

# Downloading and compiling Python 3.12
RUN wget https://www.python.org/ftp/python/3.12.8/Python-3.12.8.tar.xz \
    && tar -xf Python-3.12.8.tar.xz \
    && cd Python-3.12.8 \
    && ./configure --enable-optimizations \
    && make -j$(nproc) \
    && make altinstall \
    && cd .. \
    && rm -rf Python-3.12.8 Python-3.12.8.tar.xz

# Creating symlink for python3.12 as python3
RUN ln -s /usr/local/bin/python3.12 /usr/local/bin/python3

# Ensuring pip is installed for Python 3.12
RUN curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py \
    && /usr/local/bin/python3.12 get-pip.py \
    && rm get-pip.py

# Installing Python packages
RUN /usr/local/bin/python3.12 -m pip install --no-cache-dir \
    primesieve \
    numpy \
    cryptography \
    passlib \
    bcrypt \
    sympy

RUN ln -s /usr/local/bin/python3.12 /usr/local/bin/python

# Setting the working directory
#WORKDIR /app
WORKDIR /examples
COPY examples /examples

# Default command
#CMD ["/bin/bash"]
CMD ["/examples/menu.sh"]

