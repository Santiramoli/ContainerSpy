FROM fedora:42

# Instala dependencias necesarias para compilación y ejecución
RUN dnf install -y \
    bpftool \
    civetweb \
    iproute \
    iputils \
    ca-certificates \
    gcc \
    make \
    cmake \
    wget \
    libbpf-devel \
    elfutils-libelf-devel \
    zlib-devel \
    && dnf clean all

WORKDIR /tmp

# Descarga, extrae y compila zlog 1.2.18
RUN wget https://github.com/HardySimpson/zlog/archive/refs/tags/1.2.18.tar.gz \
    && tar -zxvf 1.2.18.tar.gz \
    && cd zlog-1.2.18 \
    && make \
    && make install

# Limpieza para reducir tamaño de imagen
RUN rm -rf /tmp/zlog-1.2.18 /tmp/1.2.18.tar.gz

WORKDIR /app

# Copia binario, BPF object y configuración
COPY src/main ./main
COPY bpf/containerSpy.bpf.o ./containerSpy.bpf.o
COPY src/zlog.conf ./zlog.conf

# Crea directorio para logs y permisos
RUN mkdir -p /var/log/containerSpy && chmod 750 /var/log/containerSpy

# Añade librería zlog a la ruta de búsqueda
ENV LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH

EXPOSE 8080

CMD ["./main"]
