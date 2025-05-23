FROM fedora:42

RUN dnf install -y \
    bpftool \
    civetweb \
    iproute \
    iputils \
    ca-certificates \
    && dnf clean all

WORKDIR /app

COPY src/main ./main
COPY bpf/containerSpy.bpf.o ./containerSpy.bpf.o

EXPOSE 8080

CMD ["./main"]
