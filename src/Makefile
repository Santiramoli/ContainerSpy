CC      := gcc
CFLAGS  := -g -O2 -I. -I/usr/local/include $(shell pkg-config --cflags libbpf civetweb)
LDFLAGS := $(shell pkg-config --libs libbpf civetweb) -lelf -lz -L/usr/local/lib -lzlog -lpthread

TARGET  := main
SRCS    := main.c utils.c handle_event.c metrics.c http_server.c

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SRCS)
	@echo "Eliminando versión anterior de '$(TARGET)'..."
	@rm -f $@
	@echo "Compilando '$(TARGET)'..."
	$(CC) $(CFLAGS) $(SRCS) -o $(TARGET) $(LDFLAGS)
	@echo "'$(TARGET)' compilado con éxito."

clean:
	@echo "Limpiando..."
	@rm -f $(TARGET)
