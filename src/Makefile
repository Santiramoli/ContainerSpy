# 1. Variables de compilación
CC      := gcc
CFLAGS  := -g -O2 -I. $(shell pkg-config --cflags libbpf civetweb)
LDFLAGS := $(shell pkg-config --libs libbpf civetweb) -lelf -lz

# 2. Ejecutable y fuentes
TARGET  := main
SRCS    := main.c utils.c handle_event.c metrics.c http_server.c

.PHONY: all clean

# 4. Objetivo por defecto: compilar
all: $(TARGET)

# 5. Regla de compilación: borra y compila
$(TARGET): $(SRCS)
	@echo "Eliminando versión anterior de '$(TARGET)'..."
	@rm -f $@
	@echo "Compilando '$(TARGET)'..."
	$(CC) $(CFLAGS) $(SRCS) -o $(TARGET) $(LDFLAGS)
	@echo "'$(TARGET)' compilado con éxito."

clean:
	@echo "Limpiando..."
	@rm -f $(TARGET)
