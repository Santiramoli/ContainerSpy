# Makefile

# Herramientas
BPF_CLANG := clang
BPFTOOL   := bpftool

# Flags para la compilación de eBPF
BPF_CFLAGS := -O2 -g -target bpf -D__TARGET_ARCH_x86_64 $(shell pkg-config --cflags libbpf)


# Ficheros
BPF_SRC := containerSpy.bpf.c
BPF_OBJ := containerSpy.bpf.o
SKEL    := containerSpy.skel.h

.PHONY: all clean

all: $(BPF_OBJ) $(SKEL)

$(BPF_OBJ): $(BPF_SRC)
	@echo ">>> Compilando eBPF object $@"
	$(BPF_CLANG) $(BPF_CFLAGS) -c $< -o $@

$(SKEL): $(BPF_OBJ)
	@echo ">>> Generando skeleton $@"
	$(BPFTOOL) gen skeleton $< > $@

clean:
	@echo ">>> Limpiando artefactos..."
	-rm -f $(BPF_OBJ) $(SKEL)
