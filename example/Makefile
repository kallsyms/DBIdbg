.PHONY: all
all: mini

mini: mini.S
	nasm -f elf64 mini.S -o mini.o
	ld mini.o -o mini

.PHONY: clean
clean:
	rm -f mini.o mini
