section .data
str: db 'Hello world!', 0xa
strlen:  equ $-str
strp: dq str
spthing: dq 0


section .text
global _start

_start:
mov rdi, 1
mov rax, strp
mov rsi, [rax]
mov rdx, strlen
mov rax, 1
syscall

mov rdi, 13
mov rax, 231
syscall

;mov rcx, 0x100000000
;.loop:
;dec rcx
;test rcx, rcx
;jnz .loop
;mov rdi, 0
;mov rax, 231
;syscall
