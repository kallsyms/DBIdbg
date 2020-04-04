section .data
str: db 'Hello world!'
strlen:  equ $-str


section .text
global _start

_start:
mov rdi, 1
mov rsi, str
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
