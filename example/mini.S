section .text
global _start

_start:
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
