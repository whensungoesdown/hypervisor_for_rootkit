.CODE

NtCreateFileTrampoline PROC

	mov r11,rsp
	sub rsp,88h
	xor eax,eax
	mov qword ptr [r11-10h],rax
	
	; 15 bytes
	dw 0
	dw 0
	dw 0
	dw 0
	db 0
	
	int 3
	int 3
	int 3
	int 3
	int 3

NtCreateFileTrampoline ENDP

; kbdclass!KeyboardClassServiceCallback:
; fffff880`02fa7990 4c8bdc          mov     r11,rsp
; fffff880`02fa7993 49895b08        mov     qword ptr [r11+8],rbx
; fffff880`02fa7997 49896b10        mov     qword ptr [r11+10h],rbp
; fffff880`02fa799b 49897318        mov     qword ptr [r11+18h],rsi
; fffff880`02fa799f 57              push    rdi
; fffff880`02fa79a0 4154            push    r12
; fffff880`02fa79a2 4155            push    r13
; fffff880`02fa79a4 4156            push    r14

KeyboardClassServiceCallbackTrampoline PROC

	mov     r11,rsp
	mov     qword ptr [r11+8],rbx
	mov     qword ptr [r11+10h],rbp
	mov     qword ptr [r11+18h],rsi
	
	; 15 bytes
	dw 0
	dw 0
	dw 0
	dw 0
	db 0
	
	int 3
	int 3
	int 3
	int 3
	int 3

KeyboardClassServiceCallbackTrampoline ENDP

END
