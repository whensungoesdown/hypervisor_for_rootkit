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

; 
; nt!NtQuerySystemInformation:
; fffff800`02beb8fc fff3            push    rbx
; fffff800`02beb8fe 4883ec30        sub     rsp,30h
; fffff800`02beb902 83f953          cmp     ecx,53h
; fffff800`02beb905 458bd8          mov     r11d,r8d
; fffff800`02beb908 488bda          mov     rbx,rdx
; fffff800`02beb90b 448bd1          mov     r10d,ecx
; fffff800`02beb90e 7f61            jg      nt!NtQuerySystemInformation+0x75 (fffff800`02beb971)
; fffff800`02beb910 743d            je      nt!NtQuerySystemInformation+0x53 (fffff800`02beb94f)
; 

NtQuerySystemInformationTrampoline PROC

	;push    rbx 
	; sometime push rbx = 053h
	db 0ffh
	db 0f3h
	sub     rsp,30h
	cmp     ecx,53h
	mov     r11d,r8d
	mov     rbx,rdx
	
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

NtQuerySystemInformationTrampoline ENDP

END
