.section .rodata
.balign 16

#ifndef EMBED_SU_PATH
#define EMBED_SU_PATH "build/embed/su_daemon_aarch64_pie"
#endif

.global embedded_su_start
.type embedded_su_start, %object
embedded_su_start:
.incbin EMBED_SU_PATH

.global embedded_su_end
.type embedded_su_end, %object
embedded_su_end:
.byte 0
