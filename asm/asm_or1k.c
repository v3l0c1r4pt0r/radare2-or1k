/* radare2 - LGPL - Copyright 2019 - v3l0c1r4pt0r */

#include <r_asm.h>
#include <r_lib.h>

static int disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	char *line = sdb_fmt("invalid");
	op->size = -1;
	r_strbuf_set(&op->buf_asm, line);
	return op->size;
}

RAsmPlugin r_asm_plugin_or1k = {
	.name = "or1k",
	.desc = "OpenRISC 1000",
	.license = "LGPL3",
	.arch = "or1k",
	.bits = 32,
	.endian = R_SYS_ENDIAN_BIG,
	.fini = NULL,
	.disassemble = &disassemble,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM, .data = &r_asm_plugin_or1k, .version = R2_VERSION};
#endif
