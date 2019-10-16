/* radare2 - LGPL - Copyright 2019 - v3l0c1r4pt0r */

#include <r_asm.h>
#include <r_lib.h>

/** Default mask for opcode */
const int INSN_OPCODE_MASK = 0b111111 << 26;
const int INSN_OPCODE_SHIFT = 26;

static int disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	ut32 insn, opcode;
	ut8 opcode_idx;
	char *line = NULL;
	op->size = -1;

	if (len < 4) {
		line = sdb_fmt("invalid");
		r_strbuf_set (&op->buf_asm, line);
		return op->size;
	}

	/* read instruction and basic opcode value */
	insn = r_read_be32(buf);
	op->size = 4;
	opcode = (insn & INSN_OPCODE_MASK);
	opcode_idx = opcode >> INSN_OPCODE_SHIFT;

	line = sdb_fmt("unk%x 0", opcode_idx);
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
