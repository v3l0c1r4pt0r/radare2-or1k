/* radare2 - LGPL - Copyright 2019 - v3l0c1r4pt0r */

#include <r_asm.h>
#include <r_lib.h>

/** Default mask for opcode */
const int INSN_OPCODE_MASK = 0b111111 << 26;
const int INSN_OPCODE_SHIFT = 26;

typedef enum insn_type {
	INSN_END = 0, /**< end of array indicator */
	INSN_INVAL = 0, /**< invalid opcode */
	INSN_X, /**< no operands */
} insn_type_t;

typedef struct {
	ut32 opcode;
	char *name;
	int type;
} insn_t;

insn_t insns[] = {
	[0x09] = {(0x09<<26), "l.rfe", INSN_X},
};

int insn_to_str(RAsm *a, char **line, insn_t *descr, ut32 insn) {
	char *name;
	insn_type_t type = descr->type;

	name = descr->name;

	switch (type) {
	case INSN_X:
		*line = sdb_fmt("%s", name);
		break;
	default:
		*line = sdb_fmt("invalid");
	}
	return 4;
}

static int disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	ut32 insn, opcode;
	ut8 opcode_idx;
	char *line = NULL;
	insn_t *insn_descr;

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

	/* make sure instruction descriptor table is not overflowed */
	if (opcode_idx >= sizeof(insns)/sizeof(insn_t)) {
		line = sdb_fmt("invalid");
		r_strbuf_set (&op->buf_asm, line);
		return op->size;
	}

	/* if instruction is marked as invalid finish processing now */
	insn_descr = &insns[opcode_idx];
	if (insn_descr->type == INSN_INVAL) {
		line = sdb_fmt("invalid");
		r_strbuf_set (&op->buf_asm, line);
		return op->size;
	}

	/* handle at least basic cases */
	insn_to_str(a, &line, insn_descr, insn);
	r_strbuf_set (&op->buf_asm, line);
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
