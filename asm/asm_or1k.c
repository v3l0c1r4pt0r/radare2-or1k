/* radare2 - LGPL - Copyright 2019 - v3l0c1r4pt0r */

#include <r_asm.h>
#include <r_lib.h>

/** Default mask for opcode */
const int INSN_OPCODE_MASK = 0b111111 << 26;
const int INSN_OPCODE_SHIFT = 26;

/** Empty mask for unused operands */
const ut32 INSN_EMPTY_MASK = 0;
const ut32 INSN_EMPTY_SHIFT = 0;

/** Mask for N operand */
const ut32 INSN_N_MASK = 0b11111111111111111111111111;

/** Shift for B operand */
const ut32 INSN_B_SHIFT = 11;
/** Mask for B operand */
const ut32 INSN_B_MASK = 0b11111 << INSN_B_SHIFT;

typedef enum insn_type {
	INSN_END = 0, /**< end of array indicator */
	INSN_INVAL = 0, /**< invalid opcode */
	INSN_X, /**< no operands */
	INSN_N, /**< 26-bit immediate */
	INSN_B, /**< 5-bit source register */
} insn_type_t;

typedef enum {
	INSN_OPER_B, /**< 5-bit source register */
	INSN_OPER_N, /**< 26-bit immediate */
	INSN_OPER_SIZE /**< number of operand types */
} insn_oper_t;

typedef struct {
	int oper;
	ut32 mask;
	ut32 shift;
} insn_oper_descr_t;

typedef struct {
	int type;
	char *format;
	insn_oper_descr_t operands[INSN_OPER_SIZE];
} insn_type_descr_t;

typedef struct {
	ut32 opcode;
	char *name;
	int type;
} insn_t;

insn_type_descr_t types[] = {
	[INSN_X] = {INSN_X, "%s",
		{
		}
	},
	/* ------NNNNNNNNNNNNNNNNNNNNNNNNNN */
	[INSN_N] = {INSN_N, "%s 0x%x",
		{
			[INSN_OPER_N] = {INSN_OPER_N, INSN_N_MASK, INSN_EMPTY_SHIFT},
		}
	},
	/* ----------------BBBBB----------- */
	[INSN_B] = {INSN_B, "%s r%d",
		{
			[INSN_OPER_B] = {INSN_OPER_B, INSN_B_MASK, INSN_B_SHIFT},
		}
	},
};

insn_t insns[] = {
	[0x00] = {(0x00<<26), "l.j", INSN_N},
	[0x09] = {(0x09<<26), "l.rfe", INSN_X},
	[0x11] = {(0x11<<26), "l.jr", INSN_B},
};

/**
 * \brief Performs sign extension of number
 *
 * \param number number to extend
 * \param mask mask under which number is placed
 *
 * \return sign-extended number
 *
 * If mask does not begin on the lsb, space on the right will also be filled with ones
 *
 */
static ut32 sign_extend(ut32 number, ut32 mask) {
	/* xor of mask with itself shifted left detects msb of mask and msb of space
	 * on the right. And discards the latter */
	ut32 first_bit = (mask ^ (mask >> 1)) & mask;
	/* if first bit is set */
	if (number & first_bit) {
		/* set every bit outside mask */
		number |= ~mask;
	}
	return number;
}

static inline ut32 get_operand_mask(insn_type_descr_t *type_descr, insn_oper_t operand) {
	return type_descr->operands[operand].mask;
}

static inline ut32 get_operand_shift(insn_type_descr_t *type_descr, insn_oper_t operand) {
	return type_descr->operands[operand].shift;
}

static inline ut32 get_operand_value(ut32 insn, insn_type_descr_t *type_descr, insn_oper_t operand) {
	return (insn & get_operand_mask(type_descr, operand)) >> get_operand_shift(type_descr, operand);
}


int insn_to_str(RAsm *a, char **line, insn_t *descr, ut32 insn) {
	struct {
	ut32 rd;
	ut32 ra;
	ut32 rb;
	ut32 n;
	ut32 k1;
	ut32 k2;
	ut32 k;
	ut32 i;
	ut32 l;
	} o = {};
	char *name;
	insn_type_t type = descr->type;
	insn_type_descr_t *type_descr = &types[type];

	o.rb = get_operand_value(insn, type_descr, INSN_OPER_B);
	o.n = get_operand_value(insn, type_descr, INSN_OPER_N);

	name = descr->name;

	switch (type) {
	case INSN_X:
		*line = sdb_fmt(type_descr->format, name);
		break;
	case INSN_N:
		*line = sdb_fmt(type_descr->format, name,
				(sign_extend(o.n, type_descr->operands[INSN_OPER_N].mask) << 2) + a->pc);
		break;
	case INSN_B:
		*line = sdb_fmt(type_descr->format, name, o.rb);
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
