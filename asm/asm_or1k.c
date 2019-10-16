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

/** Shift for D operand */
const ut32 INSN_D_SHIFT = 21;
/** Mask for D operand */
const ut32 INSN_D_MASK = 0b11111 << INSN_D_SHIFT;

/** Mask for K operand */
const ut32 INSN_K_MASK = 0b1111111111111111;

/** Mask for K operand */
const ut32 INSN_DK_K_MASK = 0b111111111111111111111;

/** Shift for B operand */
const ut32 INSN_B_SHIFT = 11;
/** Mask for B operand */
const ut32 INSN_B_MASK = 0b11111 << INSN_B_SHIFT;

/** Shift for A operand */
const ut32 INSN_A_SHIFT = 16;
/** Mask for A operand */
const ut32 INSN_A_MASK = 0b11111 << INSN_A_SHIFT;

/** Mask for I operand */
const ut32 INSN_I_MASK = 0b1111111111111111;

/** Shift for first K operand */
const ut32 INSN_K1_SHIFT = 21;
/** Mask for first K operand */
const ut32 INSN_K1_MASK = 0b11111 << INSN_K1_SHIFT;

/** Mask for second K operand */
const ut32 INSN_K2_MASK = 0b11111111111;

typedef enum insn_type {
	INSN_END = 0, /**< end of array indicator */
	INSN_INVAL = 0, /**< invalid opcode */
	INSN_X, /**< no operands */
	INSN_N, /**< 26-bit immediate */
	INSN_DN, /**< 5-bit destination register, then 26-bit immediate */
	INSN_B, /**< 5-bit source register */
	INSN_AI, /**< 5-bit source register, then 16-bit immediate */
	INSN_DAI, /**< 5-bit destination register, 5-bit source register, then 16-bit
							immediate */
	INSN_DAK, /**< 5-bit destination register, 5-bit source register, then 16-bit
							immediate */
	INSN_KABK, /**< 5-bit MSB of immediate, 5-bit source register, 5-bit source
							 register, then 11-bit rest of immediate */
	INSN_IABI, /**< 5-bit MSB of immediate, 5-bit source register, 5-bit source
							 register, then 11-bit rest of immediate */
	INSN_SIZE, /**< number of types */
} insn_type_t;

typedef enum {
	INSN_OPER_K1, /**< 5-bit MSBs of immediate */
	INSN_OPER_K2, /**< 11-bit LSBs of immediate */
	INSN_OPER_A, /**< 5-bit source register */
	INSN_OPER_B, /**< 5-bit source register */
	INSN_OPER_N, /**< 26-bit immediate */
	INSN_OPER_K, /**< 16-bit immediate */
	INSN_OPER_D, /**< 5-bit destination register */
	INSN_OPER_I, /**< 16-bit immediate */
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
	/* ------KKKKKAAAAABBBBBKKKKKKKKKKK */
	[INSN_KABK] = {INSN_KABK, "%s r%d, r%d, 0x%x",
		{
			[INSN_OPER_K1] = {INSN_OPER_K1, INSN_K1_MASK, INSN_K1_SHIFT},
			[INSN_OPER_A] = {INSN_OPER_A, INSN_A_MASK, INSN_A_SHIFT},
			[INSN_OPER_B] = {INSN_OPER_B, INSN_B_MASK, INSN_B_SHIFT},
			[INSN_OPER_K2] = {INSN_OPER_K2, INSN_K2_MASK, INSN_EMPTY_SHIFT},
		}
	},
	/* ------IIIIIAAAAABBBBBIIIIIIIIIII */
	[INSN_IABI] = {INSN_IABI, "%s r%d, r%d, 0x%x",
		{
			[INSN_OPER_K1] = {INSN_OPER_K1, INSN_K1_MASK, INSN_K1_SHIFT},
			[INSN_OPER_A] = {INSN_OPER_A, INSN_A_MASK, INSN_A_SHIFT},
			[INSN_OPER_B] = {INSN_OPER_B, INSN_B_MASK, INSN_B_SHIFT},
			[INSN_OPER_K2] = {INSN_OPER_K2, INSN_K2_MASK, INSN_EMPTY_SHIFT},
		}
	},
	/* ------NNNNNNNNNNNNNNNNNNNNNNNNNN */
	[INSN_N] = {INSN_N, "%s 0x%x",
		{
			[INSN_OPER_N] = {INSN_OPER_N, INSN_N_MASK, INSN_EMPTY_SHIFT},
		}
	},
	[INSN_DN] = {INSN_DN, "%s r%d, 0x%x",
		{
			[INSN_OPER_N] = {INSN_OPER_N, INSN_N_MASK, INSN_EMPTY_SHIFT},
			[INSN_OPER_D] = {INSN_OPER_D, INSN_D_MASK, INSN_D_SHIFT},
		}
	},
	/* ----------------BBBBB----------- */
	[INSN_B] = {INSN_B, "%s r%d",
		{
			[INSN_OPER_B] = {INSN_OPER_B, INSN_B_MASK, INSN_B_SHIFT},
		}
	},
	/* -----------AAAAAIIIIIIIIIIIIIIII */
	[INSN_AI] = {INSN_AI, "%s r%d, 0x%x",
		{
			[INSN_OPER_I] = {INSN_OPER_I, INSN_I_MASK, INSN_EMPTY_SHIFT},
			[INSN_OPER_A] = {INSN_OPER_A, INSN_A_MASK, INSN_A_SHIFT},
		}
	},
	/* ------DDDDDAAAAAIIIIIIIIIIIIIIII */
	[INSN_DAI] = {INSN_DAI, "%s r%d, r%d, 0x%x",
		{
			[INSN_OPER_D] = {INSN_OPER_D, INSN_D_MASK, INSN_D_SHIFT},
			[INSN_OPER_A] = {INSN_OPER_A, INSN_A_MASK, INSN_A_SHIFT},
			[INSN_OPER_I] = {INSN_OPER_I, INSN_I_MASK, INSN_EMPTY_SHIFT},
		}
	},
	/* ------DDDDDAAAAAKKKKKKKKKKKKKKKK */
	[INSN_DAK] = {INSN_DAK, "%s r%d, r%d, 0x%x",
		{
			[INSN_OPER_D] = {INSN_OPER_D, INSN_D_MASK, INSN_D_SHIFT},
			[INSN_OPER_A] = {INSN_OPER_A, INSN_A_MASK, INSN_A_SHIFT},
			[INSN_OPER_I] = {INSN_OPER_I, INSN_I_MASK, INSN_EMPTY_SHIFT},
		}
	},
};

insn_t insns[] = {
	[0x00] = {(0x00<<26), "l.j", INSN_N},
	[0x01] = {(0x01<<26), "l.jal", INSN_N},
	[0x02] = {(0x02<<26), "l.adrp", INSN_DN},
	[0x03] = {(0x03<<26), "l.bnf", INSN_N},
	[0x04] = {(0x04<<26), "l.bf", INSN_N},
	[0x07] = {(0x07<<26)},
	[0x09] = {(0x09<<26), "l.rfe", INSN_X},
	[0x0a] = {(0x0a<<26), "lv.ext0a", INSN_X}, /* TODO: implement */
	[0x0b] = {(0x0b<<26)},
	[0x0c] = {(0x0c<<26)},
	[0x0d] = {(0x0d<<26)},
	[0x0e] = {(0x0e<<26)},
	[0x0f] = {(0x0f<<26)},
	[0x10] = {(0x10<<26)},
	[0x11] = {(0x11<<26), "l.jr", INSN_B},
	[0x12] = {(0x12<<26), "l.jalr", INSN_B},
	[0x13] = {(0x13<<26), "l.maci", INSN_AI},
	[0x14] = {(0x14<<26)},
	[0x15] = {(0x15<<26)},
	[0x16] = {(0x16<<26)},
	[0x17] = {(0x17<<26)},
	[0x18] = {(0x18<<26)},
	[0x19] = {(0x19<<26)},
	[0x1a] = {(0x1a<<26), "l.lf", INSN_DAI},
	[0x1b] = {(0x1b<<26), "l.lwa", INSN_DAI},
	[0x1c] = {(0x1c<<26), "l.cust1", INSN_X},
	[0x1d] = {(0x1d<<26), "l.cust2", INSN_X},
	[0x1e] = {(0x1e<<26), "l.cust3", INSN_X},
	[0x1f] = {(0x1f<<26), "l.cust4", INSN_X},
	[0x20] = {(0x20<<26), "l.ld", INSN_DAI},
	[0x21] = {(0x21<<26), "l.lwz", INSN_DAI},
	[0x22] = {(0x22<<26), "l.lws", INSN_DAI},
	[0x23] = {(0x23<<26), "l.lbz", INSN_DAI},
	[0x24] = {(0x24<<26), "l.lbs", INSN_DAI},
	[0x25] = {(0x25<<26), "l.lhz", INSN_DAI},
	[0x26] = {(0x26<<26), "l.lhs", INSN_DAI},
	[0x27] = {(0x27<<26), "l.addi", INSN_DAI},
	[0x28] = {(0x28<<26), "l.addic", INSN_DAI},
	[0x29] = {(0x29<<26), "l.andi", INSN_DAK},
	[0x2a] = {(0x2a<<26), "l.ori", INSN_DAK},
	[0x2b] = {(0x2b<<26), "l.xori", INSN_DAI},
	[0x2c] = {(0x2c<<26), "l.muli", INSN_DAI},
	[0x2d] = {(0x2d<<26), "l.mfspr", INSN_DAK},
	[0x30] = {(0x30<<26), "l.mtspr", INSN_KABK},
	[0x33] = {(0x33<<26), "l.swa", INSN_IABI},
	[0x34] = {(0x34<<26)},
	[0x35] = {(0x35<<26), "l.sw", INSN_IABI},
	[0x36] = {(0x36<<26), "l.sb", INSN_IABI},
	[0x37] = {(0x37<<26), "l.sh", INSN_IABI},
	[0x3a] = {(0x3a<<26)},
	[0x3b] = {(0x3b<<26)},
	[0x3c] = {(0x3c<<26), "l.cust5", INSN_X},
	[0x3d] = {(0x3d<<26), "l.cust6", INSN_X},
	[0x3e] = {(0x3e<<26), "l.cust7", INSN_X},
	[0x3f] = {(0x3f<<26), "l.cust8", INSN_X},
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

	o.rd = get_operand_value(insn, type_descr, INSN_OPER_D);
	o.ra = get_operand_value(insn, type_descr, INSN_OPER_A);
	o.rb = get_operand_value(insn, type_descr, INSN_OPER_B);
	o.k1 = get_operand_value(insn, type_descr, INSN_OPER_K1);
	o.k2 = get_operand_value(insn, type_descr, INSN_OPER_K2);
	o.n = get_operand_value(insn, type_descr, INSN_OPER_N);
	o.k = get_operand_value(insn, type_descr, INSN_OPER_K);
	o.i = get_operand_value(insn, type_descr, INSN_OPER_I);

	name = descr->name;

	if (name == NULL || type_descr->format == NULL) {
		/* this should not happen, give up */
		*line = sdb_fmt("invalid");
		return 4;
	}

	switch (type) {
	case INSN_X:
		*line = sdb_fmt(type_descr->format, name);
		break;
	case INSN_N:
		*line = sdb_fmt(type_descr->format, name,
				(sign_extend(o.n, type_descr->operands[INSN_OPER_N].mask) << 2) + a->pc);
		break;
	case INSN_DN:
		*line = sdb_fmt(type_descr->format, name, o.rd, o.n);
		break;
	case INSN_B:
		*line = sdb_fmt(type_descr->format, name, o.rb);
		break;
	case INSN_AI:
		*line = sdb_fmt(type_descr->format, name, o.ra, o.i);
		break;
	case INSN_DAI:
		*line = sdb_fmt(type_descr->format, name, o.rd, o.ra, o.i);
		break;
	case INSN_DAK:
		*line = sdb_fmt(type_descr->format, name, o.rd, o.ra, o.i);
		break;
	case INSN_IABI:
		*line = sdb_fmt(type_descr->format, name,
				o.ra, o.rb, (o.k1 << 11) | o.k2);
		break;
	case INSN_KABK:
		*line = sdb_fmt(type_descr->format, name,
				o.ra, o.rb, (o.k1 << 11) | o.k2);
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
