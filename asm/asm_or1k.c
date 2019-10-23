/* radare2 - LGPL - Copyright 2019 - v3l0c1r4pt0r */

#include <r_asm.h>
#include <r_lib.h>
#include <or1k_disas.h>

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

static inline int has_type_descriptor(insn_type_t type) {
	return types + types_count > &types[type];
}

static inline int is_type_descriptor_defined(insn_type_t type) {
	return types[type].type == type;
}

static inline insn_type_t type_of_opcode(insn_t *descr, insn_extra_t *extra_descr) {
	r_return_val_if_fail (descr, INSN_END);

	if (extra_descr == NULL) {
		return descr->type;
	} else {
		return extra_descr->type;
	}
}

int insn_to_str(RAsm *a, char **line, insn_t *descr, insn_extra_t *extra, ut32 insn) {
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
	insn_type_t type = type_of_opcode(descr, extra);
	insn_type_descr_t *type_descr = &types[INSN_X];

	/* only use type descriptor if it has some useful data */
	if (has_type_descriptor(type) && is_type_descriptor_defined(type)) {
		type_descr = &types[type];
	}

	o.rd = get_operand_value(insn, type_descr, INSN_OPER_D);
	o.ra = get_operand_value(insn, type_descr, INSN_OPER_A);
	o.rb = get_operand_value(insn, type_descr, INSN_OPER_B);
	o.k1 = get_operand_value(insn, type_descr, INSN_OPER_K1);
	o.k2 = get_operand_value(insn, type_descr, INSN_OPER_K2);
	o.n = get_operand_value(insn, type_descr, INSN_OPER_N);
	o.k = get_operand_value(insn, type_descr, INSN_OPER_K);
	o.i = get_operand_value(insn, type_descr, INSN_OPER_I);
	o.l = get_operand_value(insn, type_descr, INSN_OPER_L);

	name = (extra == NULL) ? descr->name : extra->name;

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
	case INSN_K:
		*line = sdb_fmt(type_descr->format, name, o.k);
		break;
	case INSN_DK:
		*line = sdb_fmt(type_descr->format, name, o.rd, o.k);
		break;
	case INSN_DN:
		*line = sdb_fmt(type_descr->format, name, o.rd, o.n);
		break;
	case INSN_B:
		*line = sdb_fmt(type_descr->format, name, o.rb);
		break;
	case INSN_D:
		*line = sdb_fmt(type_descr->format, name, o.rd);
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
	case INSN_DAL:
		*line = sdb_fmt(type_descr->format, name, o.rd, o.ra, o.l);
		break;
	case INSN_DA:
		*line = sdb_fmt(type_descr->format, name, o.rd, o.ra);
		break;
	case INSN_DAB:
		*line = sdb_fmt(type_descr->format, name, o.rd, o.ra, o.rb);
		break;
	case INSN_AB:
		*line = sdb_fmt(type_descr->format, name, o.ra, o.rb);
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
	insn_extra_t *extra_descr;

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
	if (opcode_idx >= insns_count) {
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

	/* if name is null, but extra is present, it means 6 most significant bits
	 * are not enough to decode instruction */
	if ((insn_descr->name == NULL) && (insn_descr->extra != NULL)) {
		if ((extra_descr = find_extra_descriptor(insn_descr->extra, insn)) != NULL) {
			insn_to_str(a, &line, insn_descr, extra_descr, insn);
		}
		else {
			line = sdb_fmt("invalid");
		}
		r_strbuf_set (&op->buf_asm, line);
	}
	else {
		/* otherwise basic descriptor is enough */
		insn_to_str(a, &line, insn_descr, NULL, insn);
		r_strbuf_set (&op->buf_asm, line);
	}

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
