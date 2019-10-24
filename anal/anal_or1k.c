/* radare2 - LGPL - Copyright 2019 - v3l0c1r4pt0r */

#include <r_asm.h>
#include <r_anal.h>
#include <r_lib.h>
#include <or1k_disas.h>

ut32 cpu[32] = {0}; /* register contents */
ut32 cpu_enable; /* allows to treat only registers with known value as valid */

static int insn_to_op(RAnal *a, RAnalOp *op, ut64 addr, insn_t *descr, insn_extra_t *extra, ut32 insn) {
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
	insn_type_t type = type_of_opcode(descr, extra);
	insn_type_descr_t *type_descr = &types[INSN_X];

	/* only use type descriptor if it has some useful data */
	if (has_type_descriptor(type) && is_type_descriptor_defined(type)) {
		type_descr = &types[type];
	}

	if (extra == NULL) {
		op->type = descr->insn_type;
	} else {
		op->type = extra->insn_type;
	}

	switch ((insn & INSN_OPCODE_MASK) >> INSN_OPCODE_SHIFT) {
	case 0x00: /* l.j */
		o.n = get_operand_value(insn, type_descr, INSN_OPER_N);
		op->jump = (o.n << 2) + addr;
		op->delay = 1;
		break;
	case 0x11: /* l.jr */
		o.rb = get_operand_value(insn, type_descr, INSN_OPER_B);
		if (cpu_enable & (1 << o.rb)) {
			op->jump = cpu[o.rb];
		}
		break;
	case 0x06: /* extended */
		switch (insn & (1 << 16)) {
		case 0: /* l.movhi */
			o.rd = get_operand_value(insn, type_descr, INSN_OPER_D);
			o.k = get_operand_value(insn, type_descr, INSN_OPER_K);
			cpu[o.rd] = o.k << 16;
			cpu_enable |= (1 << o.rd);
			break;
		case 1: /* l.macrc */
			break;
		}
		break;
	case 0x2a: /* l.ori */
		o.rd = get_operand_value(insn, type_descr, INSN_OPER_D);
		o.ra = get_operand_value(insn, type_descr, INSN_OPER_A);
		o.i = get_operand_value(insn, type_descr, INSN_OPER_I);
		if (cpu_enable & (1 << o.ra)) {
			cpu[o.rd] = cpu[o.ra] | o.i;
			cpu_enable |= (1 << o.rd);
			op->val = cpu[o.rd];
		}
		break;
	}

	/* temporary solution to prevent using wrong register values */
	if (op->type & R_ANAL_OP_TYPE_JMP == R_ANAL_OP_TYPE_JMP) {
		cpu_enable = 0;
	}
	return 4;
}

static int or1k_op(RAnal *a, RAnalOp *op, ut64 addr, const ut8 *data, int len, RAnalOpMask mask) {
	ut32 insn, opcode;
	ut8 opcode_idx;
	char *line = NULL;
	insn_t *insn_descr;
	insn_extra_t *extra_descr;

	op->size = -1;
	r_strbuf_init (&op->esil);

	/* read instruction and basic opcode value */
	insn = r_read_be32(data);
	op->size = 4;
	opcode = (insn & INSN_OPCODE_MASK);
	opcode_idx = opcode >> INSN_OPCODE_SHIFT;

	/* make sure instruction descriptor table is not overflowed */
	if (opcode_idx >= insns_count) {
		return op->size;
	}

	/* if instruction is marked as invalid finish processing now */
	insn_descr = &insns[opcode_idx];
	if (insn_descr->type == INSN_INVAL) {
		return op->size;
	}

	/* if name is null, but extra is present, it means 6 most significant bits
	 * are not enough to decode instruction */
	if ((insn_descr->name == NULL) && (insn_descr->extra != NULL)) {
		if ((extra_descr = find_extra_descriptor(insn_descr->extra, insn)) != NULL) {
			insn_to_op(a, op, addr, insn_descr, extra_descr, insn);
		}
		else {
		}
	}
	else {
		/* otherwise basic descriptor is enough */
		insn_to_op(a, op, addr, insn_descr, NULL, insn);
	}

	return op->size;
}

RAnalPlugin r_anal_plugin_or1k = {
	.name = "or1k",
	.desc = "OpenRISC 1000",
	.license = "LGPL3",
	.bits = 32,
	.init = NULL,
	.fini = NULL,
	.op = &or1k_op,
	.set_reg_profile = NULL,
	.fingerprint_bb = NULL,
	.fingerprint_fcn = NULL,
	.diff_bb = NULL,
	.diff_fcn = NULL,
	.diff_eval = NULL
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_or1k,
	.version = R2_VERSION
};
#endif
