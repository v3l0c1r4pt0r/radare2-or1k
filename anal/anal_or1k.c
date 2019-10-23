/* radare2 - LGPL - Copyright 2019 - v3l0c1r4pt0r */

#include <r_asm.h>
#include <r_anal.h>
#include <r_lib.h>
#include <or1k_disas.h>

static int insn_to_op(RAnal *a, RAnalOp *op, ut64 addr, insn_t *descr, insn_extra_t *extra, ut32 insn) {
	if (extra == NULL) {
		op->type = descr->insn_type;
	} else {
		op->type = extra->insn_type;
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
