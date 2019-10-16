/* radare2 - LGPL - Copyright 2019 - v3l0c1r4pt0r */
#include <r_asm.h>
#include <r_anal.h>
#include <r_lib.h>

static int or1k_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *b, int len) {
	r_strbuf_init (&op->esil);
	op->size = 4;
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
