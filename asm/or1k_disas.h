/* radare2 - LGPL - Copyright 2019 - v3l0c1r4pt0r */

#include <r_lib.h>

#ifndef OR1K_DISAS_H
#define OR1K_DISAS_H

/** Default mask for opcode */
const int INSN_OPCODE_MASK;
const int INSN_OPCODE_SHIFT;

/** Empty mask for unused operands */
const ut32 INSN_EMPTY_MASK;
const ut32 INSN_EMPTY_SHIFT;

/** Mask for N operand */
const ut32 INSN_N_MASK;

/** Shift for D operand */
const ut32 INSN_D_SHIFT;
/** Mask for D operand */
const ut32 INSN_D_MASK;

/** Mask for K operand */
const ut32 INSN_K_MASK;

/** Mask for K operand */
const ut32 INSN_DK_K_MASK;

/** Shift for B operand */
const ut32 INSN_B_SHIFT;
/** Mask for B operand */
const ut32 INSN_B_MASK;

/** Shift for A operand */
const ut32 INSN_A_SHIFT;
/** Mask for A operand */
const ut32 INSN_A_MASK;

/** Mask for I operand */
const ut32 INSN_I_MASK;

/** Mask for L operand */
const ut32 INSN_L_MASK;

/** Shift for first K operand */
const ut32 INSN_K1_SHIFT;
/** Mask for first K operand */
const ut32 INSN_K1_MASK;

/** Mask for second K operand */
const ut32 INSN_K2_MASK;

typedef enum insn_type {
	INSN_END = 0, /**< end of array indicator */
	INSN_INVAL = 0, /**< invalid opcode */
	INSN_X, /**< no operands */
	INSN_N, /**< 26-bit immediate */
	INSN_DN, /**< 5-bit destination register, then 26-bit immediate */
	INSN_K, /**< 16-bit immediate */
	INSN_DK, /**< 5-bit destination register, then 16-bit immediate */
	INSN_D, /**< 5-bit destination register */
	INSN_B, /**< 5-bit source register */
	INSN_AI, /**< 5-bit source register, then 16-bit immediate */
	INSN_DAI, /**< 5-bit destination register, 5-bit source register, then 16-bit
							immediate */
	INSN_DAK, /**< 5-bit destination register, 5-bit source register, then 16-bit
							immediate */
	INSN_DAL, /**< 5-bit destination register, 5-bit source register, then 6-bit
							immediate */
	INSN_KABK, /**< 5-bit MSB of immediate, 5-bit source register, 5-bit source
							 register, then 11-bit rest of immediate */
	INSN_AB, /**< 5-bit source register, then 5-bit source register */
	INSN_DA, /**< 5-bit destination register, then 5-bit source register */
	INSN_DAB, /**< 5-bit destination register, 5-bit source register, then 5-bit
							source register */
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
	INSN_OPER_L, /**< 6-bit immediate */
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
	int opcode_mask;
} insn_extra_t;

typedef struct {
	ut32 opcode;
	char *name;
	int type;
	insn_extra_t *extra;
} insn_t;

extern insn_type_descr_t types[];
extern size_t types_count;

extern insn_extra_t extra_0x5[];
extern insn_extra_t extra_0x6[];
extern insn_extra_t extra_0x8[];
extern insn_extra_t extra_0x2e[];
extern insn_extra_t extra_0x2f[];
extern insn_extra_t extra_0x31[];
extern insn_extra_t extra_0x32[];
extern insn_extra_t extra_0x38[];
extern insn_extra_t extra_0x39[];

extern insn_t insns[];
extern size_t insns_count;

insn_extra_t *find_extra_descriptor(insn_extra_t *extra_descr, ut32 insn);

#endif /* OR1K_DISAS_H */
