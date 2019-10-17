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

/** Mask for L operand */
const ut32 INSN_L_MASK = 0b111111;

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
	/* ----------------KKKKKKKKKKKKKKKK */
	[INSN_K] = {INSN_K, "%s 0x%x",
		{
			[INSN_OPER_K] = {INSN_OPER_K, INSN_K_MASK, INSN_EMPTY_SHIFT},
		}
	},
	/* ------DDDDD-----KKKKKKKKKKKKKKKK */
	[INSN_DK] = {INSN_DK, "%s r%d, 0x%x",
		{
			[INSN_OPER_K] = {INSN_OPER_K, INSN_K_MASK, INSN_EMPTY_SHIFT},
			[INSN_OPER_D] = {INSN_OPER_D, INSN_D_MASK, INSN_D_SHIFT},
		}
	},
	/* ------DDDDDNNNNNNNNNNNNNNNNNNNNN */
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
	/* ------DDDDD--------------------- */
	[INSN_D] = {INSN_D, "%s r%d",
		{
			[INSN_OPER_D] = {INSN_OPER_D, INSN_D_MASK, INSN_D_SHIFT},
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
	/* ------DDDDDAAAAA----------LLLLLL */
	[INSN_DAL] = {INSN_DAL, "%s r%d, r%d, 0x%x",
		{
			[INSN_OPER_D] = {INSN_OPER_D, INSN_D_MASK, INSN_D_SHIFT},
			[INSN_OPER_A] = {INSN_OPER_A, INSN_A_MASK, INSN_A_SHIFT},
			[INSN_OPER_L] = {INSN_OPER_L, INSN_L_MASK, INSN_EMPTY_SHIFT},
		}
	},
	/* ------DDDDDAAAAA---------------- */
	[INSN_DA] = {INSN_DA, "%s r%d, r%d",
		{
			[INSN_OPER_D] = {INSN_OPER_D, INSN_D_MASK, INSN_D_SHIFT},
			[INSN_OPER_A] = {INSN_OPER_A, INSN_A_MASK, INSN_A_SHIFT},
		}
	},
	/* ------DDDDDAAAAABBBBB----------- */
	[INSN_DAB] = {INSN_DAB, "%s r%d, r%d, r%d",
		{
			[INSN_OPER_D] = {INSN_OPER_D, INSN_D_MASK, INSN_D_SHIFT},
			[INSN_OPER_A] = {INSN_OPER_A, INSN_A_MASK, INSN_A_SHIFT},
			[INSN_OPER_B] = {INSN_OPER_B, INSN_B_MASK, INSN_B_SHIFT},
		}
	},
	/* -----------AAAAABBBBB----------- */
	[INSN_AB] = {INSN_AB, "%s r%d, r%d",
		{
			[INSN_OPER_A] = {INSN_OPER_A, INSN_A_MASK, INSN_A_SHIFT},
			[INSN_OPER_B] = {INSN_OPER_B, INSN_B_MASK, INSN_B_SHIFT},
		}
	},
};

insn_extra_t extra_0x5[] = {
	{(0x05<<26)|(0b01<<24), "l.nop", INSN_K, INSN_OPCODE_MASK | (0b11 << 24)},
	{}
};

insn_extra_t extra_0x6[] = {
	{(0x06<<26)|(0<<16), "l.movhi", INSN_DK, INSN_OPCODE_MASK | (1 << 16)},
	{(0x06<<26)|(1<<16), "l.macrc", INSN_D, INSN_OPCODE_MASK | (1 << 16)},
	{}
};

insn_extra_t extra_0x8[] = {
	{(0x08<<26)|(0b0000000000), "l.sys", INSN_K, INSN_OPCODE_MASK | 0b1111111111 << 16},
	{(0x08<<26)|(0b0100000000), "l.trap", INSN_K, INSN_OPCODE_MASK | 0b1111111111 << 16},
	{(0x08<<26)|(0b10000000000000000000000000), "l.msync", INSN_X, INSN_OPCODE_MASK | 0x3ffffff},
	{(0x08<<26)|(0b10100000000000000000000000), "l.psync", INSN_X, INSN_OPCODE_MASK | 0x3ffffff},
	{(0x08<<26)|(0b11000000000000000000000000), "l.csync", INSN_X, INSN_OPCODE_MASK | 0x3ffffff},
	{}
};

insn_extra_t extra_0x2e[] = {
	{(0x2e<<26)|(0b00<<6), "l.slli", INSN_DAL, INSN_OPCODE_MASK | (0b11 << 6)},
	{(0x2e<<26)|(0b01<<6), "l.srli", INSN_DAL, INSN_OPCODE_MASK | (0b11 << 6)},
	{(0x2e<<26)|(0b10<<6), "l.srai", INSN_DAL, INSN_OPCODE_MASK | (0b11 << 6)},
	{(0x2e<<26)|(0b11<<6), "l.rori", INSN_DAL, INSN_OPCODE_MASK | (0b11 << 6)},
	{}
};

insn_extra_t extra_0x2f[] = {
	{(0x2f<<26)|(0b00000<<21), "l.sfeqi", INSN_AI, INSN_OPCODE_MASK | (0b11111 << 21)},
	{(0x2f<<26)|(0b00001<<21), "l.sfnei", INSN_AI, INSN_OPCODE_MASK | (0b11111 << 21)},
	{(0x2f<<26)|(0b00010<<21), "l.sfgtui", INSN_AI, INSN_OPCODE_MASK | (0b11111 << 21)},
	{(0x2f<<26)|(0b00011<<21), "l.sfgeui", INSN_AI, INSN_OPCODE_MASK | (0b11111 << 21)},
	{(0x2f<<26)|(0b00100<<21), "l.sfltui", INSN_AI, INSN_OPCODE_MASK | (0b11111 << 21)},
	{(0x2f<<26)|(0b00101<<21), "l.sfleui", INSN_AI, INSN_OPCODE_MASK | (0b11111 << 21)},
	{(0x2f<<26)|(0b01010<<21), "l.sfgtsi", INSN_AI, INSN_OPCODE_MASK | (0b11111 << 21)}, /* FIXME: signed */
	{(0x2f<<26)|(0b01011<<21), "l.sfgesi", INSN_AI, INSN_OPCODE_MASK | (0b11111 << 21)}, /* FIXME: signed */
	{(0x2f<<26)|(0b01100<<21), "l.sfltsi", INSN_AI, INSN_OPCODE_MASK | (0b11111 << 21)}, /* FIXME: signed */
	{(0x2f<<26)|(0b01101<<21), "l.sflesi", INSN_AI, INSN_OPCODE_MASK | (0b11111 << 21)}, /* FIXME: signed */
	{}
};

insn_extra_t extra_0x31[] = {
	{(0x31<<26)|(0b0001), "l.mac", INSN_AB, INSN_OPCODE_MASK | (0b1111)},
	{(0x31<<26)|(0b0011), "l.macu", INSN_AB, INSN_OPCODE_MASK | (0b1111)},
	{(0x31<<26)|(0b0010), "l.msb", INSN_AB, INSN_OPCODE_MASK | (0b1111)},
	{(0x31<<26)|(0b0100), "l.msbu", INSN_AB, INSN_OPCODE_MASK | (0b1111)},
	{}
};

insn_extra_t extra_0x32[] = {
	{(0x32<<26)|(0b00001000), "lf.sfeq.s", INSN_AB, INSN_OPCODE_MASK | (0b11111111)},
	{(0x32<<26)|(0b00001001), "lf.sfne.s", INSN_AB, INSN_OPCODE_MASK | (0b11111111)},
	{(0x32<<26)|(0b00001010), "lf.sfgt.s", INSN_AB, INSN_OPCODE_MASK | (0b11111111)},
	{(0x32<<26)|(0b00001011), "lf.sfge.s", INSN_AB, INSN_OPCODE_MASK | (0b11111111)},
	{(0x32<<26)|(0b00001100), "lf.sflt.s", INSN_AB, INSN_OPCODE_MASK | (0b11111111)},
	{(0x32<<26)|(0b00001101), "lf.sfle.s", INSN_AB, INSN_OPCODE_MASK | (0b11111111)},
	{(0x32<<26)|(0b00011000), "lf.sfeq.d", INSN_AB, INSN_OPCODE_MASK | (0b11111111)},
	{(0x32<<26)|(0b00011001), "lf.sfne.d", INSN_AB, INSN_OPCODE_MASK | (0b11111111)},
	{(0x32<<26)|(0b00011010), "lf.sfgt.d", INSN_AB, INSN_OPCODE_MASK | (0b11111111)},
	{(0x32<<26)|(0b00011011), "lf.sfge.d", INSN_AB, INSN_OPCODE_MASK | (0b11111111)},
	{(0x32<<26)|(0b00011100), "lf.sflt.d", INSN_AB, INSN_OPCODE_MASK | (0b11111111)},
	{(0x32<<26)|(0b00011101), "lf.sfle.d", INSN_AB, INSN_OPCODE_MASK | (0b11111111)},
	{(0x32<<26)|(0b00101000), "lf.sfueq.s", INSN_AB, INSN_OPCODE_MASK | (0b11111111)},
	{(0x32<<26)|(0b00101001), "lf.sfune.s", INSN_AB, INSN_OPCODE_MASK | (0b11111111)},
	{(0x32<<26)|(0b00101010), "lf.sfugt.s", INSN_AB, INSN_OPCODE_MASK | (0b11111111)},
	{(0x32<<26)|(0b00101011), "lf.sfuge.s", INSN_AB, INSN_OPCODE_MASK | (0b11111111)},
	{(0x32<<26)|(0b00101100), "lf.sfult.s", INSN_AB, INSN_OPCODE_MASK | (0b11111111)},
	{(0x32<<26)|(0b00101101), "lf.sfule.s", INSN_AB, INSN_OPCODE_MASK | (0b11111111)},
	{(0x32<<26)|(0b00101110), "lf.sfun.s", INSN_AB, INSN_OPCODE_MASK | (0b11111111)},
	{(0x32<<26)|(0b00110100), "lf.stod.d", INSN_AB, INSN_OPCODE_MASK | (0b11111111)},
	{(0x32<<26)|(0b00110101), "lf.dtos.d", INSN_AB, INSN_OPCODE_MASK | (0b11111111)},
	{(0x32<<26)|(0b00111000), "lf.sfueq.d", INSN_AB, INSN_OPCODE_MASK | (0b11111111)},
	{(0x32<<26)|(0b00111001), "lf.sfune.d", INSN_AB, INSN_OPCODE_MASK | (0b11111111)},
	{(0x32<<26)|(0b00111010), "lf.sfugt.d", INSN_AB, INSN_OPCODE_MASK | (0b11111111)},
	{(0x32<<26)|(0b00111011), "lf.sfuge.d", INSN_AB, INSN_OPCODE_MASK | (0b11111111)},
	{(0x32<<26)|(0b00111100), "lf.sfult.d", INSN_AB, INSN_OPCODE_MASK | (0b11111111)},
	{(0x32<<26)|(0b00111101), "lf.sfule.d", INSN_AB, INSN_OPCODE_MASK | (0b11111111)},
	{(0x32<<26)|(0b00111110), "lf.sfun.d", INSN_AB, INSN_OPCODE_MASK | (0b11111111)},
	{(0x32<<26)|(0b1101<<4), "lf.cust1.s", INSN_AB, INSN_OPCODE_MASK | (0b1111 << 4)},
	{(0x32<<26)|(0b1110<<4), "lf.cust1.d", INSN_AB, INSN_OPCODE_MASK | (0b1111 << 4)},
	{(0x32<<26)|(0b00000100), "lf.itof.s", INSN_DA, INSN_OPCODE_MASK | (0b11111111)},
	{(0x32<<26)|(0b00000101), "lf.ftoi.s", INSN_DA, INSN_OPCODE_MASK | (0b11111111)},
	{(0x32<<26)|(0b00010100), "lf.itof.d", INSN_DA, INSN_OPCODE_MASK | (0b11111111)},
	{(0x32<<26)|(0b00010101), "lf.ftoi.d", INSN_DA, INSN_OPCODE_MASK | (0b11111111)},
	{(0x32<<26)|(0b00000000), "lf.add.s", INSN_DAB, INSN_OPCODE_MASK | (0b11111111)},
	{(0x32<<26)|(0b00000001), "lf.sub.s", INSN_DAB, INSN_OPCODE_MASK | (0b11111111)},
	{(0x32<<26)|(0b00000010), "lf.mul.s", INSN_DAB, INSN_OPCODE_MASK | (0b11111111)},
	{(0x32<<26)|(0b00000011), "lf.div.s", INSN_DAB, INSN_OPCODE_MASK | (0b11111111)},
	{(0x32<<26)|(0b00000111), "lf.madd.s", INSN_DAB, INSN_OPCODE_MASK | (0b11111111)},
	{(0x32<<26)|(0b00010000), "lf.add.d", INSN_DAB, INSN_OPCODE_MASK | (0b11111111)},
	{(0x32<<26)|(0b00010001), "lf.sub.d", INSN_DAB, INSN_OPCODE_MASK | (0b11111111)},
	{(0x32<<26)|(0b00010010), "lf.mul.d", INSN_DAB, INSN_OPCODE_MASK | (0b11111111)},
	{(0x32<<26)|(0b00010011), "lf.div.d", INSN_DAB, INSN_OPCODE_MASK | (0b11111111)},
	{(0x32<<26)|(0b00010111), "lf.madd.d", INSN_DAB, INSN_OPCODE_MASK | (0b11111111)},
	{}
};

insn_extra_t extra_0x38[] = {
	{(0x38<<26)|(0b0000<<6)|(0b1100), "l.exths", INSN_DA, INSN_OPCODE_MASK | (0xf << 6) | 0xf},
	{(0x38<<26)|(0b0000<<6)|(0b1101), "l.extws", INSN_DA, INSN_OPCODE_MASK | (0xf << 6) | 0xf},
	{(0x38<<26)|(0b0001<<6)|(0b1100), "l.extbs", INSN_DA, INSN_OPCODE_MASK | (0xf << 6) | 0xf},
	{(0x38<<26)|(0b0001<<6)|(0b1101), "l.extwz", INSN_DA, INSN_OPCODE_MASK | (0xf << 6) | 0xf},
	{(0x38<<26)|(0b0010<<6)|(0b1100), "l.exthz", INSN_DA, INSN_OPCODE_MASK | (0xf << 6) | 0xf},
	{(0x38<<26)|(0b0011<<6)|(0b1100), "l.extbz", INSN_DA, INSN_OPCODE_MASK | (0xf << 6) | 0xf},
	{(0x38<<26)|(0b0000<<6)|(0b0000), "l.add", INSN_DAB, INSN_OPCODE_MASK | (0xc << 6) | 0xf},
	{(0x38<<26)|(0b0000<<6)|(0b0001), "l.addc", INSN_DAB, INSN_OPCODE_MASK | (0xc << 6) | 0xf},
	{(0x38<<26)|(0b0000<<6)|(0b0010), "l.sub", INSN_DAB, INSN_OPCODE_MASK | (0xc << 6) | 0xf},
	{(0x38<<26)|(0b0000<<6)|(0b0011), "l.and", INSN_DAB, INSN_OPCODE_MASK | (0xc << 6) | 0xf},
	{(0x38<<26)|(0b0000<<6)|(0b0100), "l.or", INSN_DAB, INSN_OPCODE_MASK | (0xc << 6) | 0xf},
	{(0x38<<26)|(0b0000<<6)|(0b0101), "l.xor", INSN_DAB, INSN_OPCODE_MASK | (0xc << 6) | 0xf},
	{(0x38<<26)|(0b0000<<6)|(0b1110), "l.cmov", INSN_DAB, INSN_OPCODE_MASK | (0xc << 6) | 0xf},
	{(0x38<<26)|(0b0000<<6)|(0b1111), "l.ff1", INSN_DA, INSN_OPCODE_MASK | (0xc << 6) | 0xf},
	{(0x38<<26)|(0b0000<<6)|(0b1000), "l.sll", INSN_DAB, INSN_OPCODE_MASK | (0xf << 6) | 0xf},
	{(0x38<<26)|(0b0001<<6)|(0b1000), "l.srl", INSN_DAB, INSN_OPCODE_MASK | (0xf << 6) | 0xf},
	{(0x38<<26)|(0b0010<<6)|(0b1000), "l.sra", INSN_DAB, INSN_OPCODE_MASK | (0xf << 6) | 0xf},
	{(0x38<<26)|(0b0011<<6)|(0b1000), "l.ror", INSN_DAB, INSN_OPCODE_MASK | (0xf << 6) | 0xf},
	{(0x38<<26)|(0b01<<8)|(0b1111), "l.fl1", INSN_DA, INSN_OPCODE_MASK | (0x3 << 8) | 0xf},
	{(0x38<<26)|(0b11<<8)|(0b0110), "l.mul", INSN_DAB, INSN_OPCODE_MASK | (0x3 << 8) | 0xf},
	{(0x38<<26)|(0b11<<8)|(0b0111), "l.muld", INSN_AB, INSN_OPCODE_MASK | (0x3 << 8) | 0xf},
	{(0x38<<26)|(0b11<<8)|(0b1001), "l.div", INSN_DAB, INSN_OPCODE_MASK | (0x3 << 8) | 0xf},
	{(0x38<<26)|(0b11<<8)|(0b1010), "l.divu", INSN_DAB, INSN_OPCODE_MASK | (0x3 << 8) | 0xf},
	{(0x38<<26)|(0b11<<8)|(0b1011), "l.mulu", INSN_DAB, INSN_OPCODE_MASK | (0x3 << 8) | 0xf},
	{(0x38<<26)|(0b11<<8)|(0b1100), "l.muldu", INSN_AB, INSN_OPCODE_MASK | (0x3 << 8) | 0xf},
	{}
};

insn_extra_t extra_0x39[] = {
	{(0x39<<26)|(0b00000<<21), "l.sfeq", INSN_AB, INSN_OPCODE_MASK | (0b11111 << 21)},
	{(0x39<<26)|(0b00001<<21), "l.sfne", INSN_AB, INSN_OPCODE_MASK | (0b11111 << 21)},
	{(0x39<<26)|(0b00010<<21), "l.sfgtu", INSN_AB, INSN_OPCODE_MASK | (0b11111 << 21)},
	{(0x39<<26)|(0b00011<<21), "l.sfgeu", INSN_AB, INSN_OPCODE_MASK | (0b11111 << 21)},
	{(0x39<<26)|(0b00100<<21), "l.sfltu", INSN_AB, INSN_OPCODE_MASK | (0b11111 << 21)},
	{(0x39<<26)|(0b00101<<21), "l.sfleu", INSN_AB, INSN_OPCODE_MASK | (0b11111 << 21)},
	{(0x39<<26)|(0b01010<<21), "l.sfgts", INSN_AB, INSN_OPCODE_MASK | (0b11111 << 21)},
	{(0x39<<26)|(0b01011<<21), "l.sfges", INSN_AB, INSN_OPCODE_MASK | (0b11111 << 21)},
	{(0x39<<26)|(0b01100<<21), "l.sflts", INSN_AB, INSN_OPCODE_MASK | (0b11111 << 21)},
	{(0x39<<26)|(0b01101<<21), "l.sfles", INSN_AB, INSN_OPCODE_MASK | (0b11111 << 21)},
	{}
};


insn_t insns[] = {
	[0x00] = {(0x00<<26), "l.j", INSN_N},
	[0x01] = {(0x01<<26), "l.jal", INSN_N},
	[0x02] = {(0x02<<26), "l.adrp", INSN_DN},
	[0x03] = {(0x03<<26), "l.bnf", INSN_N},
	[0x04] = {(0x04<<26), "l.bf", INSN_N},
	[0x05] = {(0x05<<26), NULL, INSN_X, extra_0x5},
	[0x06] = {(0x06<<26), NULL, INSN_X, extra_0x6},
	[0x07] = {(0x07<<26)},
	[0x08] = {(0x08<<26), NULL, INSN_X, extra_0x8},
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
	[0x2e] = {(0x2e<<26), NULL, INSN_X, extra_0x2e},
	[0x2f] = {(0x2f<<26), NULL, INSN_X, extra_0x2f},
	[0x30] = {(0x30<<26), "l.mtspr", INSN_KABK},
	[0x31] = {(0x31<<26), NULL, INSN_X, extra_0x31},
	[0x32] = {(0x32<<26), NULL, INSN_X, extra_0x32},
	[0x33] = {(0x33<<26), "l.swa", INSN_IABI},
	[0x34] = {(0x34<<26)},
	[0x35] = {(0x35<<26), "l.sw", INSN_IABI},
	[0x36] = {(0x36<<26), "l.sb", INSN_IABI},
	[0x37] = {(0x37<<26), "l.sh", INSN_IABI},
	[0x38] = {(0x38<<26), NULL, INSN_X, extra_0x38},
	[0x39] = {(0x39<<26), NULL, INSN_X, extra_0x39},
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

static inline int has_type_descriptor(insn_type_t type) {
	return types + (sizeof(types)/sizeof(insn_type_descr_t)) > &types[type];
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

static insn_extra_t *find_extra_descriptor(insn_extra_t *extra_descr, ut32 insn) {
	ut32 opcode;
	while (extra_descr->type != INSN_END) {
		opcode = (insn & extra_descr->opcode_mask);
		if (extra_descr->opcode == opcode) {
			break;
		}
		extra_descr++;
	}
	if (extra_descr->type != INSN_END) {
		return extra_descr;
	}  else {
		return NULL;
	}
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
