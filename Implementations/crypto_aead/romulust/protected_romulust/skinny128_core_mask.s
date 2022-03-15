/*******************************************************************************
* 1st-order masked ARM assembly implementation of fixsliced Skinny-128-384+.
*
* @date     March 2022
* @author 	Alexandre Adomnicai, alex.adomnicai@gmail.com
*******************************************************************************/

.syntax unified
.thumb

/******************************************************************************
* Macro to compute the SWAPMOVE technique.
*   - in0,in1       input/output registers
*   - tmp           temporary register
*   - mask          value for bitmask
*   - sh0,sh1       shift values
******************************************************************************/
.macro swpmv 	in0, in1, tmp, mask, sh0, sh1
	eor 	\tmp, \in1, \in0, lsr \sh0
	and 	\tmp, \tmp, \mask, lsr \sh1
	eor 	\in1, \in1, \tmp
	eor 	\in0, \in0, \tmp, lsl \sh0
.endm

/******************************************************************************
* 1st-order secure AND between two Boolean masked values. Technique from the
* paper 'Optimal First-Order Boolean Masking for Embedded IoT Devices' at
* https://orbilu.uni.lu/bitstream/10993/37740/1/Optimal_Masking.pdf.
*   - z1,z2         output shares
*   - x1,x2         1st input shares
*   - y1,y2         2nd input shares
*   - tmp           temporary register
******************************************************************************/
.macro secand   z1, z2, x1, x2, y1, y2, tmp
    orn     \tmp, \x1, \y2
    and     \z1, \x1, \y1
    eor     \z1, \tmp, \z1
    orn     \tmp, \x2, \y2
    and     \z2, \x2, \y1
    eor     \z2, \z2, \tmp
.endm

/******************************************************************************
* 1st-order secure OR between two Boolean masked values. Technique from the
* paper 'Optimal First-Order Boolean Masking for Embedded IoT Devices' at
* https://orbilu.uni.lu/bitstream/10993/37740/1/Optimal_Masking.pdf.
*   - z1,z2         output shares
*   - x1,x2         1st input shares
*   - y1,y2         2nd input shares
*   - tmp           temporary register
******************************************************************************/
.macro secorr    z1, z2, x1, x2, y1, y2, tmp
    orr     \tmp, \x1, \y2
    and     \z1, \x1, \y1
    eor     \z1, \tmp, \z1
    and     \tmp, \x2, \y2
    orr     \z2, \x2, \y1
    eor     \z2, \z2, \tmp
.endm

/******************************************************************************
* 1st-order secure XOR between two Boolean masked values.
*   - z1,z2         output shares
*   - x1,x2         1st input shares
*   - y1,y2         2nd input shares
******************************************************************************/
.macro secxor   z1, z2, x1, x2, y1, y2
    eor     \z1, \x1, \y1
    eor     \z2, \x2, \y2
.endm

/******************************************************************************
* 1st-order secure 8-bit S-box.
* 	- in0-3 		1st input/output shares
* 	- in0-3m 		2nd input/output shares
* 	- tmp(m) 		tmp registers
* 	- mask 			bitmask for swpmv macro
******************************************************************************/
.macro sbox in0, in1, in2, in3, in0m, in1m, in2m, in3m, tmp, tmpm, mask
	// 1st layer
	secorr 	\tmp, \tmpm, \in0, \in0m, \in1, \in1m, r0
	secxor 	\in3, \in3m, \in3, \in3m, \tmp, \tmpm
	mvn 	\in3, \in3
	swpmv 	\in2, \in1, \tmp, \mask, #1, #0
	swpmv 	\in3, \in2, \tmp, \mask, #1, #0
	swpmv 	\in2m, \in1m, \tmp, \mask, #1, #0
	swpmv 	\in3m, \in2m, \tmp, \mask, #1, #0
	// 2nd layer
	secorr 	\tmp, \tmpm, \in2, \in2m, \in3, \in3m, r0
	secxor 	\in1, \in1m, \in1, \in1m, \tmp, \tmpm
	mvn 	\in1, \in1
	swpmv 	\in1, \in0, \tmp, \mask, #1, #0
	swpmv 	\in0, \in3, \tmp, \mask, #1, #0
	swpmv 	\in1m, \in0m, \tmp, \mask, #1, #0
	swpmv 	\in0m, \in3m, \tmp, \mask, #1, #0
	// 3rd layer
	secorr 	\tmp, \tmpm, \in0, \in0m, \in1, \in1m, r0
	secxor 	\in3, \in3m, \in3, \in3m, \tmp, \tmpm
	mvn 	\in3, \in3
	swpmv 	\in2, \in1, \tmp, \mask, #1, #0
	swpmv 	\in3, \in2, \tmp, \mask, #1, #0
	swpmv 	\in2m, \in1m, \tmp, \mask, #1, #0
	swpmv 	\in3m, \in2m, \tmp, \mask, #1, #0
	// 4th layer
	secorr 	\tmp, \tmpm, \in2, \in2m, \in3, \in3m, r0
	secxor 	\in1, \in1m, \in1, \in1m, \tmp, \tmpm
	swpmv 	\in0, \in3, \tmp, \mask, #0, #0
	swpmv 	\in0m, \in3m, \tmp, \mask, #0, #0
.endm

/******************************************************************************
* Fixsliced MixColumns on all slices.
* 	- in0-3 		input/output shares
* 	- idx0-5 		rotation indexes
******************************************************************************/
.macro mixcol in0, in1, in2, in3, idx0, idx1, idx2, idx3, idx4, idx5
	and 	r8, r7, \in0, ror \idx0
	eor 	\in0, \in0, r8, ror \idx1
	and 	r8, r7, \in0, ror \idx2
	eor 	\in0, \in0, r8, ror \idx3
	and 	r8, r7, \in0, ror \idx4
	eor 	\in0, \in0, r8, ror \idx5
	and 	r8, r7, \in1, ror \idx0
	eor 	\in1, \in1, r8, ror \idx1
	and 	r8, r7, \in1, ror \idx2
	eor 	\in1, \in1, r8, ror \idx3
	and 	r8, r7, \in1, ror \idx4
	eor 	\in1, \in1, r8, ror \idx5
	and 	r8, r7, \in2, ror \idx0
	eor 	\in2, \in2, r8, ror \idx1
	and 	r8, r7, \in2, ror \idx2
	eor 	\in2, \in2, r8, ror \idx3
	and 	r8, r7, \in2, ror \idx4
	eor 	\in2, \in2, r8, ror \idx5
	and 	r8, r7, \in3, ror \idx0
	eor 	\in3, \in3, r8, ror \idx1
	and 	r8, r7, \in3, ror \idx2
	eor 	\in3, \in3, r8, ror \idx3
	and 	r8, r7, \in3, ror \idx4
	eor 	\in3, \in3, r8, ror \idx5
.endm

/******************************************************************************
* Add round tweakeys. rtk2 ^ rtk3 and rtk1 are added separately.
******************************************************************************/
.macro rtk_123
	ldr.w 	r9, [sp, #64]
	ldr.w 	r0, [r1], #4
	ldr.w 	r8, [r9], #4
	eor 	r2, r2, r0 		// add rtk
	eor 	r2, r2, r8 		// add rtk1
	ldr.w 	r0, [r1], #4
	ldr.w 	r8, [r9], #4
	eor 	r3, r3, r0 		// add rtk
	eor 	r3, r3, r8 		// add rtk1
	ldr.w 	r0, [r1], #4
	ldr.w 	r8, [r9], #4
	eor 	r4, r4, r0 		// add rtk
	eor 	r4, r4, r8 		// add rtk1
	ldr.w 	r8, [r9], #4
	ldr.w 	r0, [r1], #4
	str.w 	r9, [sp, #64]
	eor 	r5, r5, r0 		// add rtk
	eor 	r5, r5, r8 		// add rtk1
.endm

/******************************************************************************
* Add masked round tweakeys.
******************************************************************************/
.macro rtk_3m
	ldr.w 	r0, [sp, #60]
	ldr.w 	r9, [r0, #4]
	ldr.w 	r8, [r0], #8
	eor 	r11, r11, r9
	eor 	r10, r10, r8
	ldr.w 	r9, [r0, #4]
	ldr.w 	r8, [r0], #8
	str.w 	r0, [sp, #60]
	eor 	r14, r14, r9
	eor 	r12, r12, r8
.endm

/******************************************************************************
* Four consecutive rounds of Skinny-128-384+ w/ 1st-order masking.
******************************************************************************/
.macro  quadruple_round
	sbox 	r2, r3, r4, r5, r10, r11, r12, r14, r8, r9, r6
	rtk_123
	rtk_3m
	mixcol 	r2,  r3,  r4,  r5,  #30, #24, #18, #2, #6, #4
	mixcol 	r10, r11, r12, r14, #30, #24, #18, #2, #6, #4
	sbox 	r4, r5, r2, r3, r12, r14, r10, r11, r8, r9, r6
	rtk_123
	rtk_3m
	mixcol 	r2,  r3,  r4,  r5,  #16, #30, #28, #0, #16, #2
	mixcol 	r10, r11, r12, r14, #16, #30, #28, #0, #16, #2
	sbox 	r2, r3, r4, r5, r10, r11, r12, r14, r8, r9, r6
	rtk_123
	rtk_3m
	mixcol 	r2,  r3,  r4,  r5,  #10, #4, #6, #6, #26, #0
	mixcol 	r10, r11, r12, r14, #10, #4, #6, #6, #26, #0
	sbox 	r4, r5, r2, r3, r12, r14, r10, r11, r8, r9, r6
	rtk_123
	rtk_3m
	mixcol 	r2,  r3,  r4,  r5,  #4, #26, #0, #4, #4, #22
	mixcol 	r10, r11, r12, r14, #4, #26, #0, #4, #4, #22
.endm

/******************************************************************************
* Decrements rtk1 pointer (rtk1 repeats every 16-rounds).
******************************************************************************/
.macro dec_rtk1
	ldr.w 	r9, [sp, #64]
	sub 	r9, r9, #256
	str.w 	r9, [sp, #64]
.endm

/******************************************************************************
* Four consecutive rounds of Skinny-128-384+ w/ 1st-order masking.
******************************************************************************/
@ void 	skinny128_384_plus_m(u8* c, u8* c_m, u8* p, u8* p_m, u8* rtk, u8 * rtk_m, u8 *rtk1)
.global skinny128_384_plus_m
.type   skinny128_384_plus_m,%function
.align 2
skinny128_384_plus_m:
	push 	{r0-r12, r14}
	// load ptext mask
	ldr.w 	r10, [r3]
	ldr.w 	r11, [r3, #8]
	ldr.w 	r12, [r3, #4]
	ldr.w 	r14, [r3, #12]
	// load rtk address in r1
	ldr.w 	r1, [sp, #56]
	// load boolean masked ptext
	ldr.w 	r3, [r2, #8]
	ldr.w 	r4, [r2, #4]
	ldr.w 	r5, [r2, #12]
	ldr.w 	r2, [r2]
	// preload bitmask for swapmove (packing into bitsliced)
	movw 	r6, #0x0a0a
	movt 	r6, #0x0a0a
	movw 	r7, #0x3030
	movt 	r7, #0x3030
	// pack 1st 128-bit share
	swpmv 	r2, r2, r8, r6, #3, #0
	swpmv 	r3, r3, r8, r6, #3, #0
	swpmv 	r4, r4, r8, r6, #3, #0
	swpmv 	r5, r5, r8, r6, #3, #0
	swpmv 	r4, r2, r8, r7, #2, #0
	swpmv 	r3, r2, r8, r7, #4, #2
	swpmv 	r5, r2, r8, r7, #6, #4
	swpmv 	r3, r4, r8, r7, #2, #2
	swpmv 	r5, r4, r8, r7, #4, #4
	swpmv 	r5, r3, r8, r7, #2, #4
	// pack 2nd 128-bit share
	swpmv 	r10, r10, r8, r6, #3, #0
	swpmv 	r11, r11, r8, r6, #3, #0
	swpmv 	r12, r12, r8, r6, #3, #0
	swpmv 	r14, r14, r8, r6, #3, #0
	swpmv 	r12, r10, r8, r7, #2, #0
	swpmv 	r11, r10, r8, r7, #4, #2
	swpmv 	r14, r10, r8, r7, #6, #4
	swpmv 	r11, r12, r8, r7, #2, #2
	swpmv 	r14, r12, r8, r7, #4, #4
	swpmv 	r14, r11, r8, r7, #2, #4
	// preload bitmasks for swapmove (s-box)
	movw 	r6, #0x5555
	movt 	r6, #0x5555
	// run 40 rounds (skinny128-384+)
	quadruple_round
	quadruple_round
	quadruple_round
	quadruple_round
	dec_rtk1
	quadruple_round
	quadruple_round
	quadruple_round
	quadruple_round
	dec_rtk1
	quadruple_round
	quadruple_round
	// preload bitmasks for swapmove (unpacking)
	movw 	r6, #0x0a0a
	movt 	r6, #0x0a0a
	// unpack 1st 128-bit share
	swpmv 	r5, r3, r8, r7, #2, #4
	swpmv 	r5, r4, r8, r7, #4, #4
	swpmv 	r3, r4, r8, r7, #2, #2
	swpmv 	r5, r2, r8, r7, #6, #4
	swpmv 	r3, r2, r8, r7, #4, #2
	swpmv 	r4, r2, r8, r7, #2, #0
	swpmv 	r5, r5, r8, r6, #3, #0
	swpmv 	r4, r4, r8, r6, #3, #0
	swpmv 	r3, r3, r8, r6, #3, #0
	swpmv 	r2, r2, r8, r6, #3, #0
	// unpack 2nd 128-bit share
	swpmv 	r14, r11, r8, r7, #2, #4
	swpmv 	r14, r12, r8, r7, #4, #4
	swpmv 	r11, r12, r8, r7, #2, #2
	swpmv 	r14, r10, r8, r7, #6, #4
	swpmv 	r11, r10, r8, r7, #4, #2
	swpmv 	r12, r10, r8, r7, #2, #0
	swpmv 	r14, r14, r8, r6, #3, #0
	swpmv 	r12, r12, r8, r6, #3, #0
	swpmv 	r11, r11, r8, r6, #3, #0
	swpmv 	r10, r10, r8, r6, #3, #0
	ldr.w 	r1, [sp, #4]
	ldr.w 	r0, [sp], #8
	str.w 	r2, [r0]
	str.w 	r4, [r0, #4]
	str.w 	r3, [r0, #8]
	str.w 	r5, [r0, #12]
	str.w 	r10, [r1]
	str.w 	r12, [r1, #4]
	str.w 	r11, [r1, #8]
	str.w 	r14, [r1, #12]
    pop 	{r2-r12,r14}
    bx 		lr
    