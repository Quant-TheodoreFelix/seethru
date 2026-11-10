	.file	"vault.ac0a7170bdae7c8f-cgu.0"
	.section	.text._ZN5vault5Vault4slot17hed44144b5607004aE,"ax",@progbits
	.globl	_ZN5vault5Vault4slot17hed44144b5607004aE
	.p2align	2
	.type	_ZN5vault5Vault4slot17hed44144b5607004aE,@function
_ZN5vault5Vault4slot17hed44144b5607004aE:
.Lfunc_begin0:
	.file	1 "." "vault/src/lib.rs"
	.loc	1 15 0
	.cfi_startproc
	mov	x9, xzr
	mov	w8, wzr
.LBB0_1:
.Ltmp0:
	.file	2 "/home/.rustup/toolchains/stable-aarch64-apple-darwin/lib/rustlib/src/rust/library/core/src/slice/iter" "macros.rs"
	.loc	2 180 28 prologue_end
	cmp	x9, #32
	b.eq	.LBB0_4
.Ltmp1:
	.loc	1 18 36
	cbz	w1, .LBB0_5
	ldr	w10, [x0, x9]
.Ltmp2:
	.file	3 "/home/.rustup/toolchains/stable-aarch64-apple-darwin/lib/rustlib/src/rust/library/core/src/ptr" "non_null.rs"
	.loc	3 659 28
	add	x9, x9, #4
.Ltmp3:
	.loc	1 18 36
	udiv	w11, w10, w1
	msub	w10, w11, w1, w10
.Ltmp4:
	.file	4 "/home/.rustup/toolchains/stable-aarch64-apple-darwin/lib/rustlib/src/rust/library/core/src/num" "uint_macros.rs"
	.loc	4 2457 13
	add	w8, w10, w8
.Ltmp5:
	.loc	1 17 9
	b	.LBB0_1
.Ltmp6:
.LBB0_4:
	.loc	1 21 6
	mov	w0, w8
	ret
.LBB0_5:
	.loc	1 0 6 is_stmt 0
	str	x30, [sp, #-16]!
	.cfi_def_cfa_offset 16
	.cfi_offset w30, -16
.Ltmp7:
	.loc	1 18 36 is_stmt 1
	adrp	x0, .Lalloc_07cc9e2ba7cb484a7ab238f278870dc5
	add	x0, x0, :lo12:.Lalloc_07cc9e2ba7cb484a7ab238f278870dc5
	bl	_RNvNtNtCsbcsGJ9IzBgZ_4core9panicking11panic_const23panic_const_rem_by_zero
.Ltmp8:
.Lfunc_end0:
	.size	_ZN5vault5Vault4slot17hed44144b5607004aE, .Lfunc_end0-_ZN5vault5Vault4slot17hed44144b5607004aE
	.cfi_endproc

	.section	.text._ZN5vault5Vault5close17hda7e64231d54272cE,"ax",@progbits
	.globl	_ZN5vault5Vault5close17hda7e64231d54272cE
	.p2align	2
	.type	_ZN5vault5Vault5close17hda7e64231d54272cE,@function
_ZN5vault5Vault5close17hda7e64231d54272cE:
.Lfunc_begin1:
	.loc	1 23 0
	.cfi_startproc
	mov	x8, xzr
.LBB1_1:
.Ltmp9:
	.loc	2 180 28 prologue_end
	cmp	x8, #32
	b.eq	.LBB1_3
.Ltmp10:
	.loc	3 659 28
	add	x9, x8, #4
.Ltmp11:
	.file	5 "/home/.rustup/toolchains/stable-aarch64-apple-darwin/lib/rustlib/src/rust/library/core/src/ptr" "mod.rs"
	.loc	5 2178 9
	str	wzr, [x0, x8]
	mov	x8, x9
.Ltmp12:
	.loc	1 24 9
	b	.LBB1_1
.Ltmp13:
.LBB1_3:
	.loc	1 27 6
	ret
.Ltmp14:
.Lfunc_end1:
	.size	_ZN5vault5Vault5close17hda7e64231d54272cE, .Lfunc_end1-_ZN5vault5Vault5close17hda7e64231d54272cE
	.cfi_endproc

	.section	.text._ZN5vault6bucket17hb1b20723cde11643E,"ax",@progbits
	.globl	_ZN5vault6bucket17hb1b20723cde11643E
	.p2align	2
	.type	_ZN5vault6bucket17hb1b20723cde11643E,@function
_ZN5vault6bucket17hb1b20723cde11643E:
.Lfunc_begin2:
	.loc	1 37 0
	.cfi_startproc
	mov	x9, xzr
	mov	w8, wzr
.LBB2_1:
.Ltmp15:
	.loc	2 180 28 prologue_end
	cmp	x9, #32
	b.eq	.LBB2_4
.Ltmp16:
	.loc	1 40 32
	cbz	w1, .LBB2_5
	ldr	w10, [x0, x9]
.Ltmp17:
	.loc	3 659 28
	add	x9, x9, #4
.Ltmp18:
	.loc	1 40 32
	udiv	w11, w10, w1
	msub	w10, w11, w1, w10
.Ltmp19:
	.loc	4 2457 13
	add	w8, w10, w8
.Ltmp20:
	.loc	1 39 5
	b	.LBB2_1
.Ltmp21:
.LBB2_4:
	.loc	1 43 2
	mov	w0, w8
	ret
.LBB2_5:
	.loc	1 0 2 is_stmt 0
	str	x30, [sp, #-16]!
	.cfi_def_cfa_offset 16
	.cfi_offset w30, -16
.Ltmp22:
	.loc	1 40 32 is_stmt 1
	adrp	x0, .Lalloc_ccbd36a724182826256a75396b95b92d
	add	x0, x0, :lo12:.Lalloc_ccbd36a724182826256a75396b95b92d
	bl	_RNvNtNtCsbcsGJ9IzBgZ_4core9panicking11panic_const23panic_const_rem_by_zero
.Ltmp23:
.Lfunc_end2:
	.size	_ZN5vault6bucket17hb1b20723cde11643E, .Lfunc_end2-_ZN5vault6bucket17hb1b20723cde11643E
	.cfi_endproc

	.section	.text._ZN5vault9open_once17he76d7a6438ba1d15E,"ax",@progbits
	.globl	_ZN5vault9open_once17he76d7a6438ba1d15E
	.p2align	2
	.type	_ZN5vault9open_once17he76d7a6438ba1d15E,@function
_ZN5vault9open_once17he76d7a6438ba1d15E:
.Lfunc_begin3:
	.loc	1 30 0
	.cfi_startproc
	str	x30, [sp, #-32]!
	stp	x20, x19, [sp, #16]
	.cfi_def_cfa_offset 32
	.cfi_offset w19, -8
	.cfi_offset w20, -16
	.cfi_offset w30, -32
	mov	x19, x0
.Ltmp24:
	.loc	1 31 22 prologue_end
	bl	_ZN5vault5Vault4slot17hed44144b5607004aE
	mov	w20, w0
.Ltmp25:
	.loc	1 32 11
	mov	x0, x19
	bl	_ZN5vault5Vault5close17hda7e64231d54272cE
.Ltmp26:
	.loc	1 34 2
	mov	w0, w20
	.loc	1 34 2 epilogue_begin is_stmt 0
	ldp	x20, x19, [sp, #16]
	ldr	x30, [sp], #32
	ret
.Ltmp27:
.Lfunc_end3:
	.size	_ZN5vault9open_once17he76d7a6438ba1d15E, .Lfunc_end3-_ZN5vault9open_once17he76d7a6438ba1d15E
	.cfi_endproc

	.type	.Lalloc_2f51b4b2bc2de91de1afbb037539bc53,@object
	.section	.rodata.str1.1,"aMS",@progbits,1
.Lalloc_2f51b4b2bc2de91de1afbb037539bc53:
	.asciz	"vault/src/lib.rs"
	.size	.Lalloc_2f51b4b2bc2de91de1afbb037539bc53, 17

	.type	.Lalloc_07cc9e2ba7cb484a7ab238f278870dc5,@object
	.section	.rodata..Lalloc_07cc9e2ba7cb484a7ab238f278870dc5,"a",@progbits
	.p2align	3, 0x0
.Lalloc_07cc9e2ba7cb484a7ab238f278870dc5:
	.xword	.Lalloc_2f51b4b2bc2de91de1afbb037539bc53
	.asciz	"\020\000\000\000\000\000\000\000\022\000\000\000$\000\000"
	.size	.Lalloc_07cc9e2ba7cb484a7ab238f278870dc5, 24

	.type	.Lalloc_ccbd36a724182826256a75396b95b92d,@object
	.section	.rodata..Lalloc_ccbd36a724182826256a75396b95b92d,"a",@progbits
	.p2align	3, 0x0
.Lalloc_ccbd36a724182826256a75396b95b92d:
	.xword	.Lalloc_2f51b4b2bc2de91de1afbb037539bc53
	.asciz	"\020\000\000\000\000\000\000\000(\000\000\000 \000\000"
	.size	.Lalloc_ccbd36a724182826256a75396b95b92d, 24

	.section	.debug_abbrev,"",@progbits
	.byte	1
	.byte	17
	.byte	1
	.byte	37
	.byte	14
	.byte	19
	.byte	5
	.byte	3
	.byte	14
	.byte	16
	.byte	23
	.byte	27
	.byte	14
	.byte	17
	.byte	1
	.byte	85
	.byte	23
	.byte	0
	.byte	0
	.byte	2
	.byte	46
	.byte	0
	.byte	3
	.byte	14
	.byte	32
	.byte	11
	.byte	0
	.byte	0
	.byte	3
	.byte	46
	.byte	1
	.byte	17
	.byte	1
	.byte	18
	.byte	6
	.byte	3
	.byte	14
	.byte	0
	.byte	0
	.byte	4
	.byte	29
	.byte	1
	.byte	49
	.byte	19
	.byte	85
	.byte	23
	.byte	88
	.byte	11
	.byte	89
	.byte	11
	.byte	87
	.byte	11
	.byte	0
	.byte	0
	.byte	5
	.byte	29
	.byte	0
	.byte	49
	.byte	19
	.byte	17
	.byte	1
	.byte	18
	.byte	6
	.byte	88
	.byte	11
	.byte	89
	.byte	11
	.byte	87
	.byte	11
	.byte	0
	.byte	0
	.byte	6
	.byte	29
	.byte	1
	.byte	49
	.byte	19
	.byte	17
	.byte	1
	.byte	18
	.byte	6
	.byte	88
	.byte	11
	.byte	89
	.byte	11
	.byte	87
	.byte	11
	.byte	0
	.byte	0
	.byte	0
	.section	.debug_info,"",@progbits
.Lcu_begin0:
	.word	.Ldebug_info_end0-.Ldebug_info_start0
.Ldebug_info_start0:
	.hword	4
	.word	.debug_abbrev
	.byte	8
	.byte	1
	.word	.Linfo_string0
	.hword	28
	.word	.Linfo_string1
	.word	.Lline_table_start0
	.word	.Linfo_string2
	.xword	0
	.word	.Ldebug_ranges2
	.byte	2
	.word	.Linfo_string3
	.byte	1
	.byte	2
	.word	.Linfo_string4
	.byte	1
	.byte	2
	.word	.Linfo_string5
	.byte	1
	.byte	3
	.xword	.Lfunc_begin0
	.word	.Lfunc_end0-.Lfunc_begin0
	.word	.Linfo_string7
	.byte	4
	.word	42
	.word	.Ldebug_ranges0
	.byte	1
	.byte	17
	.byte	21
	.byte	5
	.word	48
	.xword	.Ltmp2
	.word	.Ltmp3-.Ltmp2
	.byte	2
	.byte	185
	.byte	40
	.byte	0
	.byte	5
	.word	54
	.xword	.Ltmp4
	.word	.Ltmp5-.Ltmp4
	.byte	1
	.byte	18
	.byte	23
	.byte	0
	.byte	2
	.word	.Linfo_string3
	.byte	1
	.byte	2
	.word	.Linfo_string4
	.byte	1
	.byte	2
	.word	.Linfo_string6
	.byte	1
	.byte	3
	.xword	.Lfunc_begin1
	.word	.Lfunc_end1-.Lfunc_begin1
	.word	.Linfo_string8
	.byte	6
	.word	131
	.xword	.Ltmp9
	.word	.Ltmp11-.Ltmp9
	.byte	1
	.byte	24
	.byte	21
	.byte	5
	.word	137
	.xword	.Ltmp10
	.word	.Ltmp11-.Ltmp10
	.byte	2
	.byte	185
	.byte	40
	.byte	0
	.byte	5
	.word	143
	.xword	.Ltmp11
	.word	.Ltmp12-.Ltmp11
	.byte	1
	.byte	25
	.byte	22
	.byte	0
	.byte	3
	.xword	.Lfunc_begin2
	.word	.Lfunc_end2-.Lfunc_begin2
	.word	.Linfo_string9
	.byte	4
	.word	42
	.word	.Ldebug_ranges1
	.byte	1
	.byte	39
	.byte	17
	.byte	5
	.word	48
	.xword	.Ltmp17
	.word	.Ltmp18-.Ltmp17
	.byte	2
	.byte	185
	.byte	40
	.byte	0
	.byte	5
	.word	54
	.xword	.Ltmp19
	.word	.Ltmp20-.Ltmp19
	.byte	1
	.byte	40
	.byte	19
	.byte	0
	.byte	0
.Ldebug_info_end0:
	.section	.text._ZN5vault5Vault4slot17hed44144b5607004aE,"ax",@progbits
.Lsec_end0:
	.section	.text._ZN5vault5Vault5close17hda7e64231d54272cE,"ax",@progbits
.Lsec_end1:
	.section	.text._ZN5vault6bucket17hb1b20723cde11643E,"ax",@progbits
.Lsec_end2:
	.section	.text._ZN5vault9open_once17he76d7a6438ba1d15E,"ax",@progbits
.Lsec_end3:
	.section	.debug_aranges,"",@progbits
	.word	92
	.hword	2
	.word	.Lcu_begin0
	.byte	8
	.byte	0
	.zero	4,255
	.xword	.Lfunc_begin0
	.xword	.Lsec_end0-.Lfunc_begin0
	.xword	.Lfunc_begin1
	.xword	.Lsec_end1-.Lfunc_begin1
	.xword	.Lfunc_begin2
	.xword	.Lsec_end2-.Lfunc_begin2
	.xword	.Lfunc_begin3
	.xword	.Lsec_end3-.Lfunc_begin3
	.xword	0
	.xword	0
	.section	.debug_ranges,"",@progbits
.Ldebug_ranges0:
	.xword	.Ltmp0
	.xword	.Ltmp1
	.xword	.Ltmp2
	.xword	.Ltmp3
	.xword	0
	.xword	0
.Ldebug_ranges1:
	.xword	.Ltmp15
	.xword	.Ltmp16
	.xword	.Ltmp17
	.xword	.Ltmp18
	.xword	0
	.xword	0
.Ldebug_ranges2:
	.xword	.Lfunc_begin0
	.xword	.Lfunc_end0
	.xword	.Lfunc_begin1
	.xword	.Lfunc_end1
	.xword	.Lfunc_begin2
	.xword	.Lfunc_end2
	.xword	.Lfunc_begin3
	.xword	.Lfunc_end3
	.xword	0
	.xword	0
	.section	.debug_str,"MS",@progbits,1
.Linfo_string0:
	.asciz	"clang LLVM (rustc version 1.95.0 (59807616e 2026-04-14))"
.Linfo_string1:
	.asciz	"vault/src/lib.rs/@/vault.ac0a7170bdae7c8f-cgu.0"
.Linfo_string2:
	.asciz	"."
.Linfo_string3:
	.asciz	"next<u32>"
.Linfo_string4:
	.asciz	"add<u32>"
.Linfo_string5:
	.asciz	"wrapping_add"
.Linfo_string6:
	.asciz	"write_volatile<u32>"
.Linfo_string7:
	.asciz	"slot"
.Linfo_string8:
	.asciz	"close"
.Linfo_string9:
	.asciz	"bucket"
	.ident	"rustc version 1.95.0 (59807616e 2026-04-14)"
	.section	".note.GNU-stack","",@progbits
	.section	.debug_line,"",@progbits
.Lline_table_start0:
