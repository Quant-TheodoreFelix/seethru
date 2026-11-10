; ModuleID = 'vault.ac0a7170bdae7c8f-cgu.0'
source_filename = "vault.ac0a7170bdae7c8f-cgu.0"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i8:8:32-i16:16:32-i64:64-i128:128-n32:64-S128-Fn32"
target triple = "aarch64-unknown-none"

@alloc_2f51b4b2bc2de91de1afbb037539bc53 = private unnamed_addr constant [17 x i8] c"vault/src/lib.rs\00", align 1
@alloc_07cc9e2ba7cb484a7ab238f278870dc5 = private unnamed_addr constant <{ ptr, [16 x i8] }> <{ ptr @alloc_2f51b4b2bc2de91de1afbb037539bc53, [16 x i8] c"\10\00\00\00\00\00\00\00\12\00\00\00$\00\00\00" }>, align 8
@alloc_ccbd36a724182826256a75396b95b92d = private unnamed_addr constant <{ ptr, [16 x i8] }> <{ ptr @alloc_2f51b4b2bc2de91de1afbb037539bc53, [16 x i8] c"\10\00\00\00\00\00\00\00(\00\00\00 \00\00\00" }>, align 8

; vault::Vault::slot
; Function Attrs: minsize noinline noredzone nounwind optsize uwtable
define dso_local noundef i32 @_ZN5vault5Vault4slot17hed44144b5607004aE(ptr noalias noundef readonly align 4 captures(none) dereferenceable(32) %self, i32 noundef %modulus) unnamed_addr #0 !dbg !5 {
start:
  %_15 = icmp eq i32 %modulus, 0
  br label %bb3, !dbg !11

bb3:                                              ; preds = %bb8, %start
  %iter.sroa.0.0.idx = phi i64 [ 0, %start ], [ %iter.sroa.0.0.add, %bb8 ]
  %sum.sroa.0.0 = phi i32 [ 0, %start ], [ %_0.i, %bb8 ], !dbg !14
  %iter.sroa.0.0.ptr = getelementptr inbounds nuw i8, ptr %self, i64 %iter.sroa.0.0.idx, !dbg !15
  %_6.i = icmp eq i64 %iter.sroa.0.0.idx, 32, !dbg !15
  br i1 %_6.i, label %bb7, label %bb6, !dbg !31

bb6:                                              ; preds = %bb3
  br i1 %_15, label %panic, label %bb8, !dbg !32

bb7:                                              ; preds = %bb3
  ret i32 %sum.sroa.0.0, !dbg !34

bb8:                                              ; preds = %bb6
  %iter.sroa.0.0.add = add nuw nsw i64 %iter.sroa.0.0.idx, 4, !dbg !35
  %_14 = load i32, ptr %iter.sroa.0.0.ptr, align 4, !dbg !32, !noundef !10
  %_13 = urem i32 %_14, %modulus, !dbg !32
  %_0.i = add i32 %_13, %sum.sroa.0.0, !dbg !39
  br label %bb3, !dbg !11

panic:                                            ; preds = %bb6
; call core::panicking::panic_const::panic_const_rem_by_zero
  tail call void @_RNvNtNtCsbcsGJ9IzBgZ_4core9panicking11panic_const23panic_const_rem_by_zero(ptr noalias noundef readonly align 8 captures(address, read_provenance) dereferenceable(24) @alloc_07cc9e2ba7cb484a7ab238f278870dc5) #4, !dbg !32
  unreachable, !dbg !32
}

; vault::Vault::close
; Function Attrs: minsize nofree norecurse noredzone nounwind optsize memory(argmem: readwrite, inaccessiblemem: readwrite) uwtable
define dso_local void @_ZN5vault5Vault5close17hda7e64231d54272cE(ptr noalias noundef align 4 dereferenceable(32) %self) unnamed_addr #1 !dbg !45 {
start:
  br label %bb3, !dbg !46

bb3:                                              ; preds = %bb6, %start
  %iter.sroa.0.0.idx = phi i64 [ 0, %start ], [ %iter.sroa.0.0.add, %bb6 ]
  %_7.i = icmp eq i64 %iter.sroa.0.0.idx, 32, !dbg !48
  br i1 %_7.i, label %bb7, label %bb6, !dbg !56

bb6:                                              ; preds = %bb3
  %iter.sroa.0.0.ptr = getelementptr inbounds nuw i8, ptr %self, i64 %iter.sroa.0.0.idx, !dbg !48
  %iter.sroa.0.0.add = add nuw nsw i64 %iter.sroa.0.0.idx, 4, !dbg !57
  store volatile i32 0, ptr %iter.sroa.0.0.ptr, align 4, !dbg !60
  br label %bb3, !dbg !46

bb7:                                              ; preds = %bb3
  ret void, !dbg !65
}

; vault::bucket
; Function Attrs: minsize noinline noredzone nounwind optsize uwtable
define dso_local noundef i32 @_ZN5vault6bucket17hb1b20723cde11643E(ptr noalias noundef readonly align 4 captures(none) dereferenceable(32) %public, i32 noundef %modulus) unnamed_addr #0 !dbg !66 {
start:
  %_14 = icmp eq i32 %modulus, 0
  br label %bb3, !dbg !67

bb3:                                              ; preds = %bb8, %start
  %iter.sroa.0.0.idx = phi i64 [ 0, %start ], [ %iter.sroa.0.0.add, %bb8 ]
  %sum.sroa.0.0 = phi i32 [ 0, %start ], [ %_0.i, %bb8 ], !dbg !70
  %iter.sroa.0.0.ptr = getelementptr inbounds nuw i8, ptr %public, i64 %iter.sroa.0.0.idx, !dbg !71
  %_6.i = icmp eq i64 %iter.sroa.0.0.idx, 32, !dbg !71
  br i1 %_6.i, label %bb7, label %bb6, !dbg !74

bb6:                                              ; preds = %bb3
  br i1 %_14, label %panic, label %bb8, !dbg !75

bb7:                                              ; preds = %bb3
  ret i32 %sum.sroa.0.0, !dbg !77

bb8:                                              ; preds = %bb6
  %iter.sroa.0.0.add = add nuw nsw i64 %iter.sroa.0.0.idx, 4, !dbg !78
  %_13 = load i32, ptr %iter.sroa.0.0.ptr, align 4, !dbg !75, !noundef !10
  %_12 = urem i32 %_13, %modulus, !dbg !75
  %_0.i = add i32 %_12, %sum.sroa.0.0, !dbg !80
  br label %bb3, !dbg !67

panic:                                            ; preds = %bb6
; call core::panicking::panic_const::panic_const_rem_by_zero
  tail call void @_RNvNtNtCsbcsGJ9IzBgZ_4core9panicking11panic_const23panic_const_rem_by_zero(ptr noalias noundef readonly align 8 captures(address, read_provenance) dereferenceable(24) @alloc_ccbd36a724182826256a75396b95b92d) #4, !dbg !75
  unreachable, !dbg !75
}

; vault::open_once
; Function Attrs: minsize noredzone nounwind optsize uwtable
define dso_local noundef i32 @_ZN5vault9open_once17he76d7a6438ba1d15E(ptr noalias noundef align 4 dereferenceable(32) %vault, i32 noundef %modulus) unnamed_addr #2 !dbg !82 {
start:
; call vault::Vault::slot
  %slot = tail call noundef i32 @_ZN5vault5Vault4slot17hed44144b5607004aE(ptr noalias noundef nonnull readonly align 4 captures(address, read_provenance) dereferenceable(32) %vault, i32 noundef %modulus) #5, !dbg !83
; call vault::Vault::close
  tail call void @_ZN5vault5Vault5close17hda7e64231d54272cE(ptr noalias noundef nonnull align 4 dereferenceable(32) %vault) #6, !dbg !84
  ret i32 %slot, !dbg !86
}

; core::panicking::panic_const::panic_const_rem_by_zero
; Function Attrs: cold minsize noinline noredzone noreturn nounwind optsize uwtable
declare dso_local void @_RNvNtNtCsbcsGJ9IzBgZ_4core9panicking11panic_const23panic_const_rem_by_zero(ptr noalias noundef readonly align 8 captures(address, read_provenance) dereferenceable(24)) unnamed_addr #3

attributes #0 = { minsize noinline noredzone nounwind optsize uwtable "probe-stack"="inline-asm" "target-cpu"="generic" "target-features"="+v8a,+strict-align,+neon,+fp-armv8" }
attributes #1 = { minsize nofree norecurse noredzone nounwind optsize memory(argmem: readwrite, inaccessiblemem: readwrite) uwtable "probe-stack"="inline-asm" "target-cpu"="generic" "target-features"="+v8a,+strict-align,+neon,+fp-armv8" }
attributes #2 = { minsize noredzone nounwind optsize uwtable "probe-stack"="inline-asm" "target-cpu"="generic" "target-features"="+v8a,+strict-align,+neon,+fp-armv8" }
attributes #3 = { cold minsize noinline noredzone noreturn nounwind optsize uwtable "probe-stack"="inline-asm" "target-cpu"="generic" "target-features"="+v8a,+strict-align,+neon,+fp-armv8" }
attributes #4 = { noinline noreturn nounwind }
attributes #5 = { noinline nounwind }
attributes #6 = { nounwind }

!llvm.ident = !{!0}
!llvm.dbg.cu = !{!1}
!llvm.module.flags = !{!3, !4}

!0 = !{!"rustc version 1.95.0 (59807616e 2026-04-14)"}
!1 = distinct !DICompileUnit(language: DW_LANG_Rust, file: !2, producer: "clang LLVM (rustc version 1.95.0 (59807616e 2026-04-14))", isOptimized: true, runtimeVersion: 0, emissionKind: LineTablesOnly, splitDebugInlining: false, nameTableKind: None)
!2 = !DIFile(filename: "vault/src/lib.rs/@/vault.ac0a7170bdae7c8f-cgu.0", directory: ".")
!3 = !{i32 7, !"Dwarf Version", i32 4}
!4 = !{i32 2, !"Debug Info Version", i32 3}
!5 = distinct !DISubprogram(name: "slot", linkageName: "_ZN5vault5Vault4slot17hed44144b5607004aE", scope: !7, file: !6, line: 15, type: !9, scopeLine: 15, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition | DISPFlagOptimized, unit: !1, templateParams: !10)
!6 = !DIFile(filename: "vault/src/lib.rs", directory: ".", checksumkind: CSK_MD5, checksum: "f93191952dfdf50beefab62146e736e3")
!7 = !DINamespace(name: "Vault", scope: !8)
!8 = !DINamespace(name: "vault", scope: null)
!9 = !DISubroutineType(types: !10)
!10 = !{}
!11 = !DILocation(line: 17, column: 9, scope: !12)
!12 = distinct !DILexicalBlock(scope: !13, file: !6, line: 17, column: 9)
!13 = distinct !DILexicalBlock(scope: !5, file: !6, line: 16, column: 9)
!14 = !DILocation(line: 0, scope: !5)
!15 = !DILocation(line: 1720, column: 9, scope: !16, inlinedAt: !22)
!16 = distinct !DISubprogram(name: "eq<u32>", linkageName: "_ZN78_$LT$core..ptr..non_null..NonNull$LT$T$GT$$u20$as$u20$core..cmp..PartialEq$GT$2eq17h792402a625630e8bE", scope: !18, file: !17, line: 1719, type: !9, scopeLine: 1719, flags: DIFlagPrototyped, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition | DISPFlagOptimized, unit: !1, templateParams: !10)
!17 = !DIFile(filename: "/home/.rustup/toolchains/stable-aarch64-apple-darwin/lib/rustlib/src/rust/library/core/src/ptr/non_null.rs", directory: "", checksumkind: CSK_MD5, checksum: "e5222a5160165ba1cd09076ad7a11733")
!18 = !DINamespace(name: "{impl#16}", scope: !19)
!19 = !DINamespace(name: "non_null", scope: !20)
!20 = !DINamespace(name: "ptr", scope: !21)
!21 = !DINamespace(name: "core", scope: null)
!22 = distinct !DILocation(line: 180, column: 28, scope: !23, inlinedAt: !30)
!23 = distinct !DILexicalBlock(scope: !25, file: !24, line: 162, column: 17)
!24 = !DIFile(filename: "/home/.rustup/toolchains/stable-aarch64-apple-darwin/lib/rustlib/src/rust/library/core/src/slice/iter/macros.rs", directory: "", checksumkind: CSK_MD5, checksum: "87d1f0c2746f51593d75ddf4c9271f14")
!25 = distinct !DILexicalBlock(scope: !26, file: !24, line: 161, column: 17)
!26 = distinct !DISubprogram(name: "next<u32>", linkageName: "_ZN91_$LT$core..slice..iter..Iter$LT$T$GT$$u20$as$u20$core..iter..traits..iterator..Iterator$GT$4next17hec77efe9ce703ef9E", scope: !27, file: !24, line: 157, type: !9, scopeLine: 157, flags: DIFlagPrototyped, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition | DISPFlagOptimized, unit: !1, templateParams: !10)
!27 = !DINamespace(name: "{impl#171}", scope: !28)
!28 = !DINamespace(name: "iter", scope: !29)
!29 = !DINamespace(name: "slice", scope: !21)
!30 = distinct !DILocation(line: 17, column: 21, scope: !12)
!31 = !DILocation(line: 180, column: 28, scope: !23, inlinedAt: !30)
!32 = !DILocation(line: 18, column: 36, scope: !33)
!33 = distinct !DILexicalBlock(scope: !12, file: !6, line: 17, column: 9)
!34 = !DILocation(line: 21, column: 6, scope: !5)
!35 = !DILocation(line: 659, column: 28, scope: !36, inlinedAt: !38)
!36 = distinct !DISubprogram(name: "add<u32>", linkageName: "_ZN4core3ptr8non_null16NonNull$LT$T$GT$3add17h78cf1a556b1b6058E", scope: !37, file: !17, line: 651, type: !9, scopeLine: 651, flags: DIFlagPrototyped, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition | DISPFlagOptimized, unit: !1, templateParams: !10)
!37 = !DINamespace(name: "NonNull", scope: !19)
!38 = distinct !DILocation(line: 185, column: 40, scope: !23, inlinedAt: !30)
!39 = !DILocation(line: 2457, column: 13, scope: !40, inlinedAt: !44)
!40 = distinct !DISubprogram(name: "wrapping_add", linkageName: "_RNvMs6_NtCsbcsGJ9IzBgZ_4core3numm12wrapping_add", scope: !42, file: !41, line: 2456, type: !9, scopeLine: 2456, flags: DIFlagPrototyped, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition | DISPFlagOptimized, unit: !1, templateParams: !10)
!41 = !DIFile(filename: "/home/.rustup/toolchains/stable-aarch64-apple-darwin/lib/rustlib/src/rust/library/core/src/num/uint_macros.rs", directory: "", checksumkind: CSK_MD5, checksum: "de2f29a3485fc28d710ba6c3062e6efa")
!42 = !DINamespace(name: "{impl#8}", scope: !43)
!43 = !DINamespace(name: "num", scope: !21)
!44 = distinct !DILocation(line: 18, column: 23, scope: !33)
!45 = distinct !DISubprogram(name: "close", linkageName: "_ZN5vault5Vault5close17hda7e64231d54272cE", scope: !7, file: !6, line: 23, type: !9, scopeLine: 23, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition | DISPFlagOptimized, unit: !1, templateParams: !10)
!46 = !DILocation(line: 24, column: 9, scope: !47)
!47 = distinct !DILexicalBlock(scope: !45, file: !6, line: 24, column: 9)
!48 = !DILocation(line: 1720, column: 9, scope: !49, inlinedAt: !50)
!49 = distinct !DISubprogram(name: "eq<u32>", linkageName: "_ZN78_$LT$core..ptr..non_null..NonNull$LT$T$GT$$u20$as$u20$core..cmp..PartialEq$GT$2eq17h792402a625630e8bE", scope: !18, file: !17, line: 1719, type: !9, scopeLine: 1719, flags: DIFlagPrototyped, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition | DISPFlagOptimized, unit: !1, templateParams: !10)
!50 = distinct !DILocation(line: 180, column: 28, scope: !51, inlinedAt: !55)
!51 = distinct !DILexicalBlock(scope: !52, file: !24, line: 162, column: 17)
!52 = distinct !DILexicalBlock(scope: !53, file: !24, line: 161, column: 17)
!53 = distinct !DISubprogram(name: "next<u32>", linkageName: "_ZN94_$LT$core..slice..iter..IterMut$LT$T$GT$$u20$as$u20$core..iter..traits..iterator..Iterator$GT$4next17h617ded451f3bd33fE", scope: !54, file: !24, line: 157, type: !9, scopeLine: 157, flags: DIFlagPrototyped, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition | DISPFlagOptimized, unit: !1, templateParams: !10)
!54 = !DINamespace(name: "{impl#179}", scope: !28)
!55 = distinct !DILocation(line: 24, column: 21, scope: !47)
!56 = !DILocation(line: 180, column: 28, scope: !51, inlinedAt: !55)
!57 = !DILocation(line: 659, column: 28, scope: !58, inlinedAt: !59)
!58 = distinct !DISubprogram(name: "add<u32>", linkageName: "_ZN4core3ptr8non_null16NonNull$LT$T$GT$3add17h78cf1a556b1b6058E", scope: !37, file: !17, line: 651, type: !9, scopeLine: 651, flags: DIFlagPrototyped, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition | DISPFlagOptimized, unit: !1, templateParams: !10)
!59 = distinct !DILocation(line: 185, column: 40, scope: !51, inlinedAt: !55)
!60 = !DILocation(line: 2178, column: 9, scope: !61, inlinedAt: !63)
!61 = distinct !DISubprogram(name: "write_volatile<u32>", linkageName: "_ZN4core3ptr14write_volatile17hb20ce68506a148d8E", scope: !20, file: !62, line: 2167, type: !9, scopeLine: 2167, flags: DIFlagPrototyped, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition | DISPFlagOptimized, unit: !1, templateParams: !10)
!62 = !DIFile(filename: "/home/.rustup/toolchains/stable-aarch64-apple-darwin/lib/rustlib/src/rust/library/core/src/ptr/mod.rs", directory: "", checksumkind: CSK_MD5, checksum: "8f706ae0a0620120e6e931983ef127f1")
!63 = distinct !DILocation(line: 25, column: 22, scope: !64)
!64 = distinct !DILexicalBlock(scope: !47, file: !6, line: 24, column: 9)
!65 = !DILocation(line: 27, column: 6, scope: !45)
!66 = distinct !DISubprogram(name: "bucket", linkageName: "_ZN5vault6bucket17hb1b20723cde11643E", scope: !8, file: !6, line: 37, type: !9, scopeLine: 37, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition | DISPFlagOptimized, unit: !1, templateParams: !10)
!67 = !DILocation(line: 39, column: 5, scope: !68)
!68 = distinct !DILexicalBlock(scope: !69, file: !6, line: 39, column: 5)
!69 = distinct !DILexicalBlock(scope: !66, file: !6, line: 38, column: 5)
!70 = !DILocation(line: 0, scope: !66)
!71 = !DILocation(line: 1720, column: 9, scope: !16, inlinedAt: !72)
!72 = distinct !DILocation(line: 180, column: 28, scope: !23, inlinedAt: !73)
!73 = distinct !DILocation(line: 39, column: 17, scope: !68)
!74 = !DILocation(line: 180, column: 28, scope: !23, inlinedAt: !73)
!75 = !DILocation(line: 40, column: 32, scope: !76)
!76 = distinct !DILexicalBlock(scope: !68, file: !6, line: 39, column: 5)
!77 = !DILocation(line: 43, column: 2, scope: !66)
!78 = !DILocation(line: 659, column: 28, scope: !36, inlinedAt: !79)
!79 = distinct !DILocation(line: 185, column: 40, scope: !23, inlinedAt: !73)
!80 = !DILocation(line: 2457, column: 13, scope: !40, inlinedAt: !81)
!81 = distinct !DILocation(line: 40, column: 19, scope: !76)
!82 = distinct !DISubprogram(name: "open_once", linkageName: "_ZN5vault9open_once17he76d7a6438ba1d15E", scope: !8, file: !6, line: 30, type: !9, scopeLine: 30, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition | DISPFlagOptimized, unit: !1, templateParams: !10)
!83 = !DILocation(line: 31, column: 22, scope: !82)
!84 = !DILocation(line: 32, column: 11, scope: !85)
!85 = distinct !DILexicalBlock(scope: !82, file: !6, line: 31, column: 5)
!86 = !DILocation(line: 34, column: 2, scope: !82)
