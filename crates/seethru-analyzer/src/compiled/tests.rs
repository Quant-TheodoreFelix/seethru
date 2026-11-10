use super::asm::{self, Cpu, Naming};
use super::ir::{self, Callee, Op};

const TEXT: &str = r#"define { ptr, i64 } @"_ZN4demo$LT$T$GT$4pick17h0E"(ptr noundef %base, i64 range(i64 0, 9) %at) unnamed_addr #3 !dbg !4 {
start:
  %slot = getelementptr inbounds nuw i8, ptr %base, i64 %at, !dbg !7
  %pair = tail call noundef range(i32 0, 5) i32 @helper(ptr noundef nonnull %slot, i32 3), !dbg !7
  call void asm sideeffect "dsb sy, (x)", "~{memory}"(), !dbg !7
  %both = phi ptr [ %slot, %start ], [ %base, %other ]
  call void @llvm.memcpy.p0.p0.i64(ptr %base, ptr %slot, i64 8, i1 false)
  store volatile <2 x i32> <i32 0, i32 0>, ptr %slot, align 4, !dbg !8
  %q = sdiv i32 %pair, 7
  ret { ptr, i64 } zeroinitializer
}

attributes #3 = { noinline optnone }
!1 = !DIFile(filename: "src/a, b.rs", directory: "/work\5Cdir")
!4 = distinct !DISubprogram(name: "pick<T>", file: !1, line: 3)
!5 = distinct !DISubprogram(name: "drop_in_place<demo::Key>", file: !1, line: 20)
!6 = !DILocation(line: 9, column: 1, scope: !4)
!7 = !DILocation(line: 4, column: 9, scope: !4)
!8 = !DILocation(line: 21, column: 5, scope: !5, inlinedAt: !6)
"#;

#[test]
fn reads_functions_calls_and_debug_places() {
    let module = ir::parse(TEXT);
    assert_eq!(module.functions.len(), 1);
    let function = &module.functions[0];
    assert_eq!(function.symbol, "_ZN4demo$LT$T$GT$4pick17h0E");
    assert_eq!(function.params.len(), 2);
    assert!(function.unoptimized);
    let ops: Vec<&Op> = function.body.iter().map(|i| &i.op).collect();
    assert!(matches!(ops[0], Op::Offset { base: Some(_), indexes } if indexes.len() == 1));
    assert!(matches!(
        ops[1],
        Op::Call { callee: Callee::Function(name), args, returns_pointer: false }
            if name == "helper" && args.len() == 2 && args[1].is_none()
    ));
    assert!(matches!(
        ops[2],
        Op::Call { callee: Callee::Assembly, args, .. } if args.is_empty()
    ));
    assert!(matches!(ops[3], Op::Alias { of } if of.len() == 2));
    assert!(matches!(
        ops[4],
        Op::Call { callee: Callee::Copy, args, .. } if args.len() == 4
    ));
    assert!(matches!(
        ops[5],
        Op::Store {
            volatile: true,
            value: None,
            ptr: Some(_)
        }
    ));
    assert!(matches!(ops[6], Op::Divide { by_variable: false, operands } if operands.len() == 1));
    assert!(function.body[5].automatic);
    assert!(!function.body[0].automatic);
    let frames = module.frames(8);
    let lines: Vec<(&str, u32)> = frames.iter().map(|f| (f.path.as_str(), f.line)).collect();
    assert_eq!(
        lines,
        [
            ("/work\\dir/src/a, b.rs", 21),
            ("/work\\dir/src/a, b.rs", 9)
        ]
    );
}

type Row<'a> = (Option<&'a str>, Option<(&'a str, u32)>, u32);

fn spots(listing: &asm::Listing) -> Vec<Row<'_>> {
    listing
        .divisions
        .iter()
        .map(|(spot, count)| {
            let place = spot
                .place
                .as_ref()
                .map(|(path, line)| (path.as_ref(), *line));
            (spot.function.as_deref(), place, *count)
        })
        .collect()
}

#[test]
fn reads_division_instructions_with_their_source_lines() {
    let listing = asm::parse(
        "\t.file\t1 \"/work\" \"src/a.rs\"\n\t.file\t2 \"/rust/core/num.rs\"\nf:\n\t.loc\t1 7 3 prologue_end\n\tudiv\tw0, w0, w1\n\tudiv\tw2, w2, w1\n\t.loc\t2 90 1\n\tbl\t__aeabi_uidivmod\n\t.loc\t1 8 1\n\tdivss\t%xmm0, %xmm1\n\tmul\tx0, x0, x1\n",
        Naming::Plain,
        Cpu::Arm64,
    );
    assert!(listing.has_lines);
    assert_eq!(
        spots(&listing),
        [
            (Some("f"), Some(("/rust/core/num.rs", 90)), 1),
            (Some("f"), Some(("/work/src/a.rs", 7)), 2)
        ]
    );
}

#[test]
fn records_the_function_each_division_instruction_is_in() {
    let text = "\t.file\t1 \"/work\" \"src/a.rs\"\n\t.globl\t_first\n_first:\nLfunc_begin0:\n\t.loc\t1 3 1\nLBB0_2:\n\tudiv\tw0, w0, w1\nltmp4:\n\tsdiv\tw0, w0, w1\n\t; InlineAsm Start\nretry:\n\tudiv\tw2, w2, w3\n\t; InlineAsm End\n_second:\n\tudiv\tw0, w0, w1\n\t.loc\t1 0 0\n\tudiv\tw0, w0, w1\n\t.loc\t1 9 1\n\tudiv\tw0, w0, w1\n";
    let listing = asm::parse(text, Naming::of("\"e-m:o-i64:64\""), Cpu::Arm64);
    let functions: Vec<&str> = listing.functions.iter().map(AsRef::as_ref).collect();
    assert_eq!(functions, ["first", "second"]);
    assert_eq!(
        spots(&listing),
        [
            (Some("first"), Some(("/work/src/a.rs", 3)), 2),
            (Some("second"), None, 2),
            (Some("second"), Some(("/work/src/a.rs", 9)), 1),
        ]
    );
    assert!(listing.divides(Some("first"), "/work/src/a.rs", 3));
    assert!(!listing.divides(Some("second"), "/work/src/a.rs", 3));
    assert!(listing.divides(None, "/work/src/a.rs", 9));
    let by_hand: Vec<(Option<&str>, u32, u32, bool)> = listing
        .by_hand
        .iter()
        .map(|(spot, block)| {
            (
                spot.function.as_deref(),
                block.blocks,
                block.divisions,
                block.branches,
            )
        })
        .collect();
    assert_eq!(by_hand, [(Some("first"), 1, 1, false)]);

    let elf = asm::parse(
        "\t.file\t1 \"src/a.rs\"\nLoad:\n\t.loc\t1 3 1\n.Ltmp0:\n\tdivl\t%ecx\n$local:\n\tdivl\t%ecx\n",
        Naming::of("\"e-m:e-p270:32:32\""),
        Cpu::X86,
    );
    assert_eq!(spots(&elf), [(Some("Load"), Some(("src/a.rs", 3)), 2)]);
}

#[test]
fn reads_a_division_that_runs_only_when_a_condition_holds() {
    let text = "\t.file\t1 \"src/a.rs\"\nwork:\n\t.loc\t1 7 5\n\titttt\tne\n\tldrne\tr0, [r0]\n\tudivne\tr2, r0, r1\n\tmlsne\tr0, r2, r1, r0\n\tbxne\tlr\n";
    let thumb = asm::parse(text, Naming::Plain, Cpu::Arm);
    assert_eq!(spots(&thumb), [(Some("work"), Some(("src/a.rs", 7)), 1)]);
    let other = asm::parse(text, Naming::Plain, Cpu::X86);
    assert!(other.divisions.is_empty());
}

#[test]
fn reads_division_helpers_and_vector_forms_the_way_each_target_spells_them() {
    let call =
        "\t.file\t1 \"src/a.rs\"\n_work:\n\t.loc\t1 7 5\n\tbl\t___udivti3\n\tcallq\t___umodti3\n";
    let mach_o = asm::parse(call, Naming::Underscored, Cpu::Arm64);
    assert_eq!(spots(&mach_o), [(Some("work"), Some(("src/a.rs", 7)), 2)]);
    let elf = asm::parse(call, Naming::Plain, Cpu::Arm64);
    assert!(elf.divisions.is_empty());

    let vectors = "\t.file\t1 \"src/a.rs\"\nwork:\n\t.loc\t1 7 5\n\tvdivu.vv\tv0, v1, v2\n\tvrem.vx\tv0, v1, a0\n\tvadd.vv\tv0, v1, v2\n\tsdivr\tz0.s, p0/m, z0.s, z1.s\n";
    let riscv = asm::parse(vectors, Naming::Plain, Cpu::RiscV);
    assert_eq!(spots(&riscv), [(Some("work"), Some(("src/a.rs", 7)), 3)]);
    let arm = asm::parse(vectors, Naming::Plain, Cpu::Arm64);
    assert_eq!(spots(&arm), [(Some("work"), Some(("src/a.rs", 7)), 1)]);
}

#[test]
fn markers_that_do_not_pair_up_are_reported_as_a_partial_read() {
    let paired = asm::parse("work:\n\t#APP\n\tnop\n\t#NO_APP\n", Naming::Plain, Cpu::X86);
    assert!(!paired.truncated);
    for text in [
        "work:\n\t#APP\n\tnop\n",
        "work:\n\t#NO_APP\n\tnop\n",
        "work:\n\t#APP\n\t#APP\n\tnop\n\t#NO_APP\n",
    ] {
        assert!(
            asm::parse(text, Naming::Plain, Cpu::X86).truncated,
            "{text:?}"
        );
    }
}

#[test]
fn a_chain_of_places_that_loops_ends() {
    let module = ir::parse(
        "define i32 @f(i32 %a) !dbg !4 {\nstart:\n  %r = urem i32 %a, %a, !dbg !7\n  ret i32 %r\n}\n\n!1 = !DIFile(filename: \"src/a.rs\", directory: \"\")\n!4 = distinct !DISubprogram(name: \"f\", file: !1, line: 1)\n!7 = !DILocation(line: 2, column: 5, scope: !99, inlinedAt: !7)\n!8 = !DILocation(line: 3, column: 5, scope: !4, inlinedAt: !8)\n",
    );
    assert!(module.frames(7).is_empty());
    assert_eq!(module.frames(8).len(), 64);
}

fn region(open: &str, close: &str, body: &str) -> String {
    format!("\t.file\t1 \"src/a.rs\"\nwork:\n\t.loc\t1 5 9\n\t{open}\n{body}\t{close}\n\tret\n")
}

#[test]
fn reads_hand_written_blocks_in_every_marker_style() {
    let cases = [
        (
            "#APP",
            "#NO_APP",
            "\n\txorl\t%edx, %edx\n\tdivl\t%esi\n\n",
            Cpu::X86,
            (1, false),
        ),
        (
            "#APP",
            "#NO_APP",
            "\n.Ltmp16:\n\tdecq\t%rax\n\tjne\t.Ltmp16\n\n",
            Cpu::X86,
            (0, true),
        ),
        (
            "#APP",
            "#NO_APP",
            "\n\tjmp\t.Ltmp2\n\tcmovnel\t%eax, %ecx\n\n",
            Cpu::X86,
            (0, false),
        ),
        (
            "## InlineAsm Start",
            "## InlineAsm End",
            "\n\tdivl\t%esi\n\n",
            Cpu::X86,
            (1, false),
        ),
        (
            "; InlineAsm Start",
            "; InlineAsm End",
            "Ltmp15:\n\tsubs\tx0, x0, #1\n\tb.ne\tLtmp15\n",
            Cpu::Arm64,
            (0, true),
        ),
        (
            "//APP",
            "//NO_APP",
            "\tudiv\tw0, w9, w1\n\tcbz\tw0, .Ltmp3\n",
            Cpu::Arm64,
            (1, true),
        ),
        (
            "//APP",
            "//NO_APP",
            "\t// keep x0 \n\tbl\thelper\n\tb\t.Ltmp3\n",
            Cpu::Arm64,
            (0, false),
        ),
        (
            "@APP",
            "@NO_APP",
            ".Ltmp20:\n\tsubs\tr0, r0, #1\n\tbne\t.Ltmp20\n",
            Cpu::Arm,
            (0, true),
        ),
        (
            "@APP",
            "@NO_APP",
            "\tudiv\tr0, r3, r1\n\tbl\thelper\n\tbics\tr0, r1\n\tblx\tr2\n",
            Cpu::Arm,
            (1, false),
        ),
        ("@APP", "@NO_APP", "\tbls.n\t.Ltmp1\n", Cpu::Arm, (0, true)),
        (
            "#APP",
            "#NO_APP",
            "\tdivuw\ta2, a3, a1\n\tbnez\ta0, .Ltmp19\n",
            Cpu::RiscV,
            (1, true),
        ),
        (
            "#APP",
            "#NO_APP",
            "\taddi\ta0, a0, -1\n\tj\t.Ltmp19\n",
            Cpu::RiscV,
            (0, false),
        ),
        (
            "#APP",
            "#NO_APP",
            "\tbeq\t$1, $2, .Ltmp1\n",
            Cpu::Other,
            (0, false),
        ),
    ];
    for (open, close, body, cpu, (divisions, branches)) in cases {
        let listing = asm::parse(&region(open, close, body), Naming::Plain, cpu);
        let blocks: Vec<(Row<'_>, u32, bool)> = listing
            .by_hand
            .iter()
            .map(|(spot, block)| {
                let place = spot
                    .place
                    .as_ref()
                    .map(|(path, line)| (path.as_ref(), *line));
                (
                    (spot.function.as_deref(), place, block.blocks),
                    block.divisions,
                    block.branches,
                )
            })
            .collect();
        assert_eq!(
            blocks,
            [(
                (Some("work"), Some(("src/a.rs", 5)), 1),
                divisions,
                branches
            )],
            "{open} {body:?}"
        );
        assert!(listing.divisions.is_empty(), "{open} {body:?}");
        let functions: Vec<&str> = listing.functions.iter().map(AsRef::as_ref).collect();
        assert_eq!(functions, ["work"], "{open} {body:?}");
    }
}

#[test]
fn a_comment_that_only_mentions_a_marker_does_not_open_a_block() {
    let listing = asm::parse(
        "\t.file\t1 \"src/a.rs\"\nwork:\n\t.loc\t1 5 9\n\t# APP data follows\n\t#NO_APP\n\tdivl\t%esi\n\t#APP\n\tnop\n\t#APP\n\tnop\n\t#NO_APP\n\t#APP\n\tnop\n",
        Naming::Plain,
        Cpu::X86,
    );
    assert_eq!(spots(&listing), [(Some("work"), Some(("src/a.rs", 5)), 1)]);
    let blocks: Vec<u32> = listing.by_hand.values().map(|block| block.blocks).collect();
    assert_eq!(blocks, [2]);
}

#[test]
fn reads_the_processor_and_naming_rules_of_a_module() {
    let module = ir::parse(
        "target datalayout = \"e-m:o-i64:64-i128:128-n32:64-S128-Fn32\"\ntarget triple = \"arm64-apple-macosx11.0.0\"\n\nmodule asm \".globl raw\"\n",
    );
    assert_eq!(module.naming, Naming::Underscored);
    assert_eq!(module.cpu, Cpu::Arm64);
    assert!(module.file_assembly);
    let plain = ir::parse("target triple = \"x86_64-unknown-none-elf\"\n");
    assert_eq!(plain.naming, Naming::Plain);
    assert_eq!(plain.cpu, Cpu::X86);
    assert!(!plain.file_assembly);
    for (triple, cpu) in [
        ("i686-pc-windows-msvc", Cpu::X86),
        ("aarch64-unknown-none", Cpu::Arm64),
        ("thumbv7em-unknown-none-eabi", Cpu::Arm),
        ("armv7-unknown-linux-gnueabihf", Cpu::Arm),
        ("riscv64", Cpu::RiscV),
        ("wasm32-unknown-unknown", Cpu::Other),
        ("powerpc64le-unknown-linux-gnu", Cpu::Other),
    ] {
        assert_eq!(Cpu::of(&format!("\"{triple}\"")), cpu, "{triple}");
    }
}

#[test]
fn a_call_to_hand_written_assembly_is_told_apart_from_other_calls() {
    let module = ir::parse(
        "define i32 @f(i32 %by, i32 %value, ptr %table) {\nstart:\n  %1 = tail call { i32, i32 } asm sideeffect inteldialect \"xor edx, edx\\0Adiv ${2:k}\", \"=&{ax},=&{dx},r,0,~{dirflag},~{fpsr},~{flags}\"(i32 %by, i32 %value) #5, !dbg !20, !srcloc !23\n  call void asm sideeffect \"dsb sy, (x)\", \"~{memory}\"(), !dbg !20\n  %2 = call i32 %table(i32 %by)\n  %3 = call i32 @\"asm\"(i32 %by)\n  callbr void asm sideeffect \"cbnz ${0}, ${1:l}\", \"r,!i,~{cc}\"(i32 %value) #1\n          to label %bb1 [label %bb3], !dbg !11, !srcloc !12\n  ret i32 %2\n}\n",
    );
    let callees: Vec<(&Callee, usize, Option<u32>)> = module.functions[0]
        .body
        .iter()
        .filter_map(|instruction| match &instruction.op {
            Op::Call { callee, args, .. } => Some((callee, args.len(), instruction.debug)),
            _ => None,
        })
        .collect();
    assert_eq!(
        callees,
        [
            (&Callee::Assembly, 2, Some(20)),
            (&Callee::Assembly, 0, Some(20)),
            (&Callee::Opaque, 1, None),
            (&Callee::Function("asm".to_owned()), 1, None),
            (&Callee::Assembly, 1, Some(11)),
        ]
    );
}
