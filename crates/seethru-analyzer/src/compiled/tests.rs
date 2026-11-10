use super::asm::{self, Naming};
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
        Op::Call { callee: Callee::Opaque, args, .. } if args.is_empty()
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

#[test]
fn reads_division_instructions_with_their_source_lines() {
    let listing = asm::parse(
        "\t.file\t1 \"/work\" \"src/a.rs\"\n\t.file\t2 \"/rust/core/num.rs\"\nf:\n\t.loc\t1 7 3 prologue_end\n\tudiv\tw0, w0, w1\n\t.loc\t2 90 1\n\tbl\t__aeabi_uidivmod\n\t.loc\t1 8 1\n\tdivss\t%xmm0, %xmm1\n\tmul\tx0, x0, x1\n",
        Naming::Plain,
    );
    assert!(listing.has_lines);
    let found: Vec<(Option<&str>, &str, u32)> = listing
        .divisions
        .iter()
        .map(|spot| (spot.function.as_deref(), spot.path.as_str(), spot.line))
        .collect();
    assert_eq!(
        found,
        [
            (Some("f"), "/rust/core/num.rs", 90),
            (Some("f"), "/work/src/a.rs", 7)
        ]
    );
}

#[test]
fn records_the_function_each_division_instruction_is_in() {
    let text = "\t.file\t1 \"/work\" \"src/a.rs\"\n\t.globl\t_first\n_first:\nLfunc_begin0:\n\t.loc\t1 3 1\nLBB0_2:\n\tudiv\tw0, w0, w1\nltmp4:\n\tsdiv\tw0, w0, w1\n\t; InlineAsm Start\nretry:\n\tudiv\tw2, w2, w3\n\t; InlineAsm End\n_second:\n\tudiv\tw0, w0, w1\n\t.loc\t1 0 0\n\tudiv\tw0, w0, w1\n\t.loc\t1 9 1\n\tudiv\tw0, w0, w1\n";
    let listing = asm::parse(text, Naming::of("\"e-m:o-i64:64\""));
    let functions: Vec<&str> = listing.functions.iter().map(String::as_str).collect();
    assert_eq!(functions, ["first", "second"]);
    let found: Vec<(Option<&str>, u32)> = listing
        .divisions
        .iter()
        .map(|spot| (spot.function.as_deref(), spot.line))
        .collect();
    assert_eq!(found, [(Some("first"), 3), (Some("second"), 9)]);
    assert!(listing.divides(Some("first"), "/work/src/a.rs", 3));
    assert!(!listing.divides(Some("second"), "/work/src/a.rs", 3));
    assert!(listing.divides(None, "/work/src/a.rs", 9));

    let elf = asm::parse(
        "\t.file\t1 \"src/a.rs\"\nLoad:\n\t.loc\t1 3 1\n.Ltmp0:\n\tdivl\t%ecx\n$local:\n\tdivl\t%ecx\n",
        Naming::of("\"e-m:e-p270:32:32\""),
    );
    let functions: Vec<&str> = elf.functions.iter().map(String::as_str).collect();
    assert_eq!(functions, ["Load"]);
    assert_eq!(elf.divisions.len(), 1);
}
