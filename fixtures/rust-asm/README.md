# rust-asm

A small library for seethru tests. It has no program, only a library, and three blocks of hand-written assembly. The blocks exist for x86_64 and aarch64.

- `reduce` reads a word of a key that the code wipes afterwards and divides it inside an `asm!` block (line 24 on x86_64, line 28 on aarch64). The compiler cannot see into the block, so only the machine code shows the division. This is the finding.
- `spin` has a block with a conditional jump. It is listed, and it is not a finding.
- `settle` has a block with neither.
- `share` divides a public value in plain Rust. It is listed as a division seethru did not tie to a secret.

The tests build it with `seethru scan --build` and read the `machineCode` part of the report.
