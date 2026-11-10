# rust-vault

A small Cargo workspace for seethru tests.

`vault/src/lib.rs` divides a value that the code wipes after use (`Vault::slot`) and a value it never wipes (`bucket`). Only the first is a finding.

`compiled/` holds the output of this command, so tests do not need a Rust toolchain for `aarch64-unknown-none`.

```
RUSTFLAGS="--emit=llvm-ir,asm -C debuginfo=line-tables-only --remap-path-prefix=$PWD=." \
  cargo build --release --target aarch64-unknown-none
```
