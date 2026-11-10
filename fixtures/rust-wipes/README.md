# rust-wipes

A small program for seethru tests. It clears memory in three ways, and a release build keeps only two of them.

- `removed` fills a key with zeros as its last use (`key.fill(0)`, line 19). Nothing reads the key afterwards, so the compiler deletes the write. This is the finding.
- `kept` writes zeros with `write_volatile`, which the compiler must keep.
- `clear` fills a buffer that the caller reads afterwards, so the write stays.

The tests build it with `seethru scan --build --tool objdump --tool dwarfdump` and expect one `memory-wipe-removed` finding.
