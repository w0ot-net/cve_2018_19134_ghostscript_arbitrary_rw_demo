# cve-2018-19134_ghostscript_arbitrary_rw_demo

Exploits a type confusion in `zsetcolor` (CVE-2018-19134, fixed in Ghostscript 9.26) to produce address-arbitrary read/write matching the [ghostscript_exploitation_library](https://github.com/w0ot-net/ghostscript_exploitation_library) API contract.

## How it works

`zsetcolor` retrieves a pattern instance from a dictionary's "Implementation" field and casts it to `gs_pattern_instance_t *` without validating the ref type. By supplying a crafted PostScript array as the Implementation, the exploit controls the struct's `type` pointer, redirecting its `procs.get_pattern` and `procs.uses_base_space` function pointers to `zpop` and `zucache`.

`zpop` decrements `op_stack.stack.p` (osp) by `sizeof(ref)` = 16 bytes without dereferencing the pointed-to memory. `zucache` is a no-op. The exploit probes at runtime to find which ref index within the fake struct overlaps `osp`, then selects the appropriate exploitation technique:

**TAS mode** (GS 9.08–9.25): `osp` overlaps a ref's `type_attrs` field. Repeated `setpattern` calls subtract 16 from `type_attrs` until it wraps from `t_array` (4) to `t_string` (18), converting the array into a string whose `value.bytes` pointer still addresses the original ref storage — exposing it as raw bytes for direct byte-level read/write.

A master/slave upgrade then turns this ~32KB window into full address-arbitrary r/w: a slave string's ref struct within the window is repointed on each call by overwriting its `value.bytes` field through the master, and re-fetched via a `getinterval` sub-array that shares the underlying storage. This produces `read_bytes(addr, len)` and `write_bytes(addr, bytes)` matching the library's `rw_init` contract. A leaked code pointer (`zput` address from arr[0]'s ref struct) is provided as `code_ptr`.

**VALUE mode** (GS 8.64–9.07): `osp` overlaps a ref's `value` field (the element pointer). Each `setpattern` call shifts the array's view backward over heap memory by `sizeof(ref)` per `zpop` call, providing ref-level read/write across object boundaries.

VALUE mode cannot produce address-arbitrary byte-level access: PostScript's array `put` writes full 16-byte typed refs, so there is no way to independently rewrite a string ref's 8-byte `value.bytes` pointer — the master/slave upgrade that TAS mode uses is structurally impossible at ref granularity. Similarly, array `get` on a string ref returns its content, not its raw backing pointer, so address discovery via self-reference (as TAS mode does) is also unavailable. VALUE mode therefore cannot integrate with the library.

## Setup

Requires a Ghostscript version vulnerable to CVE-2018-19134 (fixed in 9.26). We use [ghostscript_version_graveyard](https://github.com/w0ot-net/ghostscript_version_graveyard) to run old Ghostscript versions via Docker.

Copy the example config and adjust paths if needed:

```bash
cp gs.conf.example gs.conf
```

`gs.conf` is gitignored so you can point it at your local graveyard checkout.

## Running

Standalone (demo output):

```bash
./run.sh
```

With the exploitation library (registers `rw_init`, enables `mem_*` / ELF / `gs_exec`):

```bash
source gs.conf
$GS_RUN $GS_VERSION -- -dNOSAFER -dBATCH -dNOPAUSE -dNODISPLAY -dQUIET \
    /path/to/library.ps /work/exploit.ps
```

When `library.ps` is loaded first, the exploit auto-detects the library and calls `rw_init` with `read_bytes`, `write_bytes`, `code_ptr`, and `scratch`. Subsequent PostScript can then use the full `mem_*` API, ELF resolution, and `gs_exec`.

## Tested versions

| Version | Mode | op_stack.p offset | Library |
|---------|------|-------------------|---------|
| 8.63 | — | — | setpattern path does not reach vulnerable code |
| 8.64 | VALUE | pinst[31] (504) | no — ref-level `put` cannot repoint a string's backing pointer |
| 8.71 | VALUE | pinst[31] (504) | no — same structural limitation |
| 9.01 | VALUE | pinst[38] (616) | no — 32-bit integers |
| 9.06 | VALUE | pinst[38] (616) | no — same structural limitation |
| 9.10 | TAS | pinst[39] (624) | **rw_init OK** |
| 9.14 | TAS | pinst[39] (624) | **rw_init OK** |
| 9.18 | TAS | pinst[39] (624) | **rw_init OK** |
| 9.20 | TAS | pinst[39] (624) | **rw_init OK** |
| 9.22 | TAS | pinst[39] (624) | **rw_init OK** |
| 9.26 | — | — | patched |

The exploit auto-detects the correct offset and mode at runtime.

## Example output (GS 9.18, TAS mode with library)

```
CVE-2018-19134 type confusion succeeded after 1288 iterations.
Mode: TAS at pinst[39]  (byte offset 624)
code_ptr: 0x00007A11A5BF20C0
mem_base: 0x000000001BE962C8
read_bytes / write_bytes registered (address-arbitrary r/w).

[+] rw_init succeeded -- library seam active.
```

## Example output (GS 9.18, TAS mode standalone)

```
CVE-2018-19134 type confusion succeeded after 1288 iterations.
Mode: TAS at pinst[39]  (byte offset 624)
code_ptr: 0x000076ABE587D0C0
mem_base: 0x000000003289D058
read_bytes / write_bytes registered (address-arbitrary r/w).

[*] library not loaded; read_bytes / write_bytes available for manual use.
[*] To activate the full exploitation chain, load library.ps before this file.
```

## Example output (GS 8.64, VALUE mode)

```
CVE-2018-19134 pointer-shift primitive established.
Mode: VALUE at pinst[31]  (byte offset 504)
Shift rate: 3 refs (48 bytes) per setpattern call

=== ARBITRARY WRITE ===
Writing integer 42424242 through shifted[3] (= arr[0]):

  Write via shifted pointer:  42424242
  Read-back via original arr: 42424242

=== ARBITRARY READ ===
Reading 3 refs (48 bytes) before arr's original storage:

  [arr - 1 ref]: int = 1337
  [arr - 2 ref]: int = 7331
  [arr - 3 ref]: int = 9999

=== RESULT ===
Arbitrary ref-level read/write over 524320 bytes of Ghostscript heap memory.

NOTE: VALUE mode provides ref-level access only.
The library API requires address-arbitrary byte-level r/w (TAS mode, GS 9.10-9.25).
```

## Acknowledgments

Based on the research by Man Yue Mo: [Exploiting CVE-2018-19134: Ghostscript RCE through type confusion](https://securitylab.github.com/research/cve-2018-19134-ghostscript-rce/).
