# cve-2018-19134_ghostscript_arbitrary_rw_demo

Demonstrates arbitrary read/write over Ghostscript's heap by exploiting a type confusion in `zsetcolor` (CVE-2018-19134, fixed in Ghostscript 9.26).

## How it works

`zsetcolor` retrieves a pattern instance from a dictionary's "Implementation" field and casts it to `gs_pattern_instance_t *` without validating the ref type. By supplying a crafted PostScript array as the Implementation, the exploit controls the struct's `type` pointer, redirecting its `procs.get_pattern` and `procs.uses_base_space` function pointers to `zpop` and `zucache`.

`zpop` decrements `op_stack.stack.p` (osp) by `sizeof(ref)` = 16 bytes without dereferencing the pointed-to memory. `zucache` is a no-op. By overlaying a target array's ref at the fake `i_ctx_t` offset 0x270 (where `osp` lives), each `setpattern` call subtracts 16 from the array's `type_attrs` field. After ~1288 iterations the two-byte `type_attrs` wraps from `t_array` (4) to `t_string` (18), converting the array into a string whose `value.bytes` pointer still addresses the original ref storage — exposing it as raw bytes for direct read/write.

## Setup

Requires a Ghostscript version vulnerable to CVE-2018-19134 (fixed in 9.26). We use [ghostscript_version_graveyard](https://github.com/w0ot-net/ghostscript_version_graveyard) to run Ghostscript 9.18 via Docker.

Copy the example config and adjust paths if needed:

```bash
cp gs.conf.example gs.conf
```

`gs.conf` is gitignored so you can point it at your local graveyard checkout.

## Running

```bash
./run.sh
```

Expected output:

```
CVE-2018-19134 type confusion succeeded after 1288 iterations.

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
Arbitrary read/write over 32767 bytes of Ghostscript heap memory.
```

## Acknowledgments

Based on the research by Man Yue Mo: [Exploiting CVE-2018-19134: Ghostscript RCE through type confusion](https://securitylab.github.com/research/cve-2018-19134-ghostscript-rce/).
