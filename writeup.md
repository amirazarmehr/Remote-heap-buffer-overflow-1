# ELF x64 - Remote Heap buffer overflow 1 — Writeup

**Category:** pwn / heap exploitation
**Arch:** x86-64 ELF, dynamically linked
**Protections (verify with `checksec`):** PIE/RELRO/ASLR status should be confirmed on your own copy before relying on anything below — this writeup assumes a GOT that's writable (Partial RELRO or no RELRO).

## TL;DR

`Remote-Heap` is a small heap-management service (`new` / `free` / `modif` / `show` commands over stdin). Allocating a user name is missing 3 bytes from its `malloc()` size, giving a small, fully-controlled heap overflow. That overflow is enough to forge a chunk's size field and force `malloc()` to return a chunk that overlaps an existing object. Using that overlap twice gets us:

1. An **arbitrary-read primitive** (leak a GOT entry via the `show` command) → libc base.
2. An **arbitrary-write primitive** (overwrite `strcmp`'s GOT entry with `system`) → shell, because the program's own `get_id()` passes attacker-controlled input as the first argument to `strcmp()` on every `free`.

Full PoC: [`exploit.py`](./exploit.py).

## 1. The service

The binary implements a tiny in-memory user database:

```
new <name>     -- allocate a new user, with a random 128-char ID
show           -- list all users: index, ID, NAME
modif <id> <s> -- replace a user's NAME with s
free <id>      -- free a user (looked up by its random ID string)
```

Each user is two heap allocations:

```
user struct (malloc(0x90)):
  +0x00  8 bytes   name_ptr        -> pointer to the separate name buffer
  +0x08  4 bytes   name_buf_size   -> bookkeeping used by modif
  +0x0c  128 bytes random ID string, NUL-terminated at +0x8b

name buffer (malloc(len + 1)):
  +0x00  3 bytes   "U__"           -> fixed magic prefix written by new_user
  +0x03  len bytes attacker-controlled name
  +0x03+len  1 byte 0x00           -> terminator
```

`user_list[i]` is a pointer to the struct; `get_id(str)` linearly scans `user_list`, `strcmp()`-ing `str` against each struct's stored ID, and returns the matching index (or `-1`).

## 2. The bug: a 3-byte heap overflow in `new_user`

```c
// new_user (decompiled)
pvVar4 = malloc(len + 1);          // allocates  len + 1  bytes
*(uint*)pvVar4 = 0x5f5f55;          // writes "U__\0" at offsets 0..3
memcpy(pvVar4 + 3, name, len);      // writes offsets 3 .. len+2
*(char*)(pvVar4 + len + 3) = 0;     // writes offset len+3
```

The function writes `len + 4` bytes (offsets `0` through `len+3`) into a buffer that only has `len + 1` usable bytes (offsets `0` through `len`). That's a **3-byte overflow**, and the last two of those three bytes are fully attacker-controlled — they're just the tail of whatever `name` you send; only the final byte is a fixed `0x00`.

Three bytes isn't enough to write a full fake chunk header, but it's exactly the classic "off-by-few" primitive used to corrupt the **low byte(s) of the next chunk's size field** in the heap. Clearing the right bits also lets `free()`'s sanity checks pass on a chunk whose real size no longer matches its recorded size — the standard setup for forcing **overlapping chunks**.

`modif_user` doesn't share this bug (its `realloc()` size accounts correctly for the data it writes), but it's still useful: it lets us overwrite a chunk's contents starting at offset `0`, with no `"U__"` prefix in the way, which is what we need once an overlap is in place.

## 3. The leak primitive: `show_users`

```c
// show_users (decompiled)
printf("NAME = %s\n", *(void**)user_list[i]);   // dereferences name_ptr, no validation
```

`show` prints whatever `name_ptr` points to, as a C string, with zero validation that it's an address the program actually allocated. If we can make a user's `name_ptr` field (struct offset `+0x00`) equal to an arbitrary address, `show` becomes an **arbitrary-memory-read** gadget.

## 4. Exploit chain

### Phase 1 — leak libc via `GOT[free]`

1. Create three users `A`, `B`, `C`.
2. Use `modif` on `A`'s name to trigger the overflow and forge the size field of `B`'s adjacent chunk.
3. `free B`, then `new` with a payload whose first 8 bytes (after padding) are `GOT[free]`. The corrupted free-list now hands back a chunk that overlaps `B`'s struct, with `B`'s `name_ptr` field aliasing attacker-controlled data — set it to `GOT[free]`.
4. `show`: `B`'s `NAME` field now prints the raw bytes stored at `GOT[free]`.

`free()` is called by `free_user` itself (and `puts`/`printf` are called before any input is even read), so `GOT[free]` is already resolved to its real libc address by this point. The leak gives us:

```
leak_bytes (6-7 usable, printf("%s") stops at the embedded NUL)
  -> pad to 8 with \x00
  -> free_addr = u64(leak)
  -> libc_base = free_addr - libc.symbols['free']
  -> system_addr = libc_base + libc.symbols['system']
```

> **Partial leak gotcha:** user-space addresses on x86-64 Linux have a `0x00` high byte, so `%s` truncates the leak early. `recv(6)` + `ljust(8, b"\x00")` before `u64()` is required.

### Phase 2 — hijack `GOT[strcmp]` → `system`

Repeat the exact same overlap technique on three fresh users `X`, `Y`, `Z`, this time targeting `GOT[strcmp]` instead of `GOT[free]`:

1. `modif X` to forge the size field of `Y`'s chunk.
2. `free Y`, then `new` with a payload whose embedded pointer is `GOT[strcmp]` — same overlap trick, now aliasing `Y`'s `name_ptr` onto `GOT[strcmp]`.
3. `modif Z <system_addr packed as 8 bytes>` — because of the overlap, this write lands directly in `GOT[strcmp]`, replacing it with `system`'s address.

### Phase 3 — trigger

`get_id()` is called by `free_user` on every `free <id>` command and does:

```c
strcmp(id_string, stored_id);
```

With `GOT[strcmp]` now pointing at `system`, this call becomes `system(id_string)`. So:

```
free /bin/sh
```

executes `system("/bin/sh")`, and `/bin/sh`'s calling convention lines up for free — `id_string` is already in the first-argument register the way `strcmp` expects its first argument, which is also exactly where `system` expects its command string.

### Heap-state caveat

Each phase performs two `free()`s per `free_user` call (name buffer *and* struct) plus a large overlap allocation, which leaves a leftover tcache-sized chunk behind. Phase 2 was built to re-run the exact same offset arithmetic as phase 1 on a *clean-looking* heap, but the leftover chunk from phase 1 means it isn't actually clean — reusing the same indices caused glibc's tcache double-free check (`key` field, glibc ≥ 2.29) to abort. The fix was a throwaway allocation (`new E`) between phases, sized to absorb that leftover chunk before grooming the heap for phase 2. This is called out explicitly in [`exploit.py`](./exploit.py) — don't copy the offset constants between phases without accounting for whatever the previous phase left behind in the free lists.

## 5. Primitive summary

| Primitive | How |
|---|---|
| Heap overflow (3 bytes, 2 controlled) | `new_user`'s `malloc(len+1)` vs. `len+4` bytes written |
| Forge next chunk's size | `modif` an existing user with a payload ending in the forged size byte |
| Chunk overlap | `free` the size-corrupted chunk, then `new` with the target address as fake data |
| Arbitrary read | Overlap onto a struct's `name_ptr`, then `show` |
| Arbitrary write | Overlap onto a struct's `name_ptr`, then `modif` |
| Code execution | GOT-overwrite `strcmp` → `system`, triggered via `free_user`'s internal `get_id()` call |

## 6. PoC

See [`exploit.py`](./exploit.py). Requires `pwntools`. Tested against a local `process()` instance; for a remote target, replace the libc leak step's `libc_base` source with the remote libc (don't rely on `p.libs()` — it only works for locally-spawned processes) and use the libc matching the target's actual deployed version.

## 7. Root cause / fix

- `new_user`: allocate `len + 4` bytes, not `len + 1`.
- `show_users` / any function dereferencing `name_ptr`: this is a design smell more than a single bug — a response to any heap-exploitation challenge class of issue is to enable Full RELRO (makes the GOT read-only, blocking the write primitive) and use a hardened allocator (e.g., tcache safe-linking in glibc ≥ 2.32) that would turn the forged-`fd` overlap trick into an abort instead of a working primitive.
