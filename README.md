# Remote-Heap — Initial Exploit

This is my initial, local version of the exploit developed while working on the Remote-Heap challenge

This version runs the target binary locally using `process()` instead of connecting to a remote service

**Important:** The libc base address is not leaked through an exploit vulnerability in this version. Instead, it is obtained from the local process mappings using pwntools' `p.libs()`:

```python
libs = p.libs()

libc_base = next(
    base for path, base in libs.items()
    if path.endswith("/libc.so.6")
)
```

This approach retrieves the mapped base address of libc from the local process and is intended for local testing, not remote exploitation

This script represents the initial version of my work on the challenge
