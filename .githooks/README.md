# Git hooks

Repository-tracked git hooks for lneto.

## Enable

```sh
git config core.hooksPath .githooks
```

This is per-clone and opt-in (git never runs tracked hooks automatically).

## pre-commit

Runs [`scripts/check-allocs.sh`](../scripts/check-allocs.sh) against the staged
Go files. lneto targets bare-metal/embedded systems, so hot paths must avoid
ungated heap allocation — a slice grown directly from untrusted network data is
an out-of-memory (OOM) vector.

The check does two things:

1. **Advisory** — runs Go escape analysis (`go build -gcflags=-m`) over the
   changed packages and lists every `make`/`append`/`new`/closure/`map` in the
   changed production files that escapes to the heap. These are not necessarily
   bugs; confirm each is **bounded and configurable** (sized once from a
   user-supplied cap and reused) rather than growing with untrusted input. See
   `dhcpv6.Limits` and `tcp.Handler.SetReassemblyBuffer` for the pattern.
   Advisory findings do **not** block the commit.

2. **Enforced** — runs the allocation-regression tests
   (`testing.AllocsPerRun`, named `*NoAllocs` / `*ZeroAlloc` / `*no-allocs`) in
   the changed packages. A failure means a path asserted to be allocation-free
   regressed, and the commit is blocked.

You can run the same check manually at any time:

```sh
scripts/check-allocs.sh            # staged files
scripts/check-allocs.sh ./path/to/file.go
```

Bypass once with `git commit --no-verify`.
