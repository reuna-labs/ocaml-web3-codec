#!/usr/bin/env python3
"""Defer the `merge` bindings ocaml-protoc-plugin emits at module level.

The plugin emits, for every message:

    let merge =
    let merge_<field> = Runtime'.Merge.merge Runtime'.Spec.( ... ) in
    ...
    fun t1 t2 -> { ... }

Those `let merge_<field> = ...` bindings sit outside the `fun`, so they run
when the module is initialised. When a field's spec names another message --
`(enum (module Foo.Bar))`, or a default such as `Foo.Bar.from_int_exn 0` --
that forces `Foo`. Every message in a .proto file lands in one
`module rec`, so if `Foo` is declared *after* the message referring to it,
forcing it during initialisation raises `Undefined recursive module`.

Tron hits this: `ResourceReceipt` is declared before `Transaction` and its
`result` field is a `Transaction.Result.ContractResult`. CometBFT's schema
happens not to, which is why the same runtime works there untouched.

Upstream knows this failure mode -- andersfugmann/ocaml-protoc-plugin#27,
"feat: lazier runtime", added `Runtime'.apply_lazy` for exactly it. That fix
covers the serialisers, and only on Melange:

    let apply_lazy f = match Sys.backend_type with
      | Native | Bytecode -> f ()
      | Other _ -> ...lazy...

`merge` was not covered, and native was assumed safe. Making the runtime
unconditionally lazy does not help: the eager bindings are in the generated
code, not the runtime. Verified by patching it and re-running.

So this script defers `merge` the same way `apply_lazy` defers the
serialisers. The body is unchanged; it is evaluated once, on first call,
by which time the recursive module is initialised.

The rewrite is anchored on a shape the plugin emits without exception: a
bare `let merge =` line, and the next binding at the same or lower indent is
always `let spec () =`. The script asserts both, and asserts it rewrote at
least one site, so a future plugin version that changes the shape fails the
build loudly rather than silently emitting code that crashes at start-up.

Report upstream and delete this once it lands there.
"""

import re
import sys

MERGE = re.compile(r"^(\s*)let merge =\s*$")
BINDING = re.compile(r"^(\s*)let (\w+)")


def lazify(text, path):
    lines = text.split("\n")
    out = []
    i = 0
    rewritten = 0
    while i < len(lines):
        m = MERGE.match(lines[i])
        if not m:
            out.append(lines[i])
            i += 1
            continue

        indent = m.group(1)
        # Find the end of the merge body: the next binding at the same or lower
        # indent that is not one of merge's own `let merge_<field> = ... in`.
        end = None
        for j in range(i + 1, len(lines)):
            b = BINDING.match(lines[j])
            if b and len(b.group(1)) <= len(indent) and not lines[j].lstrip().startswith("let merge_"):
                if b.group(2) != "spec":
                    raise SystemExit(
                        f"{path}:{j + 1}: expected `let spec` after `let merge`, "
                        f"found `let {b.group(2)}`. The plugin's output shape changed; "
                        f"re-check tools/lazify-merge.py before trusting it."
                    )
                end = j
                break
        if end is None:
            raise SystemExit(f"{path}:{i + 1}: unterminated `let merge` body")

        body = lines[i + 1 : end]
        out.append(f"{indent}let merge =")
        out.append(f"{indent}  (* deferred by tools/lazify-merge.py; see that file *)")
        out.append(f"{indent}  let merge' = lazy (")
        out.extend(body)
        out.append(f"{indent}  ) in")
        out.append(f"{indent}  fun t1' t2' -> (Lazy.force merge') t1' t2'")
        rewritten += 1
        i = end

    return "\n".join(out), rewritten


def main(paths):
    total = 0
    for path in paths:
        with open(path, encoding="utf-8") as f:
            text = f.read()
        new, n = lazify(text, path)
        if n:
            with open(path, "w", encoding="utf-8") as f:
                f.write(new)
        total += n
    if total == 0:
        raise SystemExit(
            "lazify-merge.py rewrote nothing. Either the plugin stopped emitting "
            "`merge`, or its shape changed; check before assuming this is fine."
        )
    print(f"lazify-merge: deferred {total} merge bindings across {len(paths)} files")


if __name__ == "__main__":
    main(sys.argv[1:])
