# `web3-codec-protobuf` -- the vendored `ocaml_protoc_plugin` runtime

This is the runtime library of [ocaml-protoc-plugin][] 6.2.0, vendored with its
ppx pre-expanded. It carries two hand edits -- see "The patches" below. One is
a memory-safety fix.

It was extracted from `ocaml-cometbft/lib/proto/runtime/`, which vendored it
first. Every chain library in this tree that speaks protobuf needs the same
runtime -- CometBFT does today, Tron does now, Sui's RPC v2 will -- and a third
copy is one copy too many. The generated bindings stay in the repository that
owns the schema; only the runtime and the generator invocation are shared.
`ocaml-cometbft` has not yet been migrated onto this package.

The library name `ocaml_protoc_plugin` is not a choice: the plugin emits
`module Runtime' = Ocaml_protoc_plugin` into every generated file, so the
runtime must be reachable under exactly that name. A consumer writes
`(libraries web3-codec-protobuf)` and the generated code resolves unchanged.

## Why vendor it

The generated bindings need this runtime, and the runtime itself is tiny --
`(libraries base64 ptime)`, both fine for a unikernel. The *package*, however,
depends on `ppx_expect`, `ppx_inline_test`, `omd`, `conf-protoc` and
`conf-pkg-config`, because those are what building and testing the code
generator needs.

That cone makes `opam monorepo lock` fail outright: `omd` pulls `uutf`/`uunf`/
`uucp`, `conf-protoc` wants a `protoc` binary at build time, and several have no
Dune port. So a MirageOS/Solo5 unikernel could not vendor its dependencies at
all while `cometbft-proto` depended on the package.

Vendoring the runtime alone cuts the dependency to `base64` + `ptime` and the
unikernel builds. nethsm's `etcd_client` reached the same conclusion
independently; this follows its recipe.

Neither `base64` nor `ptime` depends on `unix`, so this package links into a
Solo5 unikernel. That must stay true.

## Regenerating

The ppx is only used for inline tests, so expanding under the *release* profile
removes it entirely -- under `dev` the expansion leaves calls to
`Ppx_inline_test_lib` and `Expect_test_collector` behind, which would put those
libraries back in the dependency cone.

```sh
opam source ocaml-protoc-plugin --dir=/tmp/opp
cd /tmp/opp
mkdir -p pp/src/ocaml_protoc_plugin
for i in src/ocaml_protoc_plugin/*.ml; do
  # dune prints compiler diagnostics on stdout *after* the expanded source, so
  # they have to be cut off or they end up inside the vendored .ml files.
  dune describe pp "$i" --profile release 2>/dev/null \
    | sed '/^File "src\/ocaml_protoc_plugin\//,$d' > "pp/$i"
done
cp src/ocaml_protoc_plugin/*.mli  <repo>/lib/protobuf/
cp pp/src/ocaml_protoc_plugin/*.ml <repo>/lib/protobuf/
```

Then check nothing crept back in:

```sh
grep -c 'Ppx_inline_test_lib\|Expect_test_collector' lib/protobuf/*.ml
grep -l '^File "src/' lib/protobuf/*.ml
```

## The patches

### `validate_capacity` -- a memory-safety fix

`reader.ml`'s bounds check compares `t.offset + count <= t.end_offset`. `count`
is `Int64.to_int` of a varint the sender chose, so a large value overflows the
addition to a negative int, the comparison succeeds, and
`read_length_delimited` hands `deserialize.ml` an out-of-range length. That
reaches `String.unsafe_blit`, and the process segfaults reading past the end of
the buffer.

85 bytes of random input reach it. No caller-side guard can help: a segfault is
not an exception, so `Result.catch` and any `try ... with` around `from_proto`
are equally useless.

The fix compares against the remaining space -- `count >= 0 && count <=
t.end_offset - t.offset` -- which cannot overflow, because both offsets are in
range for the buffer and their difference is therefore a non-negative int.

Found by `ocaml-tron`'s `fuzz/fuzz_raw_data.ml`. **This should be reported
upstream**; any project decoding untrusted protobuf with this library is
exposed.

### `apply_lazy` -- a laziness fix

`apply_lazy` in `ocaml_protoc_plugin.ml` is unconditionally lazy here.
Upstream gates the lazy path on `Sys.backend_type`, taking it only for
non-native backends.

That gate assumes native initialisation order is always safe. It is not.
Every message in a `.proto` file lands in a single `module rec`, and the
thunks `apply_lazy` wraps close over `spec ()`, which names the message's
field types. When a message is declared before one it refers to, forcing the
thunk during initialisation raises `Undefined recursive module` -- on native
as much as on Melange.

Tron's schema hits this: `ResourceReceipt` is declared before `Transaction`
and its `result` field is a `Transaction.Result.ContractResult`. CometBFT's
schema happens not to, which is why the runtime worked there untouched.

The change is upstream's own, ungated. [PR #27, "feat: lazier
runtime"][pr27], introduced `apply_lazy` for precisely this failure on
Melange. The native case should be reported upstream, after which this patch
goes away. Cost is one `Lazy.force` on a memoised thunk per call, on a code
path upstream already runs for every Melange build.

This patch is necessary but **not sufficient**. The plugin also emits each
message's `merge` as an eager module-level binding, outside any thunk, and
that has the same problem. `tools/lazify-merge.py` defers those at generation
time. Either fix alone still raises; both are required.

Re-vendoring per the recipe above drops **both** patches. Re-apply them: without
the first, malformed input can segfault the process; without the second, the
generated Tron bindings crash on start-up rather than at a diagnosable point.

## Generating bindings

`tools/gen-protobuf.sh` at the root of this repository wraps the `protoc`
invocation, including the parameters that must not drift between consumers.
Generated sources are committed by the consuming repository, so building a
consumer needs neither `protoc` nor the `ocaml-protoc-plugin` binary.

[ocaml-protoc-plugin]: https://github.com/andersfugmann/ocaml-protoc-plugin
[pr27]: https://github.com/andersfugmann/ocaml-protoc-plugin/pull/27
