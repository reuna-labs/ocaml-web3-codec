#!/bin/bash
#
# Generate OCaml protobuf bindings for a consuming repository.
#
# The bindings a chain library needs are specific to that chain's schema, so
# they live in that repository and are COMMITTED there: building a consumer
# needs neither protoc nor the ocaml-protoc-plugin binary. Only the runtime
# (web3-codec-protobuf, lib/protobuf/) and this invocation are shared.
#
# Extracted from ocaml-cometbft/gen.sh, generalised over the proto tree and the
# file list. The flags below are the shared part and are deliberately not
# parameterised -- see "Why these flags" at the bottom.
#
# requires: opam install ocaml-protoc-plugin   (and a protoc on PATH)
#
# usage:
#   gen-protobuf.sh -I <proto-dir> -o <out-dir> [-g <google-out-dir>] \
#       [-p <plugin-param>] \
#       <file.proto> [<file.proto> ...] [-- <google/protobuf/x.proto> ...]
#
# example (ocaml-tron):
#   tools/gen-protobuf.sh -I ./proto -o ./lib/proto/gen \
#     core/Tron.proto core/contract/balance_contract.proto \
#     -- google/protobuf/any.proto

set -eu

proto_dir=""
out_dir=""
google_out=""
files=()
google_files=()
# Extra plugin parameters, appended to the shared ones. Empty by default: the
# flags below are the shared part and stay that way. See "Plugin parameters"
# at the bottom for the one schema that needs this.
extra_params=""

while [ $# -gt 0 ]; do
  case "$1" in
    -I) proto_dir="$2"; shift 2 ;;
    -o) out_dir="$2"; shift 2 ;;
    -g) google_out="$2"; shift 2 ;;
    -p) extra_params="$extra_params;$2"; shift 2 ;;
    --) shift
        while [ $# -gt 0 ]; do google_files+=("$1"); shift; done ;;
    -*) echo "unknown flag: $1" >&2; exit 2 ;;
    *)  files+=("$1"); shift ;;
  esac
done

if [ -z "$proto_dir" ] || [ -z "$out_dir" ] || [ "${#files[@]}" -eq 0 ]; then
  sed -n '/^# usage:/,/^$/p' "$0" >&2
  exit 2
fi

command -v protoc >/dev/null || {
  echo "protoc not on PATH" >&2; exit 1; }

# The well-known types are generated into a subdirectory so that a consumer's
# dune can flatten both into one library with (include_subdirs unqualified),
# which is what makes cross-file references such as
# Any.Google.Protobuf.Any resolve without qualification.
[ -n "$google_out" ] || google_out="$out_dir/google_types"

set -x

rm -rf "$out_dir"
mkdir -p "$out_dir" "$google_out"

params="int64_as_int=false$extra_params"

protoc -I "$proto_dir" \
  "--ocaml_out=$params:$out_dir" \
  "${files[@]}"

# The well-known types are generated with the SAME parameters, not the default
# ones. ocaml-protoc-plugin requires it: a parameter that changes module or
# file naming -- prefix_output_with_package is the one in use -- has to be
# applied to every dependency too, or the generated cross-file references do
# not resolve.
if [ "${#google_files[@]}" -gt 0 ]; then
  protoc "--ocaml_out=$params:$google_out" "${google_files[@]}"
fi

# Defer the module-level `merge` bindings. Without this, a schema whose earlier
# messages reference later ones -- Tron's does -- raises "Undefined recursive
# module" the moment the generated module is initialised. See
# tools/lazify-merge.py for the full account and the upstream reference.
"$(dirname "$0")/lazify-merge.py" $(find "$out_dir" -name '*.ml')

# Why these flags
#
#   int64_as_int=false
#     Balances, block heights, gas, vote power and fee limits are genuine
#     int64 across every schema this is used for, and OCaml's int is 63-bit.
#     Truncating a balance is not a diagnosable failure; it is a wrong number.
#
#   -p prefix_output_with_package=true   (Cosmos only, so far)
#     ocaml-protoc-plugin names an output file after the .proto's basename.
#     Most schemas have unique basenames; Cosmos does not -- cosmos/bank,
#     cosmos/tx, ibc/applications/transfer and cosmwasm/wasm all define a
#     tx.proto, and there are three keys.proto and two query.proto besides.
#     Without the prefix the plugin reports "Tried to write the same file
#     twice" and emits nothing. With it, output is named after the full
#     protobuf package, which is unique by construction.
#
#     It is not the default because it lengthens every module name, and a
#     schema that does not need it should not pay for it.
#
#   no annot=[@@deriving show]
#     Without ppx_deriving wired into the library the attribute is silently
#     ignored, and wiring it in would put a ppx and a runtime library into the
#     one package a unikernel is guaranteed to link. Keeping the generated
#     library at exactly base64 + ptime is worth more than derived printers.
#     Write the printers that matter by hand, in the consuming repository.
