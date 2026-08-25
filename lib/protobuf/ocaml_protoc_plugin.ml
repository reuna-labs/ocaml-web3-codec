[@@@ocaml.ppx.context
{
  tool_name = "ppx_driver";
  include_dirs = [];
  hidden_include_dirs = [];
  load_path = ([], []);
  open_modules = [];
  for_package = None;
  debug = false;
  use_threads = false;
  use_vmthreads = false;
  recursive_types = false;
  principal = false;
  transparent_modules = false;
  unboxed_types = false;
  unsafe_string = false;
  cookies =
    [ ("inline_tests", "disabled"); ("library-name", "ocaml_protoc_plugin") ];
}]

module Json = Json
module Reader = Reader
module Writer = Writer
module Service = Service
module Result = Result
module Extensions = Extensions
module Json_options = Json_options

[@@@ocaml.text "/*"]

module Serialize = Serialize
module Deserialize = Deserialize
module Serialize_json = Serialize_json
module Deserialize_json = Deserialize_json
module Spec = Spec
module Field = Field
module Merge = Merge

(* REUNA PATCH -- the one hand edit in this vendored runtime.
   Upstream restricts the lazy path to non-native backends:

     match Sys.backend_type with
     | Native | Bytecode -> f ()
     | Other _ -> ...lazy...

   That gate assumes native initialisation order is always safe. It is not.
   Every message in a .proto file lands in one `module rec`, and these
   thunks close over `spec ()`, which names the message's field types. When a
   message is declared before one it refers to -- Tron's `ResourceReceipt`
   refers to `Transaction.Result.ContractResult` -- forcing the thunk during
   initialisation raises `Undefined recursive module` on native too.

   The fix is upstream's own, ungated: andersfugmann/ocaml-protoc-plugin#27,
   "feat: lazier runtime", which introduced this function for the identical
   failure on Melange. Report the native case upstream and drop this patch
   once it lands.

   Cost is one `Lazy.force` on a memoised thunk per call. The lazy path is
   not novel code -- upstream runs it for every Melange build.

   `merge` needs the same treatment and is not routed through here; that is
   handled by tools/lazify-merge.py at generation time. Both are required:
   either alone still raises. *)
let apply_lazy f =
  let f = Lazy.from_fun f in
  fun x -> (Lazy.force f) x
[@@ocaml.doc " Apply lazy binding, so that generated code never forces a\n    recursive module during initialisation. "]

[@@@ocaml.text "/*"]
