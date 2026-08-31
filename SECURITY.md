# Security policy

These codecs process attacker-controlled network and signed data and remain
unaudited alphas. Report vulnerabilities privately to `security@reuna.io`; do
not publish a crashing or memory-safety reproducer before a coordinated fix is
available.

## Review boundary

Review every length, offset, recursion depth, allocation and canonical-form
check before extending a parser. Differential fixtures must come from an
independent implementation, and fuzz regressions must retain the smallest
reproducer.

Fuzzing the vendored protobuf reader previously found an integer-overflow bounds
check that reached `String.unsafe_blit` out of bounds. The local runtime fixes
that defect. Because a native segfault is not an OCaml exception, callers
cannot compensate with `try`; the parser itself and its bounds are the security
boundary.
