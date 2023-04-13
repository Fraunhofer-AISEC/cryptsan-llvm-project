# Optimizations in LLVM 12.0.1

## Commands

  Clang: `echo 'int;' | clang -xc -O0 - -o /dev/null -\#\#\#`
  LLVM: `llvm-as < /dev/null | opt -O0 -disable-output -debug-pass=Arguments`

## Level: O0

### Clang

- Adds:
  - mrelax-all
  - mrelax-relocations
  - mrelocation-model static
  - mframe-pointer=all
  - mconstructor-aliases
  - munwind-tables

### LLVM

- Adds:
  - tti
  - verify
  - ee-instrument
  - targetlibinfo
  - assumption-cache-tracker
  - profile-summary-info
  - annotation2metadata
  - forceattrs
  - basiccg
  - always-inline
  - annotation-remarks

## Level: O1

### Clang

- Removes:
  - mrelax-all

- Adds:
  - mframe-pointer=none

### LLVM

- Removes: Nothing
- Adds:
  - tbaa
  - scoped-noalias-aa
  - simplifycfg
  - domtree
  - sroa
  - early-cse
  - lower-expect
  - inferattrs
  - ipsccp
  - called-value-propagation
  - globalopt
  - mem2reg
  - deadargelim
  - basic-aa
  - aa
  - loops
  - lazy-branch-prob
  - lazy-block-freq
  - opt-remark-emitter
  - instcombine
  - globals-aa
  - prune-eh
  - function-attrs
  - memoryssa
  - early-cse-memssa
  - libcalls-shrinkwrap
  - postdomtree
  - branch-prob
  - block-freq
  - pgo-memop-opt
  - reassociate
  - loop-simplify
  - lcssa-verification
  - lcssa
  - scalar-evolution
  - loop-rotate
  - licm
  - loop-unswitch
  - loop-idiom
  - indvars
  - loop-deletion
  - loop-unroll
  - phi-values
  - memdep
  - memcpyopt
  - sccp
  - demanded-bits
  - bdce
  - adce
  - barrier
  - rpo-function-attrs
  - globaldce
  - float2int
  - lower-constant-intrinsics
  - loop-accesses
  - loop-distribute
  - inject-tli-mappings
  - loop-vectorize
  - loop-load-elim
  - vector-combine
  - transform-warning
  - alignment-from-assumptions
  - strip-dead-prototypes
  - cg-profile
  - loop-sink
  - instsimplify
  - div-rem-pairs

## Level: O2

### Clang

- Removes: Nothing
- Adds: Nothing

### LLVM

- Removes:
  - always-inline

- Adds:
  - inline
  - openmpopt
  - speculative-execution
  - lazy-value-info
  - jump-threading
  - correlated-propagation
  - tailcallelim
  - mldst-motion
  - gvn
  - dse
  - elim-avail-extern
  - slp-vectorizer
  - constmerge

## Level: O3

### Clang

- Removes: Nothing
- Adds: Nothing

### LLVM

- Adds:
  - callsite-splitting
  - argpromotion
  - aggressive-instcombine
