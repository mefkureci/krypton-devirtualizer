# Krypton (Continuation Fork)

A **.NET Reactor devirtualizer** focused on producing a runnable, standalone devirtualized
output — not just a disassembly report. It reconstructs VM-protected methods back into real
CIL, recovers hidden call sites, restores NecroBit-stubbed method bodies, decrypts protected
strings/resources, and validates the result with automated load/JIT/differential checks —
all through a generic engine with no per-target hardcoding.

## Credits

This repository is based on the original work by PeterG75:

- Upstream: [https://github.com/PeterG75/Krypton](https://github.com/PeterG75/Krypton)

Huge credit to the upstream project for the foundation. This fork extends the pipeline,
runtime stability, and build workflow for modern `net8.0` usage, and adds a substantially
larger reconstruction engine on top (see [Releases](#releases) for what changed).

## What This Repo Does

Krypton processes a virtualized/protected assembly and reconstructs it back into ordinary,
readable IL:

1. `ResourceParsing` - locates the VM payload and decodes its layout (operands, strings, method keys).
2. `OpcodeMapping` - finds the handler switch method and maps VM byte -> semantic opcode via
   pattern matching, cross-method discrimination, and constraint solving (stack/CFG/type/data-flow).
3. `MethodDisassembling` - disassembles VM methods into an intermediate model.
4. `SemanticValidation` - runs a VM semantic validator (CFG + stack effects) and adjusts unsafe,
   low-confidence mappings; tracks anchors to a sound fixpoint.
5. `MethodRecompiling` - translates the VM model back into compilable CIL.
6. `MethodReplacing` - replaces virtualized method bodies with the recompiled ones.
7. `HiddenCallRecovery` - recovers .NET Reactor "Hide Method Calls" delegate-proxy stubs back
   into direct calls, including generic method signatures (nested generics, arrays, pointers,
   byref, assembly-scoped generic arguments).
8. `PostDeobfuscation` - renames obfuscated members, inlines trivial wrappers, simplifies
   control flow, and neutralizes leftover protection runtime.
9. `StringDecryption` - inlines .NET Reactor string-decoder call sites as literals (opt-in).
10. `ResourceDecryption` - restores AES+deflate protected embedded resources (opt-in).
11. **NecroBit body restoration** - detects stub-shaped method bodies left behind by the
    protector's runtime body-swap mechanism, captures the real bodies via a sandboxed runtime
    pass, and reinjects them with correct locals/EH/maxstack.

Every classification and reconstruction step is evidence-driven (static structure + sandboxed
runtime capture) rather than hardcoded per-sample - the same engine runs unmodified against any
.NET Reactor-protected input.

## Practical Goal

This fork targets a devirtualized output that:
- preserves original runtime behavior,
- starts without native runtime crashes,
- remains executable and readable (in dnSpy/ILSpy) after full reconstruction,
- has no functional dependency on the .NET Reactor runtime.

## Build

### Requirements
- Windows x64 (tested/recommended)
- `.NET SDK 8.0 or newer`

### Recommended build
From repository root:

```powershell
powershell -ExecutionPolicy Bypass -File .\build-all.ps1 -Configuration Release
```

The script performs:
1. restore for main projects,
2. build for `Krypton.Core` and `Krypton.Pipeline`,
3. serial build for `Krypton` launcher (to avoid intermittent static-graph MSBuild restore/build edge cases).

### Manual build (Release Rebuild)
```powershell
dotnet build .\Krypton.Core\Krypton.Core.csproj -c Release -t:Rebuild
dotnet build .\Krypton.Pipeline\Krypton.Pipeline.csproj -c Release -t:Rebuild
dotnet msbuild .\Krypton\Krypton.csproj /t:Rebuild /p:Configuration=Release /m:1
```

One-liner equivalent:
```powershell
dotnet build .\Krypton.Core\Krypton.Core.csproj -c Release -t:Rebuild; dotnet build .\Krypton.Pipeline\Krypton.Pipeline.csproj -c Release -t:Rebuild; dotnet msbuild .\Krypton\Krypton.csproj /t:Rebuild /p:Configuration=Release /m:1
```

`Krypton.Runner` (the isolated `net48` sandbox host used for runtime capture/validation) builds
as part of `Krypton.sln`:
```powershell
dotnet build .\Krypton.Runner\Krypton.Runner.csproj -c Release
```

### Tests
```powershell
dotnet test Krypton.sln -c Release
```

## Run
```powershell
dotnet .\Krypton\bin\Release\net8.0\Krypton.dll <input-assembly.exe> --no-pause
```

or:
```powershell
.\Krypton\bin\Release\net8.0\Krypton.exe <input-assembly.exe> --no-pause
```

### Drag and drop usage (Windows)
You can drag a target `.exe` (or `.dll`) file directly onto `Krypton.exe`.
Krypton receives the dropped file path as argument and runs devirtualization for that input.

## Output
For `sample.exe`:
- patched output: `sample-Devirtualized.exe`
- report: `sample-Devirtualized-report.txt`

## Useful Environment Variables

### UX / logging
- `KRYPTON_NO_PAUSE=1`
- `KRYPTON_LOG_VM_MAP=1`
- `KRYPTON_LOG_LOCAL_TYPES=1`
- `KRYPTON_LOG_EXCEPTIONS=1`

### Mapping behavior
- `KRYPTON_ENABLE_AGGRESSIVE_LAST_RESORT=1` (enables aggressive tie-breaks in rare-opcode inference; default is strict/safety-first)
- `KRYPTON_STRICT_MAPPING=1` (rejects any non-exact opcode assignment)
- `KRYPTON_GLOBAL_STACK_SOLVER=1` (enables the cross-method stack-constraint solver for ambiguous bytes)
- `KRYPTON_TYPE_CONSTRAINTS=1` (enables type-flow constraint anchoring)

### NecroBit body restoration
- `KRYPTON_ENABLE_NECROBIT_BODY_RESTORE=1` / `KRYPTON_DISABLE_NECROBIT_BODY_RESTORE=1`

### Runtime stabilization
- `KRYPTON_DISABLE_HASHTABLE_SANITIZE=1`
- `KRYPTON_DISABLE_WINFORMS_GUARD_BYPASS=1`
- `KRYPTON_DISABLE_STRING_ANTI_MANIPULATION_PATCH=1`
- `KRYPTON_DISABLE_SHARED_BOOTSTRAP_NEUTRALIZE=1`
- `KRYPTON_DISABLE_STARTUP_GUARD=1`
- `KRYPTON_DISABLE_ALL_BOOTSTRAP_CCTORS=1`

### Hidden-call recovery and cleanup
- `KRYPTON_HCR_ENABLE=0` (disables `HiddenCallRecovery`; on by default)
- `KRYPTON_CLEAN_ENABLE=0` (master kill-switch for `PostDeobfuscation`; on by default)
- `KRYPTON_STRING_DECRYPT=1` (enables `StringDecryption`; off by default)
- `KRYPTON_RESOURCE_DECRYPT=1` (enables `ResourceDecryption`; off by default)

### Write / patch behavior
- `KRYPTON_ALLOW_PARTIAL_OUTPUT=1` (allows writing when some VM opcodes remain unresolved)
- `KRYPTON_ALLOW_STABILIZATION_ONLY_OUTPUT=1` (allows output even with zero recompiled methods, applying only stabilization patches)
- `KRYPTON_USE_INPLACE_PATCH=1` (forces in-place patch mode instead of default rewrite mode)
- `KRYPTON_STRIP_MALFORMED_ATTRIBUTES=1`

There are additional low-level tuning/diagnostic variables for the opcode-scoring, semantic
validation, and cleanup stages (`KRYPTON_LOG_*`, `KRYPTON_DUMP_*`, `KRYPTON_CLEAN_*`, `KRYPTON_VM_TRACE_*`);
the ones above cover normal usage. Grep the pipeline sources for `KRYPTON_` for the full set.

## Krypton.Runner

`Krypton.Runner` is a `net48` sandbox host used by the pipeline (and available standalone) to
capture runtime-only evidence without ever touching network/disk from the target assembly:
type-initializer execution, JIT preparation, NecroBit body materialization, hidden-call target
resolution, and keyed-string evaluation. Two diagnostic modes worth knowing about:

- `--standalone-check <exe>` - loads the assembly, runs every type initializer, and
  JIT-prepares every method; reports failures grouped by exception kind. This is the core
  regression harness used to compare a devirtualized output against its original baseline.
- `--necrobit-body-dump-all <exe> <out.json>` - classifies every method by on-disk body shape,
  then captures the real materialized body for every detected stub in one deterministic,
  resumable pass (no manual token lists).

## Auxiliary Tooling (`tools/`)

The repository includes helper utilities for pattern and runtime investigation:
- `PatternProbe`
- `HandlerDump`
- `MethodFullDump`
- `MethodBodyPayloadProbe`
- `ProtectionMap`

These tools help during opcode mapping extension, payload-body inspection, and protection-regression analysis.

## Known Limitations
- Not all Reactor families are fully covered; mapping still depends on observable handler patterns.
- If unknown VM bytes remain, affected methods are intentionally skipped (safety-first).
- A small number of opcode bytes can be provably ambiguous from static+runtime evidence alone
  (e.g. inside self-verifying anti-tamper routines); these are handled via explicit
  method-local semantic-equivalence proofs or neutralized rather than guessed.

## Recommended Roadmap
1. Fully generalize pattern verification (less name-based hints, more signature/data-flow based matching).
2. Extend coverage for remaining opcodes in very large methods (for example `<Module>` and complex UI flows).
3. Add automated multi-sample test matrix (build + devirt + smoke-run).
4. Add before/after metrics export for objective validation.

## Releases

See [GitHub Releases](https://github.com/dawwinci/krypton-devirtualizer/releases) for tagged
builds and full changelogs. Highlights of the current release:

- **Full CLR opcode universe coverage** for the VM instruction set: added the missing
  arithmetic/overflow, unsigned, conversion, and comparison-branch families to a single
  self-validating opcode catalog (`VMOpCodeCatalog`) that fails fast if the enum and its
  metadata ever drift apart, instead of hand-maintained tables scattered across the pipeline.
- **Generic hidden-call signature reconstruction**: fixed a depth-tracking bug that silently
  broke *all* generic-type parsing in call-site reconstruction, added the missing primitive
  element types, and added support for the reflection-style assembly-qualified generic name
  format alongside dnlib's own format - together these close an entire class of
  `MissingMethodException` failures on generic-instance return/parameter types (nested
  generics, arrays, pointers, byref, assembly-scoped type arguments all supported).
  Cross-checked with a corlib-vs-facade-assembly scope-resolution fix so imports bind to the
  runtime's real declaring assembly instead of a forwarding facade.
  See [`Krypton.Pipeline/Stages/HiddenCallRecovery.cs`](Krypton.Pipeline/Stages/HiddenCallRecovery.cs).
- **Correct maxstack on reinjected bodies**: method bodies rebuilt from captured NecroBit IL
  now keep their captured `MaxStackSize` instead of relying on auto-recomputation, which could
  undercount and produce an invalid program. Closes a class of `InvalidProgramException`
  failures on reinjected bodies.
- **Wholesale NecroBit restoration**: `--necrobit-body-dump-all` replaces one-off, per-method
  body capture with a single deterministic, resumable, assembly-wide pass that classifies every
  method by on-disk shape and captures every detected stub's real body through the sandboxed
  runtime host - no manual token lists.
- **Bulk keyed-string evidence at scale**: keyed-string evaluation now batches through an
  `@file` argument instead of individual command-line arguments, removing the OS command-line
  length ceiling when resolving thousands of decoder sites in one pass.
- **New generic standalone validation harness** (`--standalone-check`): loads the output,
  runs every type initializer and JIT-prepares every method, and reports failures grouped by
  exception kind - the baseline regression tool used to confirm a devirtualized output matches
  its original assembly's runtime behavior exactly, with no restoration-introduced failures.
- **New cross-method opcode discrimination stages**: `GlobalStackConstraintSolver`,
  `TypeConstraintAnchoring`, `KnownPlaintextCryptoAnchoring`, `DispatcherValidation`,
  `SoundOpcodeFixpoint`/`SoundOpcodeInventory`, and `BoundedStateWorklist` - a set of opt-in,
  evidence-only solvers that resolve otherwise-ambiguous VM opcode bytes using cross-method
  stack/CFG/type/data-flow constraints and runtime-observed plaintext, without ever voting,
  scoring, or guessing a mapping into existence.

All of the above were validated end-to-end against real .NET Reactor-protected binaries during
development (full pipeline run, whole-assembly `--standalone-check` regression against the
original baseline, and differential output comparison) - sample-specific artifacts are kept out
of this repository (see `.gitignore`), but the fixes themselves are fully generic and apply to
any Reactor-protected input.

## Disclaimer
This project is intended for research, interoperability, and technical understanding of
virtualized/obfuscated code in lawful contexts (e.g. security research, malware analysis,
recovering your own legitimately-owned software). Do not use it against software you do not
have the right to analyze.
