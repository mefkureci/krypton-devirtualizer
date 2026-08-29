# Krypton Pipeline Hardening — Design

Date: 2026-08-29
Status: Approved for planning

## Context

Krypton devirtualizes `.NET Reactor`-protected assemblies. Five gaps were
identified by direct code inspection (file/line references below reflect the
state of `main` at the time of writing). Each gap causes either silent
incorrect output, a crash on load (`InvalidProgramException`), or a
regression suite that can't actually catch either.

## 1. Full CLR opcode universe (self-validating catalog)

**Problem.** `Krypton.Core/Architecture/VMOpCode.cs` defines ~40 opcode
values. The real CLR instruction set is ~220 values
(`AsmResolver.PE.DotNet.Cil.CilCode`). Any obfuscated method whose VM handler
implements an operation outside this ~40-value set (e.g. `div`, `rem`,
`cgt`/`clt`/`ceq`, `box`/`isinst`/`castclass`, `ldc.i8`/`ldc.r4`/`ldc.r8`,
`calli`, `throw`, `initobj`, …) can never be recognized by the opcode mapper,
regardless of how good the pattern matching is.

**Design.**
- Expand `VMOpCode` to cover the full CIL opcode space.
- Add `Krypton.Core/Architecture/VMOpCodeCatalog.cs`: a single source of
  truth mapping each `VMOpCode` to its CIL opcode, stack pop/push behavior,
  and operand kind. This replaces the duplicated switch statements currently
  living independently in `OpcodeMapping.Scoring.cs`, `SemanticValidation.cs`,
  `DnlibStyleMaxStackAnalyzer.TryGetStackUsage`, and `CilBodyStackAnalyzer`.
- Add a self-validating test (`Krypton.Tests`) that enumerates every real
  `CilCode` value and asserts a catalog entry exists for it. A future CLR
  opcode, or any regression that drops an entry, fails CI instead of quietly
  shrinking the mapper's search space.

**Files touched.** `VMOpCode.cs`, new `VMOpCodeCatalog.cs`,
`OpcodeMapping.Scoring.cs`, `SemanticValidation.cs`,
`DnlibStyleMaxStackAnalyzer.cs`, `CilBodyStackAnalyzer.cs`, new test file.

**Risk.** Largest-surface-area change of the five — touches every stage that
reasons about opcodes. Mitigated by doing it as a pure data/lookup
consolidation (behavior of existing ~40 mapped opcodes must not change) and
leaning on the self-validating test plus the regression harness (§5).

## 2. Generic hidden-call signature reconstruction

**Problem.** `Krypton.Pipeline/Stages/HiddenCallRecovery.cs` rebuilds direct
calls from NET Reactor's "Hide Method Calls" delegate-thunk stubs. Its
`ParseTypeSig`/`BuildCustomTypeSig`/`BuildMethodSignature` have no concept of
generic types or generic methods — a generic declaring type or parameter
type is fed straight into a flat `namespace.TypeName` split
(`GetNamespace`/`GetTypeName`), producing an unresolvable or wrong
`TypeReference`. The source data is also lossy:
`Krypton.Runner/DynamicMethodSerializer.SerializeMethod` records only a
human-readable signature string (`FullName` calls), with no structured
generic-argument information, even though the runtime `MethodInfo`
(`.GetGenericArguments()`) has the closed, concrete types available.

**Design.**
- Runner side: extend the dump schema (`CalleeDescriptor` equivalent) with
  `IsGenericMethod`, `MethodGenericArgs: string[]`, `IsGenericType`,
  `TypeGenericArgs: string[]`, populated from the live `MethodInfo`/
  `Type.GetGenericArguments()` off the resolved DynamicMethod target — these
  are always closed/concrete at this point, so there's no open-generic
  ambiguity to resolve.
- Pipeline side: `BuildMethodSignature`/`BuildCallInstruction` construct a
  proper `GenericInstanceTypeSignature` for a generic declaring type, and a
  `MethodSpecification` + `GenericInstanceMethodSignature` when
  `IsGenericMethod` is set. Each generic argument is resolved recursively
  through the same `ParseTypeSig` path used for ordinary parameters.
- Failure mode: if a generic shape can't be confidently reconstructed, skip
  patching that call site and log a warning — leave the original stub in
  place rather than emit a broken signature. This matches the "skip on
  doubt" pattern already used elsewhere in the pipeline (e.g. unresolved
  opcode methods are skipped, not guessed).

**Files touched.** `Krypton.Runner/DynamicMethodSerializer.cs`,
`Krypton.Runner/DumpModels.cs`, `Krypton.Pipeline/Stages/HiddenCallRecovery.cs`.

## 3. Correct maxstack on reinjected (NecroBit) bodies

**Problem.** The main VM-recompilation path already cross-validates maxstack
with two independent analyzers — `DnlibStyleMaxStackAnalyzer` and
`CilBodyStackAnalyzer` — wired into `MethodReplacing.cs`,
`SemanticValidation.cs`, and `VerifiableIlSanitizer.cs`. The NecroBit body
reinjection path does not use either: `Devirtualizer.
TryReplaceMethodInstructionsFromRawCil` sets
`body.ComputeMaxStackOnBuild = true` and trusts AsmResolver's built-in
computation, which lacks the exception-handler/filter-region handling the
two custom analyzers already have. This is the source of
`InvalidProgramException` specifically on NecroBit-restored bodies.

**Design.** After disassembling a raw NecroBit body into a
`CilInstructionCollection`, wrap it in a `RecompiledMethodArtifact` and run
both existing analyzers (no new analyzer). If they agree, set `body.MaxStack`
explicitly and set `ComputeMaxStackOnBuild = false`. If they disagree or
report an issue, fall back to `ComputeMaxStackOnBuild = true` but log a
warning so the discrepancy is visible instead of silent.

**Files touched.** `Krypton.Pipeline/Devirtualizer.cs` (around
`TryReplaceMethodInstructionsFromRawCil`, ~line 3337).

## 4. Generalize per-sample hardcoded token fallbacks; widen NecroBit coverage

Three call sites share one root cause: a heuristic that was validated
against one sample got a hand-found metadata token baked in as a fallback,
instead of the heuristic being made robust enough not to need one.

**4a. `FindStringDecoderToken`** (`Devirtualizer.cs`, ~line 2702). Falls back
to a hardcoded `0x0600005C` when the signature scan (`int → string` method)
finds no candidate. Fix: remove the constant; extend the scan to also use
the call-site pattern detection `StringDecryption.cs` already performs
elsewhere in the pipeline. If still nothing is found, skip string decoding
for that sample with a clear log message rather than guessing a token that
belongs to a different binary.

**4b. `FixDnSpyStackIssues`** (`PostDeobfuscation.cs`, ~line 2394). Hunts for
one specific method by hardcoded token `0x0600005B`, falling back to a
hardcoded obfuscated name `"ÂÂ•"` with a 2-parameter signature filter. The
actual fix it applies (`ApplyBasicDnSpyCleanup`: NOP unreachable blocks,
strip `dup`/`pop` and const-push/`pop` stack noise) is entirely
sample-independent — it's a generic structural cleanup, arbitrarily gated
behind finding one specific method. Fix: drop the token/name targeting
entirely; apply `ApplyBasicDnSpyCleanup` to every method with a body inside
the configured `CleanNamespace` scope (`IsInNamespace` check stays as the
scope guard).

**4c. NecroBit form coverage** (`Krypton.Runner/NecrobitDumpRunner.cs` +
`FormSnapshot.cs`). `NecrobitDumpRunner.Run` only drives
`FormSnapshot.CaptureFromEntryPoint`, which arms and captures the single
form `Main` shows. `FormSnapshot.CaptureAll` already exists (used for a
different purpose — reading `InitializeComponent` property values) and
constructs every `Form`-derived type independently. Fix: after the
entry-point pass arms NecroBit's global watchdog hook, also drive
`CaptureAll`-style construction of every `Form` type in the assembly so
instance-ctor stubs on secondary dialogs/forms not reachable from `Main` get
restored in the same pass — no manual enumeration of which forms to visit.

**Files touched.** `Devirtualizer.cs`, `PostDeobfuscation.cs`,
`Krypton.Runner/NecrobitDumpRunner.cs`, `Krypton.Runner/FormSnapshot.cs`.

## 5. Standalone regression harness (output vs. baseline)

**Problem.** `Krypton.Tests/SampleRegressionTests.cs` only asserts that the
pipeline ran and found `> 0` VM methods. It performs no check that the
*output* is correct, loadable, or behaviorally equivalent to the original.
No sample binaries exist locally today (confirmed: none present in-repo or
in the workspace root), so the harness must degrade gracefully when empty
while still being obviously correct once samples are added.

**Design.** New harness, per discovered sample:
1. Run the full `Devirtualizer` pipeline (existing behavior).
2. Load the devirtualized output and structurally validate it: no
   `InvalidProgramException`/`BadImageFormatException` on metadata load, and
   re-run the §1/§3 analyzers in *validator* mode (stack never goes
   negative, branch targets stay in range, computed maxstack matches the
   emitted one) across every recompiled/reinjected method body.
3. For console/library samples (no GUI dependency detected), execute
   original and devirtualized assemblies side by side in separate processes
   with the same fixed input/args, and diff stdout + exit code — genuine
   behavioral comparison against the original baseline.
4. For WinForms samples where full execution isn't practical inside a test
   run, fall back to the structural check plus a written report (method
   count, unresolved-opcode count, unresolved-hidden-call count) for manual
   review.
5. Runnable both via `dotnet test` (existing xunit integration, `Category=
   Regression` trait preserved) and standalone
   (`dotnet run --project Krypton.Tests -- --harness <folder>`), so it fits
   an ad hoc "drop in more real-world samples and see what breaks" workflow.
6. When zero samples are found, keep the existing skip-don't-fail behavior,
   but log an explicit "0 samples found under <paths>, add binaries there to
   enable" message so the harness is visibly wired up even before real
   samples exist.

**Files touched.** New harness file(s) under `Krypton.Tests/`, replacing/
extending `SampleRegressionTests.cs`. Depends on §1 and §3's analyzers
being usable in "validate" mode, not just "compute" mode.

## Cross-cutting notes

- No test samples are available locally; every section above must degrade
  gracefully (skip + clear log) rather than fail when no protected binaries
  are present. Correctness of §1–§4 will initially be judged by unit-level
  tests (catalog completeness, generic-signature construction against
  synthetic AsmResolver module fixtures, maxstack analyzer agreement on
  constructed instruction sequences) rather than end-to-end sample runs,
  until real samples are supplied.
- Sections 1 and 3 share the opcode-catalog/analyzer consolidation — §3
  should land after §1's catalog exists if sequencing allows, since it
  reduces duplicate stack-effect logic instead of adding a third copy.
- Section 4's three sub-fixes are independent of each other and of
  §1–§3, and can be implemented/tested in any order.
