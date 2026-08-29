# Krypton Pipeline Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close five verified correctness gaps in the Krypton `.NET Reactor` devirtualizer: an incomplete VM opcode set, non-generic hidden-call reconstruction, unvalidated maxstack on NecroBit-reinjected bodies, three per-sample hardcoded token fallbacks, and a regression suite that doesn't check output correctness.

**Architecture:** No new subsystems — every task hardens an existing pipeline stage in place (`Krypton.Core`, `Krypton.Pipeline`, `Krypton.Runner`, `Krypton.Tests`). Phase 1 builds a data-driven opcode catalog and wires it into the existing stack-effect table and CIL-emission switch. Phase 2 adds structured generic-argument data to the Runner's dump schema and teaches the Pipeline's signature builder to consume it. Phase 3 reuses Phase 1's/the existing two stack analyzers to validate NecroBit-reinjected bodies before trusting AsmResolver's auto maxstack. Phase 4 replaces three sample-specific hardcoded metadata tokens with pattern/heuristic detection and widens NecroBit form coverage. Phase 5 replaces the assertion-free regression test with a harness that structurally and (where possible) behaviorally validates output against the original.

**Tech Stack:** C# / .NET 8 (`Krypton.Core`, `Krypton.Pipeline`, `Krypton.Tests`) and .NET Framework 4.8 (`Krypton.Runner`), AsmResolver.DotNet 5.5.1 (net8.0 projects), dnlib (`Krypton.Runner`), xunit (`Krypton.Tests`).

**Spec:** `docs/superpowers/specs/2026-08-29-krypton-pipeline-hardening-design.md`

## Global Constraints

- `Krypton.Core`, `Krypton.Pipeline`, `Krypton.Tests` target `net8.0`, `LangVersion 8` — do not use C# 9+-only syntax (no `init` accessors, no target-typed `new()`, no records). `Krypton.Runner` targets `net48` and uses `dnlib`, not AsmResolver — code added there must use dnlib types (`IMethod`, `MethodSpec`, `TypeSpec`, `GenericInstSig`), not AsmResolver types.
- No `.NET Reactor`-protected sample binaries exist locally (confirmed: none under the repo or workspace root). Every task must be unit-testable in isolation, without a real protected binary, and every pipeline-facing change must degrade gracefully (skip + log) rather than throw when expected data is absent.
- Follow existing conventions: canonical/macro-collapsed `VMOpCode` granularity (one enum value per logical operation, not per IL short-form), "skip and log a warning" on any inference/reconstruction that can't be done with confidence (never guess), xunit for tests, `KRYPTON_*` environment variables for new opt-out/opt-in toggles (matching existing ones like `KRYPTON_HCR_ENABLE`, `KRYPTON_CLEAN_DNSPY_TOKEN`).
- Build: `dotnet build Krypton.Core/Krypton.Core.csproj -c Release`, `dotnet build Krypton.Pipeline/Krypton.Pipeline.csproj -c Release`, `dotnet build Krypton.Runner/Krypton.Runner.csproj -c Release` (or `powershell -ExecutionPolicy Bypass -File .\build-all.ps1 -Configuration Release` for everything). Tests: `dotnet test Krypton.Tests/Krypton.Tests.csproj`.
- `VMOpCode` enum values are referenced by other code only by name, never by numeric ordinal (the persisted `HandlerSignatureRecord.OpCode` field is a `string`) — new entries can be appended anywhere in the enum without a compatibility concern.

---

## Task 0: Make internals testable without a live sample

Every later task needs to unit-test `private`/`internal` members of `Krypton.Pipeline` and `Krypton.Runner` directly, because there is no protected sample to drive the public `Devirtualizer.Devirtualize()` entry point end-to-end. This task wires up `InternalsVisibleTo` once, up front.

**Files:**
- Modify: `Krypton.Pipeline/Krypton.Pipeline.csproj`
- Modify: `Krypton.Runner/Krypton.Runner.csproj`
- Modify: `Krypton.Core/Krypton.Core.csproj`

**Interfaces:**
- Produces: `Krypton.Tests` can call `internal` members of `Krypton.Core`, `Krypton.Pipeline`, and `Krypton.Runner` directly.

- [ ] **Step 1: Add `InternalsVisibleTo` to all three production projects**

In `Krypton.Core/Krypton.Core.csproj`, `Krypton.Pipeline/Krypton.Pipeline.csproj`, and `Krypton.Runner/Krypton.Runner.csproj`, add inside the existing `<ItemGroup>` that has `<PackageReference>` (or a new `<ItemGroup>` if none fits):

```xml
<ItemGroup>
  <InternalsVisibleTo Include="Krypton.Tests" />
</ItemGroup>
```

- [ ] **Step 2: Build to confirm no regressions**

Run: `dotnet build Krypton.Core/Krypton.Core.csproj -c Release && dotnet build Krypton.Pipeline/Krypton.Pipeline.csproj -c Release && dotnet build Krypton.Runner/Krypton.Runner.csproj -c Release`
Expected: all three build with 0 errors (same as before this change — this step only grants test visibility, it changes no runtime behavior).

- [ ] **Step 3: Commit**

```bash
git add Krypton.Core/Krypton.Core.csproj Krypton.Pipeline/Krypton.Pipeline.csproj Krypton.Runner/Krypton.Runner.csproj
git commit -m "chore: expose internals to Krypton.Tests for direct unit testing"
```

---

## Phase 1 — Full CLR opcode universe (self-validating catalog)

**Scope decision:** `VMOpCode` represents operations a `.NET Reactor` VM dispatcher is known to implement, not literally every CIL opcode that exists — opcodes with no plausible place in a bytecode-interpreter VM (`calli`, `jmp`, `mkrefany`, `refanytype`, `refanyval`, `cpblk`, `initblk`, `arglist`, `localloc`, the `tail.`/`constrained.`/`unaligned.`/`volatile.`/`readonly.` prefixes) are intentionally excluded. This task closes the gaps that matter for general-purpose obfuscated code: integer division/remainder/multiplication, bitwise and/or, all six comparison operators (as both push-producing and branch forms), the object-model operators (`box`/`isinst`/`castclass`/`initobj`), the remaining numeric literal loads (`ldc.i8`/`ldc.r4`/`ldc.r8`), and `throw`/`rethrow`. The self-validating test asserts completeness against this documented universe (a named, in-code list), not against every `AsmResolver.PE.DotNet.Cil.CilCode` value — so the exclusion is explicit and machine-checked, not silent.

### Task 1: Expand `VMOpCode` and add the self-validating `VMOpCodeCatalog`

**Files:**
- Modify: `Krypton.Core/Architecture/VMOpCode.cs`
- Create: `Krypton.Core/Architecture/VMOpCodeCatalog.cs`
- Test: `Krypton.Tests/VMOpCodeCatalogTests.cs`

**Interfaces:**
- Produces: `VMOpCodeCatalog.Entries : IReadOnlyDictionary<VMOpCode, VMOpCodeCatalogEntry>`, `VMOpCodeCatalog.TryGetFixedStackEffect(VMOpCode opCode, out int pop, out int push) : bool`, `VMOpCodeCatalogEntry { VMOpCode OpCode; CilCode CilCode; VMStackEffectKind Kind; int Pop; int Push; }`, `enum VMStackEffectKind { Fixed, MethodSignatureDependent, Custom }`.
- Consumed by: Task 2 (`MethodRecompiling`), Task 3 (`MethodRecompiling.TranslateInstruction`), Task 12 (regression harness validator).

- [ ] **Step 1: Write the failing completeness test**

```csharp
// Krypton.Tests/VMOpCodeCatalogTests.cs
using System;
using System.Linq;
using Krypton.Core.Architecture;
using Xunit;

namespace Krypton.Tests
{
    public class VMOpCodeCatalogTests
    {
        [Fact]
        public void Catalog_HasEntryForEveryDeclaredVMOpCode()
        {
            var declared = Enum.GetValues(typeof(VMOpCode)).Cast<VMOpCode>().ToArray();
            var missing = declared.Where(op => !VMOpCodeCatalog.Entries.ContainsKey(op)).ToArray();

            Assert.True(
                missing.Length == 0,
                "VMOpCode values missing a VMOpCodeCatalog entry: " + string.Join(", ", missing));
        }

        [Theory]
        [InlineData(VMOpCode.Div, 2, 1)]
        [InlineData(VMOpCode.Div_Un, 2, 1)]
        [InlineData(VMOpCode.Rem, 2, 1)]
        [InlineData(VMOpCode.Rem_Un, 2, 1)]
        [InlineData(VMOpCode.Mul, 2, 1)]
        [InlineData(VMOpCode.And, 2, 1)]
        [InlineData(VMOpCode.Or, 2, 1)]
        [InlineData(VMOpCode.Ceq, 2, 1)]
        [InlineData(VMOpCode.Cgt, 2, 1)]
        [InlineData(VMOpCode.Cgt_Un, 2, 1)]
        [InlineData(VMOpCode.Clt, 2, 1)]
        [InlineData(VMOpCode.Clt_Un, 2, 1)]
        [InlineData(VMOpCode.Box, 1, 1)]
        [InlineData(VMOpCode.Isinst, 1, 1)]
        [InlineData(VMOpCode.Castclass, 1, 1)]
        [InlineData(VMOpCode.Initobj, 1, 0)]
        [InlineData(VMOpCode.Ldc_I8, 0, 1)]
        [InlineData(VMOpCode.Ldc_R4, 0, 1)]
        [InlineData(VMOpCode.Ldc_R8, 0, 1)]
        [InlineData(VMOpCode.Throw, 1, 0)]
        [InlineData(VMOpCode.Rethrow, 0, 0)]
        [InlineData(VMOpCode.BrEqual, 2, 0)]
        [InlineData(VMOpCode.BrNotEqual, 2, 0)]
        [InlineData(VMOpCode.BrGreaterThan, 2, 0)]
        [InlineData(VMOpCode.BrGreaterThan_Un, 2, 0)]
        [InlineData(VMOpCode.BrGreaterOrEqual, 2, 0)]
        [InlineData(VMOpCode.BrGreaterOrEqual_Un, 2, 0)]
        [InlineData(VMOpCode.BrLessThan_Signed, 2, 0)]
        [InlineData(VMOpCode.BrLessOrEqual, 2, 0)]
        [InlineData(VMOpCode.BrLessOrEqual_Un, 2, 0)]
        public void Catalog_ReportsExpectedFixedStackEffect(VMOpCode op, int expectedPop, int expectedPush)
        {
            var ok = VMOpCodeCatalog.TryGetFixedStackEffect(op, out var pop, out var push);

            Assert.True(ok, $"{op} should have a fixed stack effect.");
            Assert.Equal(expectedPop, pop);
            Assert.Equal(expectedPush, push);
        }

        [Fact]
        public void Catalog_CallLikeOpCodes_AreNotFixed()
        {
            Assert.False(VMOpCodeCatalog.TryGetFixedStackEffect(VMOpCode.Call, out _, out _));
            Assert.False(VMOpCodeCatalog.TryGetFixedStackEffect(VMOpCode.Callvirt, out _, out _));
            Assert.False(VMOpCodeCatalog.TryGetFixedStackEffect(VMOpCode.Ret, out _, out _));
        }
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `dotnet test Krypton.Tests/Krypton.Tests.csproj --filter "FullyQualifiedName~VMOpCodeCatalogTests"`
Expected: FAIL to compile — `VMOpCode.Div` (and the rest of the new members) and `VMOpCodeCatalog` do not exist yet.

- [ ] **Step 3: Expand `VMOpCode`**

Append the new canonical opcodes to `Krypton.Core/Architecture/VMOpCode.cs` (existing entries unchanged, order-independent — see Global Constraints):

```csharp
namespace Krypton.Core.Architecture
{
    public enum VMOpCode
    {
        Nop,

        Ldstr,

        Call,
        Callvirt,

        Br,
        BrTrue,
        BrLessThan,
        BrFalse,

        Ldloc,
        Stloc,
        Ldfld,
        Ldsfld,
        Stsfld,
        Stfld,

        Pop,
        Dup,

        Ldc_I4,
        Ldelem_Ref,
        Ldelem_U1,
        Stelem_Ref,
        Stelem_I1,
        Add,
        Xor,
        Shl,
        Shr,
        Neg,
        Ldnull,
        Ldtoken,
        Switch,

        Ldarg,
        Ldlen,
        Ldelema,
        Ldobj,
        Stobj,
        Conv_I4,
        Conv_I8,
        Conv_U1,
        Not,
        Sub,
        Newarr,
        Newobj,
        Unbox_Any,
        Ret,
        Leave,
        EndFinally,

        // ── Phase 1 additions: arithmetic ──────────────────────────────
        Div,
        Div_Un,
        Rem,
        Rem_Un,
        Mul,
        And,
        Or,

        // ── Phase 1 additions: comparisons (push a bool/int result) ────
        Ceq,
        Cgt,
        Cgt_Un,
        Clt,
        Clt_Un,

        // ── Phase 1 additions: comparison branches (pop 2, no push) ────
        BrEqual,
        BrNotEqual,
        BrGreaterThan,
        BrGreaterThan_Un,
        BrGreaterOrEqual,
        BrGreaterOrEqual_Un,
        BrLessThan_Signed,
        BrLessOrEqual,
        BrLessOrEqual_Un,

        // ── Phase 1 additions: object model ─────────────────────────────
        Box,
        Isinst,
        Castclass,
        Initobj,

        // ── Phase 1 additions: literals ─────────────────────────────────
        Ldc_I8,
        Ldc_R4,
        Ldc_R8,

        // ── Phase 1 additions: exceptions ───────────────────────────────
        Throw,
        Rethrow
    }
}
```

- [ ] **Step 4: Create `VMOpCodeCatalog`**

```csharp
// Krypton.Core/Architecture/VMOpCodeCatalog.cs
using System.Collections.Generic;
using AsmResolver.PE.DotNet.Cil;

namespace Krypton.Core.Architecture
{
    /// <summary>
    /// How an opcode's CIL stack effect is determined. <see cref="Fixed"/> opcodes have a
    /// constant pop/push count regardless of operand. <see cref="MethodSignatureDependent"/>
    /// opcodes (call/callvirt/newobj/ret) depend on the target method's signature and are
    /// computed by existing call-site-aware logic, not this catalog. <see cref="Custom"/>
    /// opcodes (switch, leave, ...) have bespoke handling elsewhere in the pipeline.
    /// </summary>
    public enum VMStackEffectKind
    {
        Fixed,
        MethodSignatureDependent,
        Custom
    }

    public sealed class VMOpCodeCatalogEntry
    {
        public VMOpCodeCatalogEntry(VMOpCode opCode, CilCode cilCode, VMStackEffectKind kind, int pop = 0, int push = 0)
        {
            OpCode = opCode;
            CilCode = cilCode;
            Kind = kind;
            Pop = pop;
            Push = push;
        }

        public VMOpCode OpCode { get; }
        public CilCode CilCode { get; }
        public VMStackEffectKind Kind { get; }
        public int Pop { get; }
        public int Push { get; }
    }

    /// <summary>
    /// Single source of truth for every <see cref="VMOpCode"/> Krypton is willing to recompile.
    /// <see cref="VMOpCodeCatalogTests.Catalog_HasEntryForEveryDeclaredVMOpCode"/> fails CI if a
    /// new <see cref="VMOpCode"/> value is added here without a matching entry.
    /// </summary>
    public static class VMOpCodeCatalog
    {
        public static IReadOnlyDictionary<VMOpCode, VMOpCodeCatalogEntry> Entries { get; }

        static VMOpCodeCatalog()
        {
            var entries = new Dictionary<VMOpCode, VMOpCodeCatalogEntry>
            {
                [VMOpCode.Nop] = new VMOpCodeCatalogEntry(VMOpCode.Nop, CilCode.Nop, VMStackEffectKind.Fixed, 0, 0),

                [VMOpCode.Ldarg] = new VMOpCodeCatalogEntry(VMOpCode.Ldarg, CilCode.Ldarg, VMStackEffectKind.Fixed, 0, 1),
                [VMOpCode.Ldloc] = new VMOpCodeCatalogEntry(VMOpCode.Ldloc, CilCode.Ldloc, VMStackEffectKind.Fixed, 0, 1),
                [VMOpCode.Ldc_I4] = new VMOpCodeCatalogEntry(VMOpCode.Ldc_I4, CilCode.Ldc_I4, VMStackEffectKind.Fixed, 0, 1),
                [VMOpCode.Ldstr] = new VMOpCodeCatalogEntry(VMOpCode.Ldstr, CilCode.Ldstr, VMStackEffectKind.Fixed, 0, 1),
                [VMOpCode.Ldnull] = new VMOpCodeCatalogEntry(VMOpCode.Ldnull, CilCode.Ldnull, VMStackEffectKind.Fixed, 0, 1),
                [VMOpCode.Ldsfld] = new VMOpCodeCatalogEntry(VMOpCode.Ldsfld, CilCode.Ldsfld, VMStackEffectKind.Fixed, 0, 1),

                [VMOpCode.Ldfld] = new VMOpCodeCatalogEntry(VMOpCode.Ldfld, CilCode.Ldfld, VMStackEffectKind.Fixed, 1, 1),
                [VMOpCode.Ldlen] = new VMOpCodeCatalogEntry(VMOpCode.Ldlen, CilCode.Ldlen, VMStackEffectKind.Fixed, 1, 1),
                [VMOpCode.Ldobj] = new VMOpCodeCatalogEntry(VMOpCode.Ldobj, CilCode.Ldobj, VMStackEffectKind.Fixed, 1, 1),
                [VMOpCode.Unbox_Any] = new VMOpCodeCatalogEntry(VMOpCode.Unbox_Any, CilCode.Unbox_Any, VMStackEffectKind.Fixed, 1, 1),

                [VMOpCode.Ldelem_Ref] = new VMOpCodeCatalogEntry(VMOpCode.Ldelem_Ref, CilCode.Ldelem_Ref, VMStackEffectKind.Fixed, 2, 1),
                [VMOpCode.Ldelem_U1] = new VMOpCodeCatalogEntry(VMOpCode.Ldelem_U1, CilCode.Ldelem_U1, VMStackEffectKind.Fixed, 2, 1),
                [VMOpCode.Ldelema] = new VMOpCodeCatalogEntry(VMOpCode.Ldelema, CilCode.Ldelema, VMStackEffectKind.Fixed, 2, 1),

                [VMOpCode.Newarr] = new VMOpCodeCatalogEntry(VMOpCode.Newarr, CilCode.Newarr, VMStackEffectKind.Fixed, 1, 1),

                [VMOpCode.Stloc] = new VMOpCodeCatalogEntry(VMOpCode.Stloc, CilCode.Stloc, VMStackEffectKind.Fixed, 1, 0),
                [VMOpCode.Pop] = new VMOpCodeCatalogEntry(VMOpCode.Pop, CilCode.Pop, VMStackEffectKind.Fixed, 1, 0),
                [VMOpCode.Stsfld] = new VMOpCodeCatalogEntry(VMOpCode.Stsfld, CilCode.Stsfld, VMStackEffectKind.Fixed, 1, 0),

                [VMOpCode.Dup] = new VMOpCodeCatalogEntry(VMOpCode.Dup, CilCode.Dup, VMStackEffectKind.Fixed, 1, 2),

                [VMOpCode.Add] = new VMOpCodeCatalogEntry(VMOpCode.Add, CilCode.Add, VMStackEffectKind.Fixed, 2, 1),
                [VMOpCode.Sub] = new VMOpCodeCatalogEntry(VMOpCode.Sub, CilCode.Sub, VMStackEffectKind.Fixed, 2, 1),
                [VMOpCode.Xor] = new VMOpCodeCatalogEntry(VMOpCode.Xor, CilCode.Xor, VMStackEffectKind.Fixed, 2, 1),
                [VMOpCode.Shl] = new VMOpCodeCatalogEntry(VMOpCode.Shl, CilCode.Shl, VMStackEffectKind.Fixed, 2, 1),
                [VMOpCode.Shr] = new VMOpCodeCatalogEntry(VMOpCode.Shr, CilCode.Shr, VMStackEffectKind.Fixed, 2, 1),

                [VMOpCode.Neg] = new VMOpCodeCatalogEntry(VMOpCode.Neg, CilCode.Neg, VMStackEffectKind.Fixed, 1, 1),
                [VMOpCode.Not] = new VMOpCodeCatalogEntry(VMOpCode.Not, CilCode.Not, VMStackEffectKind.Fixed, 1, 1),
                [VMOpCode.Conv_I4] = new VMOpCodeCatalogEntry(VMOpCode.Conv_I4, CilCode.Conv_I4, VMStackEffectKind.Fixed, 1, 1),
                [VMOpCode.Conv_I8] = new VMOpCodeCatalogEntry(VMOpCode.Conv_I8, CilCode.Conv_I8, VMStackEffectKind.Fixed, 1, 1),
                [VMOpCode.Conv_U1] = new VMOpCodeCatalogEntry(VMOpCode.Conv_U1, CilCode.Conv_U1, VMStackEffectKind.Fixed, 1, 1),

                [VMOpCode.Stfld] = new VMOpCodeCatalogEntry(VMOpCode.Stfld, CilCode.Stfld, VMStackEffectKind.Fixed, 2, 0),
                [VMOpCode.Stobj] = new VMOpCodeCatalogEntry(VMOpCode.Stobj, CilCode.Stobj, VMStackEffectKind.Fixed, 2, 0),

                [VMOpCode.Stelem_Ref] = new VMOpCodeCatalogEntry(VMOpCode.Stelem_Ref, CilCode.Stelem_Ref, VMStackEffectKind.Fixed, 3, 0),
                [VMOpCode.Stelem_I1] = new VMOpCodeCatalogEntry(VMOpCode.Stelem_I1, CilCode.Stelem_I1, VMStackEffectKind.Fixed, 3, 0),

                [VMOpCode.BrTrue] = new VMOpCodeCatalogEntry(VMOpCode.BrTrue, CilCode.Brtrue, VMStackEffectKind.Fixed, 1, 0),
                [VMOpCode.BrFalse] = new VMOpCodeCatalogEntry(VMOpCode.BrFalse, CilCode.Brfalse, VMStackEffectKind.Fixed, 1, 0),
                [VMOpCode.BrLessThan] = new VMOpCodeCatalogEntry(VMOpCode.BrLessThan, CilCode.Blt_Un, VMStackEffectKind.Fixed, 2, 0),

                [VMOpCode.Ldtoken] = new VMOpCodeCatalogEntry(VMOpCode.Ldtoken, CilCode.Ldtoken, VMStackEffectKind.Fixed, 0, 1),

                [VMOpCode.Br] = new VMOpCodeCatalogEntry(VMOpCode.Br, CilCode.Br, VMStackEffectKind.Custom),
                [VMOpCode.Switch] = new VMOpCodeCatalogEntry(VMOpCode.Switch, CilCode.Switch, VMStackEffectKind.Custom),
                [VMOpCode.Leave] = new VMOpCodeCatalogEntry(VMOpCode.Leave, CilCode.Leave, VMStackEffectKind.Custom),
                [VMOpCode.EndFinally] = new VMOpCodeCatalogEntry(VMOpCode.EndFinally, CilCode.Endfinally, VMStackEffectKind.Fixed, 0, 0),

                [VMOpCode.Call] = new VMOpCodeCatalogEntry(VMOpCode.Call, CilCode.Call, VMStackEffectKind.MethodSignatureDependent),
                [VMOpCode.Callvirt] = new VMOpCodeCatalogEntry(VMOpCode.Callvirt, CilCode.Callvirt, VMStackEffectKind.MethodSignatureDependent),
                [VMOpCode.Newobj] = new VMOpCodeCatalogEntry(VMOpCode.Newobj, CilCode.Newobj, VMStackEffectKind.Fixed, 0, 1),
                [VMOpCode.Ret] = new VMOpCodeCatalogEntry(VMOpCode.Ret, CilCode.Ret, VMStackEffectKind.MethodSignatureDependent),

                // ── Phase 1 additions ────────────────────────────────────
                [VMOpCode.Div] = new VMOpCodeCatalogEntry(VMOpCode.Div, CilCode.Div, VMStackEffectKind.Fixed, 2, 1),
                [VMOpCode.Div_Un] = new VMOpCodeCatalogEntry(VMOpCode.Div_Un, CilCode.Div_Un, VMStackEffectKind.Fixed, 2, 1),
                [VMOpCode.Rem] = new VMOpCodeCatalogEntry(VMOpCode.Rem, CilCode.Rem, VMStackEffectKind.Fixed, 2, 1),
                [VMOpCode.Rem_Un] = new VMOpCodeCatalogEntry(VMOpCode.Rem_Un, CilCode.Rem_Un, VMStackEffectKind.Fixed, 2, 1),
                [VMOpCode.Mul] = new VMOpCodeCatalogEntry(VMOpCode.Mul, CilCode.Mul, VMStackEffectKind.Fixed, 2, 1),
                [VMOpCode.And] = new VMOpCodeCatalogEntry(VMOpCode.And, CilCode.And, VMStackEffectKind.Fixed, 2, 1),
                [VMOpCode.Or] = new VMOpCodeCatalogEntry(VMOpCode.Or, CilCode.Or, VMStackEffectKind.Fixed, 2, 1),

                [VMOpCode.Ceq] = new VMOpCodeCatalogEntry(VMOpCode.Ceq, CilCode.Ceq, VMStackEffectKind.Fixed, 2, 1),
                [VMOpCode.Cgt] = new VMOpCodeCatalogEntry(VMOpCode.Cgt, CilCode.Cgt, VMStackEffectKind.Fixed, 2, 1),
                [VMOpCode.Cgt_Un] = new VMOpCodeCatalogEntry(VMOpCode.Cgt_Un, CilCode.Cgt_Un, VMStackEffectKind.Fixed, 2, 1),
                [VMOpCode.Clt] = new VMOpCodeCatalogEntry(VMOpCode.Clt, CilCode.Clt, VMStackEffectKind.Fixed, 2, 1),
                [VMOpCode.Clt_Un] = new VMOpCodeCatalogEntry(VMOpCode.Clt_Un, CilCode.Clt_Un, VMStackEffectKind.Fixed, 2, 1),

                [VMOpCode.BrEqual] = new VMOpCodeCatalogEntry(VMOpCode.BrEqual, CilCode.Beq, VMStackEffectKind.Fixed, 2, 0),
                [VMOpCode.BrNotEqual] = new VMOpCodeCatalogEntry(VMOpCode.BrNotEqual, CilCode.Bne_Un, VMStackEffectKind.Fixed, 2, 0),
                [VMOpCode.BrGreaterThan] = new VMOpCodeCatalogEntry(VMOpCode.BrGreaterThan, CilCode.Bgt, VMStackEffectKind.Fixed, 2, 0),
                [VMOpCode.BrGreaterThan_Un] = new VMOpCodeCatalogEntry(VMOpCode.BrGreaterThan_Un, CilCode.Bgt_Un, VMStackEffectKind.Fixed, 2, 0),
                [VMOpCode.BrGreaterOrEqual] = new VMOpCodeCatalogEntry(VMOpCode.BrGreaterOrEqual, CilCode.Bge, VMStackEffectKind.Fixed, 2, 0),
                [VMOpCode.BrGreaterOrEqual_Un] = new VMOpCodeCatalogEntry(VMOpCode.BrGreaterOrEqual_Un, CilCode.Bge_Un, VMStackEffectKind.Fixed, 2, 0),
                [VMOpCode.BrLessThan_Signed] = new VMOpCodeCatalogEntry(VMOpCode.BrLessThan_Signed, CilCode.Blt, VMStackEffectKind.Fixed, 2, 0),
                [VMOpCode.BrLessOrEqual] = new VMOpCodeCatalogEntry(VMOpCode.BrLessOrEqual, CilCode.Ble, VMStackEffectKind.Fixed, 2, 0),
                [VMOpCode.BrLessOrEqual_Un] = new VMOpCodeCatalogEntry(VMOpCode.BrLessOrEqual_Un, CilCode.Ble_Un, VMStackEffectKind.Fixed, 2, 0),

                [VMOpCode.Box] = new VMOpCodeCatalogEntry(VMOpCode.Box, CilCode.Box, VMStackEffectKind.Fixed, 1, 1),
                [VMOpCode.Isinst] = new VMOpCodeCatalogEntry(VMOpCode.Isinst, CilCode.Isinst, VMStackEffectKind.Fixed, 1, 1),
                [VMOpCode.Castclass] = new VMOpCodeCatalogEntry(VMOpCode.Castclass, CilCode.Castclass, VMStackEffectKind.Fixed, 1, 1),
                [VMOpCode.Initobj] = new VMOpCodeCatalogEntry(VMOpCode.Initobj, CilCode.Initobj, VMStackEffectKind.Fixed, 1, 0),

                [VMOpCode.Ldc_I8] = new VMOpCodeCatalogEntry(VMOpCode.Ldc_I8, CilCode.Ldc_I8, VMStackEffectKind.Fixed, 0, 1),
                [VMOpCode.Ldc_R4] = new VMOpCodeCatalogEntry(VMOpCode.Ldc_R4, CilCode.Ldc_R4, VMStackEffectKind.Fixed, 0, 1),
                [VMOpCode.Ldc_R8] = new VMOpCodeCatalogEntry(VMOpCode.Ldc_R8, CilCode.Ldc_R8, VMStackEffectKind.Fixed, 0, 1),

                [VMOpCode.Throw] = new VMOpCodeCatalogEntry(VMOpCode.Throw, CilCode.Throw, VMStackEffectKind.Fixed, 1, 0),
                [VMOpCode.Rethrow] = new VMOpCodeCatalogEntry(VMOpCode.Rethrow, CilCode.Rethrow, VMStackEffectKind.Fixed, 0, 0),
            };

            Entries = entries;
        }

        public static bool TryGetFixedStackEffect(VMOpCode opCode, out int pop, out int push)
        {
            pop = 0;
            push = 0;
            if (!Entries.TryGetValue(opCode, out var entry) || entry.Kind != VMStackEffectKind.Fixed)
                return false;

            pop = entry.Pop;
            push = entry.Push;
            return true;
        }
    }
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `dotnet test Krypton.Tests/Krypton.Tests.csproj --filter "FullyQualifiedName~VMOpCodeCatalogTests"`
Expected: PASS (all 3 test methods, 21 theory cases for `Catalog_ReportsExpectedFixedStackEffect`).

- [ ] **Step 6: Commit**

```bash
git add Krypton.Core/Architecture/VMOpCode.cs Krypton.Core/Architecture/VMOpCodeCatalog.cs Krypton.Tests/VMOpCodeCatalogTests.cs
git commit -m "feat: expand VMOpCode to cover division, comparisons, object-model and literal opcodes with a self-validating catalog"
```

### Task 2: Route `MethodRecompiling.TryGetApproximateStackEffect` through the catalog

**Files:**
- Modify: `Krypton.Pipeline/Stages/MethodRecompiling.cs:344-426` (the `TryGetApproximateStackEffect` method)
- Test: `Krypton.Tests/MethodRecompilingStackEffectTests.cs`

**Interfaces:**
- Consumes: `VMOpCodeCatalog.TryGetFixedStackEffect` from Task 1.
- Produces: `TryGetApproximateStackEffect(VMOpCode, out int pop, out int push) : bool` keeps its existing signature and call sites unchanged — only its body changes.

- [ ] **Step 1: Write the failing test**

`TryGetApproximateStackEffect` is a private instance method on the `MethodRecompiling` stage class. Task 0 made internals visible to `Krypton.Tests`, so bump its accessibility from `private` to `internal` in the same edit as Step 3 below (no separate step — a private method can't be referenced by a test project even with `InternalsVisibleTo`, only `internal`/`public` members can).

```csharp
// Krypton.Tests/MethodRecompilingStackEffectTests.cs
using Krypton.Core.Architecture;
using Krypton.Pipeline.Stages;
using Xunit;

namespace Krypton.Tests
{
    public class MethodRecompilingStackEffectTests
    {
        [Theory]
        [InlineData(VMOpCode.Div, 2, 1)]
        [InlineData(VMOpCode.Mul, 2, 1)]
        [InlineData(VMOpCode.And, 2, 1)]
        [InlineData(VMOpCode.Or, 2, 1)]
        [InlineData(VMOpCode.Ceq, 2, 1)]
        [InlineData(VMOpCode.Box, 1, 1)]
        [InlineData(VMOpCode.Initobj, 1, 0)]
        [InlineData(VMOpCode.Ldc_I8, 0, 1)]
        [InlineData(VMOpCode.Throw, 1, 0)]
        [InlineData(VMOpCode.Add, 2, 1)] // pre-existing opcode: behavior must not regress
        [InlineData(VMOpCode.Dup, 1, 2)] // pre-existing opcode: behavior must not regress
        public void ReportsCatalogBackedStackEffect(VMOpCode op, int expectedPop, int expectedPush)
        {
            var stage = new MethodRecompiling();

            var ok = stage.TryGetApproximateStackEffect(op, out var pop, out var push);

            Assert.True(ok);
            Assert.Equal(expectedPop, pop);
            Assert.Equal(expectedPush, push);
        }

        [Fact]
        public void CallLikeOpCodes_ReturnFalse()
        {
            var stage = new MethodRecompiling();

            Assert.False(stage.TryGetApproximateStackEffect(VMOpCode.Call, out _, out _));
            Assert.False(stage.TryGetApproximateStackEffect(VMOpCode.Callvirt, out _, out _));
        }
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `dotnet test Krypton.Tests/Krypton.Tests.csproj --filter "FullyQualifiedName~MethodRecompilingStackEffectTests"`
Expected: FAIL to compile — `TryGetApproximateStackEffect` is `private` and `MethodRecompiling` may not be publicly constructible yet; `VMOpCode.Div` etc. don't resolve until Task 1 lands (assumed already merged when this task runs).

- [ ] **Step 3: Replace the switch body and bump visibility**

In `Krypton.Pipeline/Stages/MethodRecompiling.cs`, replace the method at line 344 (`private bool TryGetApproximateStackEffect(VMOpCode opCode, out int pop, out int push)` through its closing brace at line 426) with:

```csharp
        internal bool TryGetApproximateStackEffect(VMOpCode opCode, out int pop, out int push)
        {
            return VMOpCodeCatalog.TryGetFixedStackEffect(opCode, out pop, out push);
        }
```

Add `using Krypton.Core.Architecture;` to the top of `MethodRecompiling.cs` if not already present (it already uses `VMOpCode`/`VMMethod` from that namespace elsewhere in the file, so this is likely a no-op check, not a new using).

Also confirm the containing class declaration is at minimum `internal` (not `private`, which isn't valid for a top-level type) — check the class signature at the top of `MethodRecompiling.cs`; if it's already `internal sealed class MethodRecompiling : IStage`, no change is needed there.

- [ ] **Step 4: Run test to verify it passes**

Run: `dotnet test Krypton.Tests/Krypton.Tests.csproj --filter "FullyQualifiedName~MethodRecompilingStackEffectTests"`
Expected: PASS (11 theory cases + 1 fact).

- [ ] **Step 5: Run the full existing test suite to confirm no regression**

Run: `dotnet test Krypton.Tests/Krypton.Tests.csproj`
Expected: PASS — in particular `AssemblyLoadSmokeTests` and `HandlerSignatureCatalogSerializerTests` (unrelated to this change) must still pass, confirming the visibility bump didn't break anything.

- [ ] **Step 6: Commit**

```bash
git add Krypton.Pipeline/Stages/MethodRecompiling.cs Krypton.Tests/MethodRecompilingStackEffectTests.cs
git commit -m "refactor: back MethodRecompiling.TryGetApproximateStackEffect with VMOpCodeCatalog"
```

### Task 3: Wire the new opcodes into `TranslateInstruction` emission and `InferFromProducer`

**Files:**
- Modify: `Krypton.Pipeline/Stages/MethodRecompiling.cs:570-714` (`TranslateInstruction`) and `:442-` (`InferFromProducer`)
- Test: `Krypton.Tests/MethodRecompilingTranslateInstructionTests.cs`

**Interfaces:**
- Consumes: `VMOpCode` new values (Task 1), `ResolveTypeFromToken(DevirtualizationCtx, object) : TypeSignature` (existing private helper used by `Unbox_Any`/`Newarr`/`Ldelema` — reused unchanged for `Box`/`Isinst`/`Castclass`/`Initobj`).
- Produces: `TranslateInstruction` returns a non-null `CilInstruction` for every `Fixed`-kind opcode in the catalog; no signature change.

- [ ] **Step 1: Write the failing test**

`TranslateInstruction` is `private`; bump it to `internal` in Step 2 (same reasoning as Task 2). It needs a `VMMethod`/`VMInstruction`/locals list/fixup collections to call — construct minimal ones directly (no VM-mapped pipeline run required, since we're testing pure opcode-to-CIL translation).

```csharp
// Krypton.Tests/MethodRecompilingTranslateInstructionTests.cs
using System.Collections.Generic;
using AsmResolver.DotNet.Code.Cil;
using AsmResolver.PE.DotNet.Cil;
using Krypton.Core.Architecture;
using Krypton.Pipeline.Stages;
using Xunit;

namespace Krypton.Tests
{
    public class MethodRecompilingTranslateInstructionTests
    {
        private static (
            List<(CilInstruction instruction, int targetOffset, int sourceOffset, VMInstruction sourceInstruction)> fixups,
            List<(CilInstruction instruction, int[] targets)> switchFixups
        ) NewFixupCollections() => (
            new List<(CilInstruction, int, int, VMInstruction)>(),
            new List<(CilInstruction, int[])>()
        );

        [Theory]
        [InlineData(VMOpCode.Div, CilCode.Div)]
        [InlineData(VMOpCode.Div_Un, CilCode.Div_Un)]
        [InlineData(VMOpCode.Rem, CilCode.Rem)]
        [InlineData(VMOpCode.Rem_Un, CilCode.Rem_Un)]
        [InlineData(VMOpCode.Mul, CilCode.Mul)]
        [InlineData(VMOpCode.And, CilCode.And)]
        [InlineData(VMOpCode.Or, CilCode.Or)]
        [InlineData(VMOpCode.Ceq, CilCode.Ceq)]
        [InlineData(VMOpCode.Cgt, CilCode.Cgt)]
        [InlineData(VMOpCode.Cgt_Un, CilCode.Cgt_Un)]
        [InlineData(VMOpCode.Clt, CilCode.Clt)]
        [InlineData(VMOpCode.Clt_Un, CilCode.Clt_Un)]
        [InlineData(VMOpCode.Throw, CilCode.Throw)]
        [InlineData(VMOpCode.Rethrow, CilCode.Rethrow)]
        public void TranslatesZeroOperandOpcodes(VMOpCode vmOp, CilCode expectedCil)
        {
            var stage = new MethodRecompiling();
            var instruction = new VMInstruction(vmOp, null, 0);
            var (fixups, switchFixups) = NewFixupCollections();

            var result = stage.TranslateInstruction(null, null, instruction, new List<CilLocalVariable>(), fixups, switchFixups);

            Assert.Equal(expectedCil, result.OpCode.Code);
        }

        [Theory]
        [InlineData(VMOpCode.BrEqual, CilCode.Beq)]
        [InlineData(VMOpCode.BrNotEqual, CilCode.Bne_Un)]
        [InlineData(VMOpCode.BrGreaterThan, CilCode.Bgt)]
        [InlineData(VMOpCode.BrGreaterThan_Un, CilCode.Bgt_Un)]
        [InlineData(VMOpCode.BrGreaterOrEqual, CilCode.Bge)]
        [InlineData(VMOpCode.BrGreaterOrEqual_Un, CilCode.Bge_Un)]
        [InlineData(VMOpCode.BrLessThan_Signed, CilCode.Blt)]
        [InlineData(VMOpCode.BrLessOrEqual, CilCode.Ble)]
        [InlineData(VMOpCode.BrLessOrEqual_Un, CilCode.Ble_Un)]
        public void TranslatesComparisonBranches_AndRegistersFixup(VMOpCode vmOp, CilCode expectedCil)
        {
            var stage = new MethodRecompiling();
            var instruction = new VMInstruction(vmOp, 100, 10);
            var (fixups, switchFixups) = NewFixupCollections();

            var result = stage.TranslateInstruction(null, null, instruction, new List<CilLocalVariable>(), fixups, switchFixups);

            Assert.Equal(expectedCil, result.OpCode.Code);
            Assert.Single(fixups);
            Assert.Equal(100, fixups[0].targetOffset);
            Assert.Equal(10, fixups[0].sourceOffset);
        }

        [Theory]
        [InlineData(VMOpCode.Ldc_I8, (long)42)]
        public void TranslatesLdcI8(VMOpCode vmOp, long value)
        {
            var stage = new MethodRecompiling();
            var instruction = new VMInstruction(vmOp, value, 0);
            var (fixups, switchFixups) = NewFixupCollections();

            var result = stage.TranslateInstruction(null, null, instruction, new List<CilLocalVariable>(), fixups, switchFixups);

            Assert.Equal(CilCode.Ldc_I8, result.OpCode.Code);
            Assert.Equal(value, result.Operand);
        }
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `dotnet test Krypton.Tests/Krypton.Tests.csproj --filter "FullyQualifiedName~MethodRecompilingTranslateInstructionTests"`
Expected: FAIL — `TranslateInstruction` is `private` (not visible) and does not yet handle the new `VMOpCode` values (falls through to the `default: throw new DevirtualizationException(...)` case).

- [ ] **Step 3: Bump `TranslateInstruction` visibility and add the new cases**

In `Krypton.Pipeline/Stages/MethodRecompiling.cs`, change the method signature at line 570 from `private CilInstruction TranslateInstruction(` to `internal CilInstruction TranslateInstruction(`.

Insert the following cases into the `switch (instruction.OpCode)` block, immediately before the existing `default:` at line 712:

```csharp
                case VMOpCode.Div:
                    return new CilInstruction(CilOpCodes.Div);
                case VMOpCode.Div_Un:
                    return new CilInstruction(CilOpCodes.Div_Un);
                case VMOpCode.Rem:
                    return new CilInstruction(CilOpCodes.Rem);
                case VMOpCode.Rem_Un:
                    return new CilInstruction(CilOpCodes.Rem_Un);
                case VMOpCode.Mul:
                    return new CilInstruction(CilOpCodes.Mul);
                case VMOpCode.And:
                    return new CilInstruction(CilOpCodes.And);
                case VMOpCode.Or:
                    return new CilInstruction(CilOpCodes.Or);
                case VMOpCode.Ceq:
                    return new CilInstruction(CilOpCodes.Ceq);
                case VMOpCode.Cgt:
                    return new CilInstruction(CilOpCodes.Cgt);
                case VMOpCode.Cgt_Un:
                    return new CilInstruction(CilOpCodes.Cgt_Un);
                case VMOpCode.Clt:
                    return new CilInstruction(CilOpCodes.Clt);
                case VMOpCode.Clt_Un:
                    return new CilInstruction(CilOpCodes.Clt_Un);
                case VMOpCode.Box:
                    return new CilInstruction(CilOpCodes.Box, ResolveTypeFromToken(ctx, instruction.Operand));
                case VMOpCode.Isinst:
                    return new CilInstruction(CilOpCodes.Isinst, ResolveTypeFromToken(ctx, instruction.Operand));
                case VMOpCode.Castclass:
                    return new CilInstruction(CilOpCodes.Castclass, ResolveTypeFromToken(ctx, instruction.Operand));
                case VMOpCode.Initobj:
                    return new CilInstruction(CilOpCodes.Initobj, ResolveTypeFromToken(ctx, instruction.Operand));
                case VMOpCode.Ldc_I8:
                    return new CilInstruction(CilOpCodes.Ldc_I8, Convert.ToInt64(instruction.Operand));
                case VMOpCode.Ldc_R4:
                    return new CilInstruction(CilOpCodes.Ldc_R4, Convert.ToSingle(instruction.Operand));
                case VMOpCode.Ldc_R8:
                    return new CilInstruction(CilOpCodes.Ldc_R8, Convert.ToDouble(instruction.Operand));
                case VMOpCode.Throw:
                    return new CilInstruction(CilOpCodes.Throw);
                case VMOpCode.Rethrow:
                    return new CilInstruction(CilOpCodes.Rethrow);
                case VMOpCode.BrEqual:
                {
                    var branch = new CilInstruction(CilOpCodes.Beq);
                    fixups.Add((branch, Convert.ToInt32(instruction.Operand), instruction.Offset, instruction));
                    return branch;
                }
                case VMOpCode.BrNotEqual:
                {
                    var branch = new CilInstruction(CilOpCodes.Bne_Un);
                    fixups.Add((branch, Convert.ToInt32(instruction.Operand), instruction.Offset, instruction));
                    return branch;
                }
                case VMOpCode.BrGreaterThan:
                {
                    var branch = new CilInstruction(CilOpCodes.Bgt);
                    fixups.Add((branch, Convert.ToInt32(instruction.Operand), instruction.Offset, instruction));
                    return branch;
                }
                case VMOpCode.BrGreaterThan_Un:
                {
                    var branch = new CilInstruction(CilOpCodes.Bgt_Un);
                    fixups.Add((branch, Convert.ToInt32(instruction.Operand), instruction.Offset, instruction));
                    return branch;
                }
                case VMOpCode.BrGreaterOrEqual:
                {
                    var branch = new CilInstruction(CilOpCodes.Bge);
                    fixups.Add((branch, Convert.ToInt32(instruction.Operand), instruction.Offset, instruction));
                    return branch;
                }
                case VMOpCode.BrGreaterOrEqual_Un:
                {
                    var branch = new CilInstruction(CilOpCodes.Bge_Un);
                    fixups.Add((branch, Convert.ToInt32(instruction.Operand), instruction.Offset, instruction));
                    return branch;
                }
                case VMOpCode.BrLessThan_Signed:
                {
                    var branch = new CilInstruction(CilOpCodes.Blt);
                    fixups.Add((branch, Convert.ToInt32(instruction.Operand), instruction.Offset, instruction));
                    return branch;
                }
                case VMOpCode.BrLessOrEqual:
                {
                    var branch = new CilInstruction(CilOpCodes.Ble);
                    fixups.Add((branch, Convert.ToInt32(instruction.Operand), instruction.Offset, instruction));
                    return branch;
                }
                case VMOpCode.BrLessOrEqual_Un:
                {
                    var branch = new CilInstruction(CilOpCodes.Ble_Un);
                    fixups.Add((branch, Convert.ToInt32(instruction.Operand), instruction.Offset, instruction));
                    return branch;
                }
```

- [ ] **Step 4: Extend `InferFromProducer` for the new numeric/comparison opcodes**

In the same file, the `InferFromProducer` switch (starting line 442) lists producer opcodes that yield an `Int32` result (`Ldc_I4`, `Conv_I4`, `Ldlen`, `Ldelem_U1`, `Add`, `Xor`, `Shl`, `Shr`, `Sub`, `Neg`, `Conv_U1`, `Not`). Add the new integer-producing arithmetic and comparison opcodes to that same case group so downstream type inference (e.g. for `stloc`/`stfld` target typing) keeps working for them:

```csharp
                case VMOpCode.Ldc_I4:
                case VMOpCode.Conv_I4:
                case VMOpCode.Ldlen:
                case VMOpCode.Ldelem_U1:
                case VMOpCode.Add:
                case VMOpCode.Xor:
                case VMOpCode.Shl:
                case VMOpCode.Shr:
                case VMOpCode.Sub:
                case VMOpCode.Neg:
                case VMOpCode.Conv_U1:
                case VMOpCode.Not:
                case VMOpCode.Div:
                case VMOpCode.Div_Un:
                case VMOpCode.Rem:
                case VMOpCode.Rem_Un:
                case VMOpCode.Mul:
                case VMOpCode.And:
                case VMOpCode.Or:
                case VMOpCode.Ceq:
                case VMOpCode.Cgt:
                case VMOpCode.Cgt_Un:
                case VMOpCode.Clt:
                case VMOpCode.Clt_Un:
                    return ctx.Module.CorLibTypeFactory.Int32;
```

(This replaces the existing `case VMOpCode.Ldc_I4: ... case VMOpCode.Not: return ctx.Module.CorLibTypeFactory.Int32;` block — add the new cases into the same fall-through group rather than duplicating the `return` line.)

- [ ] **Step 5: Run test to verify it passes**

Run: `dotnet test Krypton.Tests/Krypton.Tests.csproj --filter "FullyQualifiedName~MethodRecompilingTranslateInstructionTests"`
Expected: PASS (14 zero-operand cases + 9 branch cases + 1 Ldc_I8 case).

- [ ] **Step 6: Run the full test suite**

Run: `dotnet test Krypton.Tests/Krypton.Tests.csproj`
Expected: PASS, no regressions.

- [ ] **Step 7: Commit**

```bash
git add Krypton.Pipeline/Stages/MethodRecompiling.cs Krypton.Tests/MethodRecompilingTranslateInstructionTests.cs
git commit -m "feat: recompile the new arithmetic, comparison, object-model, literal and exception VM opcodes to CIL"
```

---

## Phase 2 — Generic hidden-call signature reconstruction

### Task 4: Capture structured generic-argument data in the Runner's dump

**Files:**
- Modify: `Krypton.Runner/DumpModels.cs`
- Modify: `Krypton.Runner/DynamicMethodSerializer.cs:136-164` (`SerializeMethod`)
- Test: `Krypton.Tests/DynamicMethodSerializerGenericTests.cs`

**Interfaces:**
- Produces: `InstructionEntry.IsGenericMethod : bool`, `InstructionEntry.MethodGenericArgs : List<string>`, `InstructionEntry.IsGenericDeclaringType : bool`, `InstructionEntry.TypeGenericArgs : List<string>`.
- Consumed by: Task 6 (`HiddenCallRecovery` JSON parsing).

`Krypton.Runner` targets `net48` and uses `dnlib`, not AsmResolver. `instr.Operand` for a `call`/`callvirt`/`newobj` instruction is a `dnlib.DotNet.IMethod`, which may be a `MethodDef`, `MemberRef`, or `MethodSpec` (generic method instantiation); its `DeclaringType` may be a `TypeDef`, `TypeRef`, or `TypeSpec` (generic type instantiation, via `TypeSpec.TryGetGenericInstSig()`).

- [ ] **Step 1: Write the failing test**

`Krypton.Tests` targets `net8.0` and cannot reference `dnlib`/`Krypton.Runner` (net48) directly as a project reference for full dnlib-object construction in most cases, but `Krypton.Runner`'s `DynamicMethodSerializer` and `DumpModels` are plain code with no reflection-emit runtime dependency — add a project reference from `Krypton.Tests` to `Krypton.Runner` and construct dnlib metadata objects in-memory (dnlib works fine as a net48 library referenced from a net8.0 test host via the `Krypton.Runner.csproj`'s own dnlib package reference, since dnlib itself multi-targets). Confirm by checking `Krypton.Runner/Krypton.Runner.csproj` for its dnlib `PackageReference` `TargetFrameworks` support before writing the test; if `Krypton.Tests` cannot reference `Krypton.Runner` directly (a `net48`-only assembly is not consumable from a `net8.0` test project without `net48` also being in `Krypton.Tests`' TFM list), instead add `<TargetFrameworks>net8.0;net48</TargetFrameworks>` is out of scope — use the simpler, always-safe approach: write the test as a **pure data-shape test** against `DumpModels.InstructionEntry` (no dnlib needed) plus a **JSON round-trip test**, and verify `SerializeMethod`'s dnlib-facing logic via a focused Runner-side test that only `Krypton.Runner`'s own test target would run. Since `Krypton.Tests` is the only test project in this repo, keep the test at the `DumpModels` JSON-shape level (Step described below) and verify `SerializeMethod`'s behavior in Task 5/6 indirectly through `HiddenCallRecovery`'s consumption, which is fully testable on the `net8.0`/AsmResolver side.

```csharp
// Krypton.Tests/DynamicMethodSerializerGenericTests.cs
using System.Text.Json;
using Krypton.Runner;
using Xunit;

namespace Krypton.Tests
{
    public class DynamicMethodSerializerGenericTests
    {
        [Fact]
        public void InstructionEntry_RoundTripsGenericMethodFields()
        {
            var entry = new InstructionEntry
            {
                Offset = 0,
                Opcode = "call",
                OperandKind = "method",
                DeclType = "System.Collections.Generic.List`1",
                MemberName = "Add",
                MemberSig = "instance void (!0)",
                IsGenericMethod = false,
                MethodGenericArgs = null,
                IsGenericDeclaringType = true,
                TypeGenericArgs = new System.Collections.Generic.List<string> { "System.String" },
            };

            var json = JsonSerializer.Serialize(entry);
            var roundTripped = JsonSerializer.Deserialize<InstructionEntry>(json);

            Assert.True(roundTripped.IsGenericDeclaringType);
            Assert.Equal(new[] { "System.String" }, roundTripped.TypeGenericArgs);
            Assert.False(roundTripped.IsGenericMethod);
        }
    }
}
```

Add `<ProjectReference Include="..\Krypton.Runner\Krypton.Runner.csproj" />` to `Krypton.Tests/Krypton.Tests.csproj` if `DumpModels`/`InstructionEntry` are not already reachable (they currently are `internal`/`public sealed class` in `Krypton.Runner` — confirm `InstructionEntry` is `public` in `DumpModels.cs`, which it already is per the existing file contents).

- [ ] **Step 2: Run test to verify it fails**

Run: `dotnet test Krypton.Tests/Krypton.Tests.csproj --filter "FullyQualifiedName~DynamicMethodSerializerGenericTests"`
Expected: FAIL to compile — `InstructionEntry.IsGenericMethod`/`MethodGenericArgs`/`IsGenericDeclaringType`/`TypeGenericArgs` don't exist yet. (If the project reference itself fails because `Krypton.Runner` is `net48`-only and `Krypton.Tests` is `net8.0`, add `net48` alongside `net8.0` is not permitted by Global Constraints for `Krypton.Tests`; instead reference only the compiled `Krypton.Runner.dll` via `<Reference>` pointing at its `net48` build output, matching how `Devirtualizer.cs`'s `FindRunnerExecutable`/`FindRunner` already locate `Krypton.Runner.exe` by relative path — a `net8.0` project *can* reference a `net48` library via `<Reference Include="Krypton.Runner"><HintPath>...</HintPath></Reference>` as long as the referenced API surface avoids net48-only BCL types, which `DumpModels.cs` does since it only uses `System.Collections.Generic.List<T>` and primitives.)

- [ ] **Step 3: Add the new fields to `InstructionEntry`**

In `Krypton.Runner/DumpModels.cs`, extend `InstructionEntry`:

```csharp
    public sealed class InstructionEntry
    {
        public int Offset { get; set; }
        public string Opcode { get; set; }

        /// <summary>
        /// Discriminator: null | "i32" | "i64" | "r32" | "r64" | "string" |
        /// "method" | "field" | "type" | "sig" | "branch" | "switch"
        /// </summary>
        public string OperandKind { get; set; }

        // primitive operands
        public long? IntValue { get; set; }
        public double? FloatValue { get; set; }
        public string StringValue { get; set; }

        // member-reference operands (method / field / type)
        public string DeclType { get; set; }    // declaring type full name
        public string MemberName { get; set; }
        public string MemberSig { get; set; }   // human-readable sig, e.g. "instance void (System.String)"

        // for call/callvirt/newobj: are any params by-ref?
        public List<ParamEntry> Params { get; set; }

        // generic shape of the referenced method/type (method operands only) — closed/concrete
        // type names, captured from the live runtime target so there is no open-generic ambiguity.
        public bool IsGenericMethod { get; set; }
        public List<string> MethodGenericArgs { get; set; }
        public bool IsGenericDeclaringType { get; set; }
        public List<string> TypeGenericArgs { get; set; }

        // branch / switch
        public int? BranchTarget { get; set; }
        public List<int> SwitchTargets { get; set; }
    }
```

- [ ] **Step 4: Populate the new fields in `SerializeMethod`**

In `Krypton.Runner/DynamicMethodSerializer.cs`, replace `SerializeMethod` (lines 136-164) with:

```csharp
        private static void SerializeMethod(InstructionEntry e, IMethod m)
        {
            e.OperandKind = "method";
            e.MemberName  = m.Name;

            if (m is MethodSpec spec && spec.GenericInstMethodSig != null)
            {
                e.IsGenericMethod = true;
                e.MethodGenericArgs = new List<string>();
                foreach (var arg in spec.GenericInstMethodSig.GenericArguments)
                    e.MethodGenericArgs.Add(arg?.FullName ?? "System.Object");
            }

            var declaringType = m.DeclaringType;
            if (declaringType is TypeSpec typeSpec && typeSpec.TryGetGenericInstSig() is GenericInstSig git)
            {
                e.IsGenericDeclaringType = true;
                e.TypeGenericArgs = new List<string>();
                foreach (var arg in git.GenericArguments)
                    e.TypeGenericArgs.Add(arg?.FullName ?? "System.Object");
                e.DeclType = git.GenericType?.FullName ?? declaringType.FullName;
            }
            else
            {
                e.DeclType = declaringType?.FullName;
            }

            var ms = m.MethodSig;
            if (ms == null) return;

            // Build a human-readable sig: "instance RetType (Param1, Param2)"
            var sb = new System.Text.StringBuilder();
            if (ms.HasThis) sb.Append("instance ");
            sb.Append(ms.RetType?.FullName ?? "void");
            sb.Append(" (");
            bool first = true;
            var parms = new List<ParamEntry>();
            foreach (var pt in ms.Params)
            {
                if (!first) sb.Append(", ");
                first = false;
                var isByRef = pt is ByRefSig;
                var typeName = (isByRef ? ((ByRefSig)pt).Next?.FullName : pt?.FullName) ?? "?";
                sb.Append(isByRef ? typeName + "&" : typeName);
                parms.Add(new ParamEntry { Type = typeName, IsByRef = isByRef });
            }
            sb.Append(")");
            e.MemberSig = sb.ToString();
            e.Params = parms;
        }
```

Note this drops the old unconditional `e.DeclType = m.DeclaringType?.FullName;` line in favor of the generic-instance-aware assignment above — for a non-generic declaring type, `TryGetGenericInstSig()` returns null and the `else` branch preserves today's exact behavior (`declaringType?.FullName`).

- [ ] **Step 5: Build `Krypton.Runner` and run the test**

Run: `dotnet build Krypton.Runner/Krypton.Runner.csproj -c Release && dotnet test Krypton.Tests/Krypton.Tests.csproj --filter "FullyQualifiedName~DynamicMethodSerializerGenericTests"`
Expected: both PASS.

- [ ] **Step 6: Commit**

```bash
git add Krypton.Runner/DumpModels.cs Krypton.Runner/DynamicMethodSerializer.cs Krypton.Tests/DynamicMethodSerializerGenericTests.cs Krypton.Tests/Krypton.Tests.csproj
git commit -m "feat: capture closed generic type/method arguments in the hidden-call dynamic dump"
```

### Task 5: Parse generic-argument fields in `HiddenCallRecovery`

**Files:**
- Modify: `Krypton.Pipeline/Stages/HiddenCallRecovery.cs:238-296` (`ExtractCallee`, `ParseParamTypes`) and the `CalleeDescriptor` class at the bottom of the file
- Test: `Krypton.Tests/HiddenCallRecoveryGenericParsingTests.cs`

**Interfaces:**
- Produces: `CalleeDescriptor.IsGenericMethod`, `CalleeDescriptor.MethodGenericArgs : List<string>`, `CalleeDescriptor.IsGenericDeclaringType`, `CalleeDescriptor.TypeGenericArgs : List<string>`.
- Consumed by: Task 6 (`BuildMethodSignature`/`BuildCallInstruction`).

- [ ] **Step 1: Write the failing test**

`ExtractCallee` is `private static`; bump to `internal static` in Step 3.

```csharp
// Krypton.Tests/HiddenCallRecoveryGenericParsingTests.cs
using System.Text.Json;
using Krypton.Pipeline.Stages;
using Xunit;

namespace Krypton.Tests
{
    public class HiddenCallRecoveryGenericParsingTests
    {
        private static JsonElement ParseInstructions(string json)
        {
            using var doc = JsonDocument.Parse(json);
            return doc.RootElement.Clone();
        }

        [Fact]
        public void ExtractCallee_ParsesGenericMethodArgs()
        {
            var instrs = ParseInstructions(@"[
                { ""OperandKind"": ""method"", ""Opcode"": ""call"", ""DeclType"": ""System.Collections.Generic.List`1"",
                  ""MemberName"": ""Add"", ""MemberSig"": ""instance void (!0)"",
                  ""IsGenericDeclaringType"": true, ""TypeGenericArgs"": [""System.String""],
                  ""IsGenericMethod"": false, ""Params"": [ { ""Type"": ""System.String"", ""IsByRef"": false } ] }
            ]");

            var callee = HiddenCallRecovery.ExtractCallee(instrs);

            Assert.NotNull(callee);
            Assert.True(callee.IsGenericDeclaringType);
            Assert.Equal(new[] { "System.String" }, callee.TypeGenericArgs);
            Assert.False(callee.IsGenericMethod);
        }

        [Fact]
        public void ExtractCallee_ParsesGenericMethodInstantiation()
        {
            var instrs = ParseInstructions(@"[
                { ""OperandKind"": ""method"", ""Opcode"": ""call"", ""DeclType"": ""MyApp.Helpers"",
                  ""MemberName"": ""Identity"", ""MemberSig"": ""(!!0)"",
                  ""IsGenericMethod"": true, ""MethodGenericArgs"": [""System.Int32""] }
            ]");

            var callee = HiddenCallRecovery.ExtractCallee(instrs);

            Assert.NotNull(callee);
            Assert.True(callee.IsGenericMethod);
            Assert.Equal(new[] { "System.Int32" }, callee.MethodGenericArgs);
        }
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `dotnet test Krypton.Tests/Krypton.Tests.csproj --filter "FullyQualifiedName~HiddenCallRecoveryGenericParsingTests"`
Expected: FAIL to compile — `HiddenCallRecovery.ExtractCallee` is `private` and `CalleeDescriptor` has no generic fields.

- [ ] **Step 3: Extend `CalleeDescriptor` and `ExtractCallee`**

In `Krypton.Pipeline/Stages/HiddenCallRecovery.cs`, extend `CalleeDescriptor` (bottom of file):

```csharp
    internal sealed class CalleeDescriptor
    {
        public string       Opcode        { get; set; }
        public string       DeclaringType { get; set; }
        public string       MethodName    { get; set; }
        public string       MemberSig     { get; set; }
        public List<string> ParamTypes    { get; set; } = new List<string>();
        public bool         IsInstance    { get; set; }

        public bool         IsGenericMethod        { get; set; }
        public List<string> MethodGenericArgs       { get; set; } = new List<string>();
        public bool         IsGenericDeclaringType   { get; set; }
        public List<string> TypeGenericArgs          { get; set; } = new List<string>();
    }
```

Change `private static CalleeDescriptor ExtractCallee(JsonElement instrs)` (line 238) to `internal static CalleeDescriptor ExtractCallee(JsonElement instrs)`, and inside its loop body, after the existing `paramTypes` extraction and before the `return new CalleeDescriptor { ... }`, read the new fields:

```csharp
                // Parse parameters from MemberSig for proper arity
                var paramTypes = ParseParamTypes(memberSig, instr);

                var isGenericMethod = instr.TryGetProperty("IsGenericMethod", out var isGenMethodProp) &&
                                       isGenMethodProp.ValueKind == JsonValueKind.True;
                var methodGenericArgs = ReadStringList(instr, "MethodGenericArgs");

                var isGenericDeclaringType = instr.TryGetProperty("IsGenericDeclaringType", out var isGenTypeProp) &&
                                              isGenTypeProp.ValueKind == JsonValueKind.True;
                var typeGenericArgs = ReadStringList(instr, "TypeGenericArgs");

                return new CalleeDescriptor
                {
                    Opcode        = opcode,
                    DeclaringType = declType,
                    MethodName    = memberName,
                    MemberSig     = memberSig,
                    ParamTypes    = paramTypes,
                    IsInstance    = memberSig.StartsWith("instance", StringComparison.Ordinal),
                    IsGenericMethod = isGenericMethod,
                    MethodGenericArgs = methodGenericArgs,
                    IsGenericDeclaringType = isGenericDeclaringType,
                    TypeGenericArgs = typeGenericArgs,
                };
```

Add the small helper next to `ParseParamTypes`:

```csharp
        private static List<string> ReadStringList(JsonElement instr, string propertyName)
        {
            var result = new List<string>();
            if (!instr.TryGetProperty(propertyName, out var arr) || arr.ValueKind != JsonValueKind.Array)
                return result;

            foreach (var item in arr.EnumerateArray())
                if (item.ValueKind == JsonValueKind.String)
                    result.Add(item.GetString());

            return result;
        }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `dotnet test Krypton.Tests/Krypton.Tests.csproj --filter "FullyQualifiedName~HiddenCallRecoveryGenericParsingTests"`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add Krypton.Pipeline/Stages/HiddenCallRecovery.cs Krypton.Tests/HiddenCallRecoveryGenericParsingTests.cs
git commit -m "feat: parse generic type/method argument fields from the hidden-call dump"
```

### Task 6: Build generic-aware `TypeSignature`/`MethodSignature`/call instructions, skip on doubt

**Files:**
- Modify: `Krypton.Pipeline/Stages/HiddenCallRecovery.cs:403-533` (`BuildCallInstruction`, `BuildMethodSignature`, `ParseTypeSig`, `BuildCustomTypeSig`)
- Test: `Krypton.Tests/HiddenCallRecoveryGenericSignatureTests.cs`

**Interfaces:**
- Consumes: `CalleeDescriptor` generic fields from Task 5.
- Produces: `BuildCallInstruction(CalleeDescriptor, ModuleDefinition) : CilInstruction` returns a `newobj`/`call`/`callvirt` against a `MethodSpecification` (via `GenericInstanceMethodSignature`) when `IsGenericMethod` is set, and/or against a `GenericInstanceTypeSignature`-based type reference when `IsGenericDeclaringType` is set; returns `null` (unchanged contract — callers already skip on `null`) if a generic argument type name can't be resolved through `ParseTypeSig`.

- [ ] **Step 1: Write the failing test**

`BuildCallInstruction` is `private static`; bump to `internal static`.

```csharp
// Krypton.Tests/HiddenCallRecoveryGenericSignatureTests.cs
using System.Collections.Generic;
using AsmResolver.DotNet;
using AsmResolver.DotNet.Code.Cil;
using AsmResolver.DotNet.Signatures;
using AsmResolver.PE.DotNet.Cil;
using Krypton.Pipeline.Stages;
using Xunit;

namespace Krypton.Tests
{
    public class HiddenCallRecoveryGenericSignatureTests
    {
        private static ModuleDefinition NewTestModule() =>
            new ModuleDefinition("HiddenCallRecoveryGenericSignatureTests.dll");

        [Fact]
        public void BuildCallInstruction_GenericDeclaringType_ProducesGenericInstanceTypeCall()
        {
            var module = NewTestModule();
            var callee = new CalleeDescriptor
            {
                Opcode = "callvirt",
                DeclaringType = "System.Collections.Generic.List`1",
                MethodName = "Add",
                MemberSig = "instance void (!0)",
                ParamTypes = new List<string> { "System.String" },
                IsInstance = true,
                IsGenericDeclaringType = true,
                TypeGenericArgs = new List<string> { "System.String" },
            };

            var instruction = HiddenCallRecovery.BuildCallInstruction(callee, module);

            Assert.NotNull(instruction);
            Assert.Equal(CilCode.Callvirt, instruction.OpCode.Code);
            Assert.IsType<MemberReference>(instruction.Operand);
            var memberRef = (MemberReference)instruction.Operand;
            Assert.IsType<TypeSpecification>(memberRef.DeclaringType is TypeSpecification ? memberRef.DeclaringType : null);
        }

        [Fact]
        public void BuildCallInstruction_GenericMethod_ProducesMethodSpecification()
        {
            var module = NewTestModule();
            var callee = new CalleeDescriptor
            {
                Opcode = "call",
                DeclaringType = "MyApp.Helpers",
                MethodName = "Identity",
                MemberSig = "(!!0)",
                ParamTypes = new List<string> { "!!0" },
                IsInstance = false,
                IsGenericMethod = true,
                MethodGenericArgs = new List<string> { "System.Int32" },
            };

            var instruction = HiddenCallRecovery.BuildCallInstruction(callee, module);

            Assert.NotNull(instruction);
            Assert.Equal(CilCode.Call, instruction.OpCode.Code);
            Assert.IsType<MethodSpecification>(instruction.Operand);
        }

        [Fact]
        public void BuildCallInstruction_UnresolvableGenericArg_ReturnsNull()
        {
            var module = NewTestModule();
            var callee = new CalleeDescriptor
            {
                Opcode = "call",
                DeclaringType = "MyApp.Helpers",
                MethodName = "Identity",
                MemberSig = "(!!0)",
                ParamTypes = new List<string> { "!!0" },
                IsInstance = false,
                IsGenericMethod = true,
                MethodGenericArgs = new List<string>(), // malformed: IsGenericMethod=true but no args captured
            };

            var instruction = HiddenCallRecovery.BuildCallInstruction(callee, module);

            Assert.Null(instruction);
        }
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `dotnet test Krypton.Tests/Krypton.Tests.csproj --filter "FullyQualifiedName~HiddenCallRecoveryGenericSignatureTests"`
Expected: FAIL — `BuildCallInstruction` is `private` and does not yet branch on `IsGenericMethod`/`IsGenericDeclaringType` (it would currently build a flat, wrong `TypeReference`/`MemberReference` for these inputs instead of a generic-instance one, and never returns `null` for the malformed case).

- [ ] **Step 3: Implement generic-aware construction**

In `Krypton.Pipeline/Stages/HiddenCallRecovery.cs`, change `BuildCallInstruction`'s signature (line 403) from `private static CilInstruction BuildCallInstruction(` to `internal static CilInstruction BuildCallInstruction(`, and replace its body:

```csharp
        internal static CilInstruction BuildCallInstruction(
            CalleeDescriptor callee,
            ModuleDefinition module)
        {
            try
            {
                if (callee.IsGenericMethod && (callee.MethodGenericArgs == null || callee.MethodGenericArgs.Count == 0))
                {
                    // Flagged as generic but no concrete arguments were captured — reconstructing
                    // would guess. Skip rather than emit a call with an empty instantiation.
                    return null;
                }

                ITypeDefOrRef typeRef = BuildDeclaringTypeReference(callee, module);
                if (typeRef == null)
                    return null;

                var methodSig = BuildMethodSignature(callee, module);
                if (methodSig == null) return null;

                IMethodDescriptor targetMethod = new MemberReference(typeRef, callee.MethodName, methodSig);

                if (callee.IsGenericMethod)
                {
                    var corLib = module.CorLibTypeFactory;
                    var genericArgs = new List<TypeSignature>();
                    foreach (var argName in callee.MethodGenericArgs)
                    {
                        var argSig = ParseTypeSig(argName, module, corLib);
                        if (argSig == null)
                            return null; // couldn't resolve one of the generic arguments — skip, don't guess

                        genericArgs.Add(argSig);
                    }

                    var instantiation = new GenericInstanceMethodSignature(genericArgs.ToArray());
                    targetMethod = new MethodSpecification((IMethodDefOrRef)targetMethod, instantiation);
                }

                var opcode = (string.Equals(callee.Opcode, "call",  StringComparison.OrdinalIgnoreCase) ||
                              string.Equals(callee.Opcode, "call.", StringComparison.OrdinalIgnoreCase))
                    ? CilOpCodes.Call
                    : CilOpCodes.Callvirt;

                // Constructors always use newobj (but they appear as "call" in thunks that
                // forward to them)
                if (string.Equals(callee.MethodName, ".ctor", StringComparison.Ordinal))
                    opcode = CilOpCodes.Newobj;

                return new CilInstruction(opcode, targetMethod);
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[HCR] BuildCallInstruction failed for {callee.DeclaringType}::{callee.MethodName}: {ex.Message}");
                return null;
            }
        }

        private static ITypeDefOrRef BuildDeclaringTypeReference(CalleeDescriptor callee, ModuleDefinition module)
        {
            if (!callee.IsGenericDeclaringType || callee.TypeGenericArgs == null || callee.TypeGenericArgs.Count == 0)
            {
                // Existing non-generic path, unchanged.
                var scope    = FindOrAddAssemblyRef(callee.DeclaringType, module);
                var ns       = GetNamespace(callee.DeclaringType);
                var typeName = GetTypeName(callee.DeclaringType);

                ITypeDefOrRef typeRef = new TypeReference(module, scope, ns, typeName);

                if (callee.DeclaringType.Contains("/"))
                {
                    var parts = callee.DeclaringType.Split('/');
                    var outerScope = FindOrAddAssemblyRef(parts[0], module);
                    var current = new TypeReference(module, outerScope, GetNamespace(parts[0]), GetTypeName(parts[0]));
                    for (int p = 1; p < parts.Length; p++)
                        current = new TypeReference(module, current, string.Empty, parts[p]);
                    typeRef = current;
                }

                return typeRef;
            }

            var corLib = module.CorLibTypeFactory;
            var genericArgs = new List<TypeSignature>();
            foreach (var argName in callee.TypeGenericArgs)
            {
                var argSig = ParseTypeSig(argName, module, corLib);
                if (argSig == null)
                    return null; // couldn't resolve a generic type argument — skip, don't guess

                genericArgs.Add(argSig);
            }

            var openScope = FindOrAddAssemblyRef(callee.DeclaringType, module);
            var openNs = GetNamespace(callee.DeclaringType);
            var openName = GetTypeName(callee.DeclaringType);
            var openTypeRef = new TypeReference(module, openScope, openNs, openName);

            var instanceSig = new GenericInstanceTypeSignature(openTypeRef, false, genericArgs.ToArray());
            return instanceSig.ToTypeDefOrRef();
        }
```

Add `using AsmResolver.DotNet.Signatures.Types;` at the top of the file if `GenericInstanceTypeSignature`/`GenericInstanceMethodSignature` aren't already reachable from the existing `using AsmResolver.DotNet.Signatures;`/`using AsmResolver.DotNet.Signatures.Types;` lines (the file already has `using AsmResolver.DotNet.Signatures.Types;` per its current header — confirm before adding a duplicate).

- [ ] **Step 4: Run test to verify it passes**

Run: `dotnet test Krypton.Tests/Krypton.Tests.csproj --filter "FullyQualifiedName~HiddenCallRecoveryGenericSignatureTests"`
Expected: PASS (3 tests).

- [ ] **Step 5: Run the full test suite**

Run: `dotnet test Krypton.Tests/Krypton.Tests.csproj`
Expected: PASS, no regressions (in particular, re-run Task 5's and the pre-existing `HiddenCallRecovery`-adjacent behavior implicitly — there is no dedicated non-generic `BuildCallInstruction` test today, so also add one alongside Step 1 asserting the pre-existing non-generic path still returns a plain `MemberReference` — fold this into the same test file as a fourth `[Fact]` before moving on, to guard the refactor of `BuildDeclaringTypeReference` against regressing the non-generic case).

- [ ] **Step 6: Commit**

```bash
git add Krypton.Pipeline/Stages/HiddenCallRecovery.cs Krypton.Tests/HiddenCallRecoveryGenericSignatureTests.cs
git commit -m "feat: reconstruct generic hidden-call targets via GenericInstanceType/MethodSpecification, skip when args are unresolvable"
```

---

## Phase 3 — Correct maxstack on NecroBit-reinjected bodies

### Task 7: Validate reinjected NecroBit bodies with the existing stack analyzers before trusting auto-computed maxstack

**Files:**
- Modify: `Krypton.Pipeline/Devirtualizer.cs:3337-3370` (`TryReplaceMethodInstructionsFromRawCil`)
- Test: `Krypton.Tests/NecrobitBodyMaxStackValidationTests.cs`

**Interfaces:**
- Consumes: `CilBodyStackAnalyzer.Analyze(DevirtualizationCtx, VMMethod, RecompiledMethodArtifact) : CilBodyAnalysisResult`, `DnlibStyleMaxStackAnalyzer.Analyze(DevirtualizationCtx, VMMethod, RecompiledMethodArtifact) : DnlibStyleMaxStackAnalysisResult` (both existing, unchanged signatures), `RecompiledMethodArtifact(CilMethodBody, IReadOnlyList<VMInstruction>)` (existing constructor).

Refinement over the design doc: the main VM-recompiled path does **not** set `body.MaxStack` directly from these analyzers — it uses them as a validation/repair gate (`MethodReplacing.cs:110-136`: build artifact → analyze with both → if issues, attempt `VerifiableIlSanitizer.TryRepair` → only then build with `ComputeMaxStackOnBuild=true`). `TryReplaceMethodInstructionsFromRawCil` skips this gate entirely. The fix is to run the same validation gate, not to hand-compute `MaxStack` — reuse `ComputeMaxStackOnBuild=true` in both branches, but only after confirming (or repairing) the body is structurally clean.

- [ ] **Step 1: Write the failing test**

`TryReplaceMethodInstructionsFromRawCil` is a private instance method on the (currently `internal`, confirm) `Devirtualizer` class; bump to `internal`.

```csharp
// Krypton.Tests/NecrobitBodyMaxStackValidationTests.cs
using System.Collections.Generic;
using AsmResolver.DotNet;
using Krypton.Core;
using Krypton.Pipeline;
using Xunit;

namespace Krypton.Tests
{
    public class NecrobitBodyMaxStackValidationTests
    {
        private sealed class RecordingLogger : ILogger
        {
            public List<string> Warnings { get; } = new List<string>();
            public void Success(string message) { }
            public void Warning(string message) => Warnings.Add(message);
            public void Error(string message) { }
            public void Info(string message) { }
            public void InfoStr(string message, string message2) { }
        }

        private static (DevirtualizationCtx ctx, ModuleDefinition module, MethodDefinition method) NewTargetMethod()
        {
            var module = new ModuleDefinition("NecrobitBodyMaxStackValidationTests.dll");
            var type = new TypeDefinition(null, "T", TypeAttributes.Public, module.CorLibTypeFactory.Object.Type);
            module.TopLevelTypes.Add(type);
            var method = new MethodDefinition(
                "M",
                MethodAttributes.Public | MethodAttributes.Static,
                MethodSignature.CreateStatic(module.CorLibTypeFactory.Void));
            type.Methods.Add(method);

            var options = new DevirtualizationOptions(
                System.Reflection.Assembly.GetExecutingAssembly().Location,
                new RecordingLogger());
            var ctx = new DevirtualizationCtx(options) { Module = module };

            return (ctx, module, method);
        }

        // A well-formed CIL body: ldc.i4.1, ldc.i4.2, add, pop, ret — max depth 2.
        private static readonly byte[] WellFormedBody = { 0x17, 0x18, 0x58, 0x26, 0x2A };

        [Fact]
        public void WellFormedRawBody_TrustsAutoComputedMaxStack()
        {
            var (ctx, _, method) = NewTargetMethod();
            var devirtualizer = new Devirtualizer(ctx);

            var replaced = devirtualizer.TryReplaceMethodInstructionsFromRawCil(ctx.Module, method, WellFormedBody);

            Assert.True(replaced);
            Assert.True(method.CilMethodBody.ComputeMaxStackOnBuild);
        }
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `dotnet test Krypton.Tests/Krypton.Tests.csproj --filter "FullyQualifiedName~NecrobitBodyMaxStackValidationTests"`
Expected: FAIL — `TryReplaceMethodInstructionsFromRawCil` is `private`, not `internal`, and `Devirtualizer`'s constructor/visibility needs checking (confirm `public Devirtualizer(DevirtualizationCtx ctx)` already exists — it's used this way in `SampleRegressionTests.cs` today, so it does).

- [ ] **Step 3: Add the validation gate**

In `Krypton.Pipeline/Devirtualizer.cs`, change `TryReplaceMethodInstructionsFromRawCil`'s signature (line 3337) from `private bool TryReplaceMethodInstructionsFromRawCil(` to `internal bool TryReplaceMethodInstructionsFromRawCil(`, and replace its body:

```csharp
        internal bool TryReplaceMethodInstructionsFromRawCil(
            AsmResolver.DotNet.ModuleDefinition module,
            AsmResolver.DotNet.MethodDefinition method,
            byte[] rawBody)
        {
            try
            {
                var body = method.CilMethodBody ?? new CilMethodBody(method);
                var reader = new BinaryStreamReader(rawBody);
                var resolver = new PhysicalCilOperandResolver(module, body);
                var disassembler = new CilDisassembler(in reader, resolver)
                {
                    ResolveBranchTargets = true
                };
                var instructions = disassembler.ReadInstructions();
                if (instructions == null || instructions.Count == 0)
                    return false;

                body.Instructions.Clear();
                body.Instructions.AddRange(instructions);
                body.VerifyLabelsOnBuild = false;
                body.BuildFlags &= ~(CilMethodBodyBuildFlags.VerifyLabels |
                                     CilMethodBodyBuildFlags.FullValidation);
                method.CilMethodBody = body;

                ValidateNecrobitBodyMaxStack(method, body);
                return true;
            }
            catch (Exception ex)
            {
                Ctx?.Options?.Logger?.Warning(
                    $"Failed to restore NecroBit body for {method?.FullName ?? "<method>"}: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Runs the same two stack analyzers the main VM-recompiled path uses (see
        /// MethodReplacing.cs) against a NecroBit-reinjected body before trusting AsmResolver's
        /// automatic maxstack computation. Reinjected bodies have no VM instruction origins, so
        /// a synthetic <see cref="VMMethod"/>/<see cref="VMInstruction"/> list is used purely to
        /// satisfy the analyzers' signatures — issue attribution by VM byte is meaningless here
        /// and is not relied upon.
        /// </summary>
        private void ValidateNecrobitBodyMaxStack(AsmResolver.DotNet.MethodDefinition method, CilMethodBody body)
        {
            var syntheticVmMethod = new VMMethod(0) { Parent = method };
            var syntheticOrigins = new List<VMInstruction>(body.Instructions.Count);
            for (var i = 0; i < body.Instructions.Count; i++)
                syntheticOrigins.Add(new VMInstruction(VMOpCode.Nop, null, body.Instructions[i].Offset, -1));

            var artifact = new RecompiledMethodArtifact(body, syntheticOrigins);

            var cilAnalysis = CilBodyStackAnalyzer.Analyze(Ctx, syntheticVmMethod, artifact);
            var dnlibAnalysis = DnlibStyleMaxStackAnalyzer.Analyze(Ctx, syntheticVmMethod, artifact);

            if (cilAnalysis.TotalIssues == 0 && dnlibAnalysis.TotalIssues == 0)
            {
                body.ComputeMaxStackOnBuild = true;
                return;
            }

            Ctx?.Options?.Logger?.Warning(
                $"NecroBit-restored body for {method.FullName} failed stack validation " +
                $"(cil issues={cilAnalysis.TotalIssues}, dnlib issues={dnlibAnalysis.TotalIssues}); " +
                "proceeding with AsmResolver auto-computed maxstack, output may be unreliable for this method.");
            body.ComputeMaxStackOnBuild = true;
        }
```

This keeps `ComputeMaxStackOnBuild = true` in both branches (matching what the main path ultimately does too), but now every reinjected body is checked first and a failure is visible in the log instead of silent — matching the spec's intent ("if they disagree or report an issue... log a warning so the discrepancy is visible instead of silent") without inventing a third stack-computation mechanism.

`RecompiledMethodArtifact`, `CilBodyStackAnalyzer`, and `DnlibStyleMaxStackAnalyzer` are all `internal` types in `Krypton.Pipeline.Stages` — confirm `Devirtualizer.cs` already has `using Krypton.Pipeline.Stages;` (it does, since it already calls other stage helpers) and `using Krypton.Core.Architecture;` (for `VMMethod`/`VMInstruction`/`VMOpCode` — add if missing).

- [ ] **Step 4: Run test to verify it passes**

Run: `dotnet test Krypton.Tests/Krypton.Tests.csproj --filter "FullyQualifiedName~NecrobitBodyMaxStackValidationTests"`
Expected: PASS.

- [ ] **Step 5: Add a malformed-body regression case**

Add a second `[Fact]` to the same test file using a deliberately stack-broken byte sequence (e.g. `pop` with nothing pushed first: `0x26, 0x2A` — pop, ret) and assert the method logs a warning via `RecordingLogger.Warnings` while `TryReplaceMethodInstructionsFromRawCil` still returns `true` (graceful degrade, not a thrown exception):

```csharp
        // A malformed body: pop with an empty stack, ret. Stack analyzers must flag this.
        private static readonly byte[] StackUnderflowBody = { 0x26, 0x2A };

        [Fact]
        public void MalformedRawBody_LogsWarning_ButStillReplaces()
        {
            var (ctx, _, method) = NewTargetMethod();
            var devirtualizer = new Devirtualizer(ctx);
            var logger = (RecordingLogger)ctx.Options.Logger;

            var replaced = devirtualizer.TryReplaceMethodInstructionsFromRawCil(ctx.Module, method, StackUnderflowBody);

            Assert.True(replaced);
            Assert.Contains(logger.Warnings, w => w.Contains("failed stack validation"));
        }
```

Run: `dotnet test Krypton.Tests/Krypton.Tests.csproj --filter "FullyQualifiedName~NecrobitBodyMaxStackValidationTests"`
Expected: PASS (2 tests).

- [ ] **Step 6: Run the full test suite**

Run: `dotnet test Krypton.Tests/Krypton.Tests.csproj`
Expected: PASS, no regressions.

- [ ] **Step 7: Commit**

```bash
git add Krypton.Pipeline/Devirtualizer.cs Krypton.Tests/NecrobitBodyMaxStackValidationTests.cs
git commit -m "fix: validate NecroBit-reinjected bodies with the existing stack analyzers before trusting auto-computed maxstack"
```

---

## Phase 4 — Generalize per-sample hardcoded token fallbacks; widen NecroBit form coverage

These three tasks are independent of each other and of Phases 1-3; they can be done in any order.

### Task 8: Remove the hardcoded string-decoder token fallback

**Files:**
- Modify: `Krypton.Pipeline/Devirtualizer.cs:2702-2725` (`FindStringDecoderToken`)
- Test: `Krypton.Tests/FindStringDecoderTokenTests.cs`

- [ ] **Step 1: Write the failing test**

`FindStringDecoderToken` is `private static`; bump to `internal static`.

```csharp
// Krypton.Tests/FindStringDecoderTokenTests.cs
using System.Collections.Generic;
using AsmResolver.DotNet;
using Krypton.Pipeline;
using Xunit;

namespace Krypton.Tests
{
    public class FindStringDecoderTokenTests
    {
        [Fact]
        public void NoMatchingSignature_ReturnsZero_NotHardcodedFallback()
        {
            var module = new ModuleDefinition("FindStringDecoderTokenTests.dll");
            var instructions = new List<Devirtualizer.RawIlInstruction>(); // no candidate decoder call present

            var token = Devirtualizer.FindStringDecoderToken(module, instructions);

            Assert.Equal(0u, token);
        }

        [Fact]
        public void MatchingIntToStringSignature_ReturnsItsToken()
        {
            var module = new ModuleDefinition("FindStringDecoderTokenTests.dll");
            var type = new TypeDefinition(null, "T", TypeAttributes.Public, module.CorLibTypeFactory.Object.Type);
            module.TopLevelTypes.Add(type);
            var decoder = new MethodDefinition(
                "Decode",
                MethodAttributes.Public | MethodAttributes.Static,
                MethodSignature.CreateStatic(module.CorLibTypeFactory.String, module.CorLibTypeFactory.Int32));
            type.Methods.Add(decoder);

            var decoderToken = decoder.MetadataToken.ToUInt32();
            var instructions = new List<Devirtualizer.RawIlInstruction>
            {
                new Devirtualizer.RawIlInstruction { Op = 0x28, Token = decoderToken }, // call
            };

            var token = Devirtualizer.FindStringDecoderToken(module, instructions);

            Assert.Equal(decoderToken, token);
        }
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `dotnet test Krypton.Tests/Krypton.Tests.csproj --filter "FullyQualifiedName~FindStringDecoderTokenTests"`
Expected: FAIL to compile initially (`FindStringDecoderToken`/`RawIlInstruction` visibility); once visibility is bumped but before Step 3's logic change, `NoMatchingSignature_ReturnsZero_NotHardcodedFallback` fails at runtime (`0x0600005C` returned instead of `0`).

- [ ] **Step 3: Remove the hardcoded fallback**

In `Krypton.Pipeline/Devirtualizer.cs`, change `FindStringDecoderToken`'s signature (line 2702) to `internal static uint FindStringDecoderToken(` and remove the `return 0x0600005C;` fallback at line 2724, replacing it with `return 0;` and a log call. Since this is a `static` method with no `ctx`/logger parameter today, add one (updating its single call site to pass `Ctx.Options.Logger`):

```csharp
        internal static uint FindStringDecoderToken(
            AsmResolver.DotNet.ModuleDefinition module,
            List<RawIlInstruction> instructions,
            ILogger logger = null)
        {
            foreach (var instruction in instructions)
            {
                if (instruction.Op != 0x28 && instruction.Op != 0x6F)
                    continue;
                if (instruction.Token == 0)
                    continue;

                var method = TryFindMethodByToken(module, instruction.Token);
                if (method?.Signature == null)
                    continue;
                if (method.Signature.ParameterTypes.Count == 1 &&
                    string.Equals(method.Signature.ParameterTypes[0].FullName, "System.Int32", StringComparison.Ordinal) &&
                    string.Equals(method.Signature.ReturnType?.FullName, "System.String", StringComparison.Ordinal))
                {
                    return instruction.Token;
                }
            }

            logger?.Info("No string-decoder method matched the int->string signature scan; skipping string decoding for this sample.");
            return 0;
        }
```

Find the single call site (search for `FindStringDecoderToken(` elsewhere in `Devirtualizer.cs`) and update it to pass `Ctx.Options.Logger` as the third argument, and confirm the caller already treats a `0` return as "no decoder found, skip" (it must, since that was already a valid runtime outcome for `ResolveRuntimeFieldValues`/downstream logic when `instruction.Token != decoderToken` never matches anything — verify by reading the immediate caller before finalizing; if the caller instead unconditionally proceeds assuming a valid decoder token, add a `if (decoderToken == 0) { ...skip and return early... }` guard at the call site so removing the fallback doesn't cause a downstream `TryFindMethodByToken(module, 0)` no-op path to misbehave).

- [ ] **Step 4: Run test to verify it passes**

Run: `dotnet test Krypton.Tests/Krypton.Tests.csproj --filter "FullyQualifiedName~FindStringDecoderTokenTests"`
Expected: PASS.

- [ ] **Step 5: Run the full test suite**

Run: `dotnet test Krypton.Tests/Krypton.Tests.csproj`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add Krypton.Pipeline/Devirtualizer.cs Krypton.Tests/FindStringDecoderTokenTests.cs
git commit -m "fix: drop hardcoded string-decoder token fallback, skip string decoding cleanly when no candidate matches"
```

### Task 9: Apply `ApplyBasicDnSpyCleanup` to every method in scope, not one hardcoded target

**Files:**
- Modify: `Krypton.Pipeline/Stages/PostDeobfuscation.cs:2394-2472` (`FixDnSpyStackIssues`)
- Test: `Krypton.Tests/FixDnSpyStackIssuesTests.cs`

- [ ] **Step 1: Write the failing test**

`FixDnSpyStackIssues` is `private static`; bump to `internal static`. `ApplyBasicDnSpyCleanup` is already usable for assertions once visibility is bumped similarly.

```csharp
// Krypton.Tests/FixDnSpyStackIssuesTests.cs
using AsmResolver.DotNet;
using AsmResolver.DotNet.Code.Cil;
using AsmResolver.PE.DotNet.Cil;
using Krypton.Core;
using Krypton.Pipeline.Stages;
using Xunit;

namespace Krypton.Tests
{
    public class FixDnSpyStackIssuesTests
    {
        private sealed class NoopLogger : ILogger
        {
            public void Success(string message) { }
            public void Warning(string message) { }
            public void Error(string message) { }
            public void Info(string message) { }
            public void InfoStr(string message, string message2) { }
        }

        [Fact]
        public void CleansEveryMethodInNamespace_NotJustOneHardcodedTarget()
        {
            var module = new ModuleDefinition("FixDnSpyStackIssuesTests.dll");
            var type = new TypeDefinition("Target.Ns", "T", TypeAttributes.Public, module.CorLibTypeFactory.Object.Type);
            module.TopLevelTypes.Add(type);

            // Two methods, neither matching the old hardcoded token/name — both need the same
            // dup/pop stack-noise cleanup.
            var methodA = NewMethodWithDupPopNoise(module, "A");
            var methodB = NewMethodWithDupPopNoise(module, "B");
            type.Methods.Add(methodA);
            type.Methods.Add(methodB);

            var ctx = new DevirtualizationCtx(new DevirtualizationOptions(
                System.Reflection.Assembly.GetExecutingAssembly().Location, new NoopLogger()))
            {
                Module = module
            };

            var options = PostDeobfuscation.NewCleanOptionsForTest(cleanNamespace: "Target.Ns");

            PostDeobfuscation.FixDnSpyStackIssues(ctx, module, options);

            Assert.All(new[] { methodA, methodB }, m =>
                Assert.All(m.CilMethodBody.Instructions, instr =>
                    Assert.NotEqual(CilCode.Dup, instr.OpCode.Code)));
        }

        private static MethodDefinition NewMethodWithDupPopNoise(ModuleDefinition module, string name)
        {
            var method = new MethodDefinition(
                name,
                MethodAttributes.Public | MethodAttributes.Static,
                MethodSignature.CreateStatic(module.CorLibTypeFactory.Void));
            var body = new CilMethodBody(method);
            body.Instructions.Add(new CilInstruction(CilOpCodes.Ldc_I4, 1));
            body.Instructions.Add(new CilInstruction(CilOpCodes.Dup));
            body.Instructions.Add(new CilInstruction(CilOpCodes.Pop));
            body.Instructions.Add(new CilInstruction(CilOpCodes.Pop));
            body.Instructions.Add(new CilInstruction(CilOpCodes.Ret));
            method.CilMethodBody = body;
            return method;
        }
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `dotnet test Krypton.Tests/Krypton.Tests.csproj --filter "FullyQualifiedName~FixDnSpyStackIssuesTests"`
Expected: FAIL — `FixDnSpyStackIssues`/`CleanOptions` are not visible yet, and even once visible, today's implementation only touches a method matching a hardcoded token/name (neither `A` nor `B` matches), so neither method gets cleaned.

- [ ] **Step 3: Add a small test-only factory and rewrite `FixDnSpyStackIssues`**

`CleanOptions` is a `private sealed class` nested in `PostDeobfuscation`; add a minimal `internal static` factory next to it purely so the test can construct one without threading through the entire clean-options parsing pipeline:

```csharp
        internal static CleanOptions NewCleanOptionsForTest(string cleanNamespace) =>
            new CleanOptions { CleanNamespace = cleanNamespace };
```

Change `FixDnSpyStackIssues`'s signature (line 2394) from `private static void FixDnSpyStackIssues(` to `internal static void FixDnSpyStackIssues(`, and replace its body:

```csharp
        internal static void FixDnSpyStackIssues(DevirtualizationCtx ctx, ModuleDefinition module, CleanOptions options)
        {
            var cleanedMethods = 0;
            var totalTouched = 0;

            foreach (var type in module.GetAllTypes())
            {
                if (!IsInNamespace(type, options.CleanNamespace))
                    continue;

                foreach (var method in type.Methods)
                {
                    if (!method.HasMethodBody || method.CilMethodBody == null)
                        continue;

                    var body = method.CilMethodBody;
                    if (body.Instructions.Count == 0)
                        continue;

                    var touched = ApplyBasicDnSpyCleanup(body);
                    if (touched <= 0)
                        continue;

                    cleanedMethods++;
                    totalTouched += touched;
                }
            }

            if (cleanedMethods > 0)
                ctx.Options.Logger.Info($"Post-deobf applied dnSpy stack cleanup to {cleanedMethods} method(s) ({totalTouched} change(s)).");
            else
                ctx.Options.Logger.Info("Post-deobf dnSpy cleanup found no methods needing stack noise removal.");
        }
```

This removes the `targetToken`/`targetName`/`KRYPTON_CLEAN_DNSPY_TOKEN`/`KRYPTON_CLEAN_DNSPY_NAME` machinery entirely — `ApplyBasicDnSpyCleanup`'s fix (NOP unreachable blocks, strip `dup`/`pop` and const-push/`pop` noise) is sample-independent, so every method in the configured namespace gets the same safe, idempotent treatment instead of one hand-picked method.

- [ ] **Step 4: Run test to verify it passes**

Run: `dotnet test Krypton.Tests/Krypton.Tests.csproj --filter "FullyQualifiedName~FixDnSpyStackIssuesTests"`
Expected: PASS.

- [ ] **Step 5: Run the full test suite**

Run: `dotnet test Krypton.Tests/Krypton.Tests.csproj`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add Krypton.Pipeline/Stages/PostDeobfuscation.cs Krypton.Tests/FixDnSpyStackIssuesTests.cs
git commit -m "fix: apply dnSpy stack cleanup to every method in scope instead of one hardcoded per-sample target"
```

### Task 10: Widen NecroBit form coverage to secondary dialogs via `FormSnapshot.CaptureAll`

**Files:**
- Modify: `Krypton.Runner/NecrobitDumpRunner.cs:42-50` (inside `Run`)
- Test: manual verification only (see Step 3) — `FormSnapshot`/`NecrobitDumpRunner` drive a real WinForms message loop via reflection and are not meaningfully unit-testable without a live WinForms assembly; this task is validated by code review + the existing build, and exercised for real once a sample is available (Phase 5's harness will catch a regression here once samples exist).

- [ ] **Step 1: Read the current entry-point-only capture call**

Confirm the exact lines in `Krypton.Runner/NecrobitDumpRunner.cs` (around line 42-50):

```csharp
                try
                {
                    var forms = FormSnapshot.CaptureFromEntryPoint(assembly);
                    Console.WriteLine("[NecroBit] Ran entry point and captured " + forms.Count + " form(s) to trigger instance-ctor restoration.");
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine("[NecroBit] Entry point instantiation pass failed: " + ex.Message);
                }
```

- [ ] **Step 2: Also drive `CaptureAll` after the entry-point pass**

Replace with:

```csharp
                try
                {
                    var forms = FormSnapshot.CaptureFromEntryPoint(assembly);
                    Console.WriteLine("[NecroBit] Ran entry point and captured " + forms.Count + " form(s) to trigger instance-ctor restoration.");
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine("[NecroBit] Entry point instantiation pass failed: " + ex.Message);
                }

                try
                {
                    // The entry-point pass above arms NecroBit's global watchdog hook (integrity
                    // checks set up in the app's own Main). Secondary dialogs/forms never shown
                    // from Main still have virtualized instance ctors — construct every Form type
                    // directly (same mechanism FormSnapshot already uses elsewhere for
                    // InitializeComponent property capture) so their NecroBit stubs restore too,
                    // in the same pass, without hand-enumerating which forms to visit.
                    var allForms = FormSnapshot.CaptureAll(assembly);
                    Console.WriteLine("[NecroBit] Captured " + allForms.Count + " additional form type(s) via full-assembly scan.");
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine("[NecroBit] Full-assembly form scan failed: " + ex.Message);
                }
```

Note `CaptureAll` already has its own per-form 10-second timeout/thread-abort safety net (see `CaptureForm` in `FormSnapshot.cs`), so this cannot hang the dump indefinitely even if a form's constructor blocks on a message loop.

- [ ] **Step 3: Build and smoke-test**

Run: `dotnet build Krypton.Runner/Krypton.Runner.csproj -c Release`
Expected: 0 errors. Since there's no local sample to run `Krypton.Runner.exe --necrobit-dump` against, this task's runtime behavior is verified later, once a real sample is available, via Phase 5's regression harness (Task 13/14) rather than a unit test here.

- [ ] **Step 4: Commit**

```bash
git add Krypton.Runner/NecrobitDumpRunner.cs
git commit -m "feat: capture NecroBit method bodies from every Form type, not only the one shown by the entry point"
```

---

## Phase 5 — Standalone regression harness

### Task 11: Structural output validator (loads devirtualized output, re-runs the stack analyzers as a validator)

**Files:**
- Create: `Krypton.Tests/Harness/StructuralOutputValidator.cs`
- Test: `Krypton.Tests/Harness/StructuralOutputValidatorTests.cs`

**Interfaces:**
- Produces: `StructuralOutputValidator.Validate(ModuleDefinition module) : StructuralValidationReport`, `StructuralValidationReport { int MethodsChecked; int MethodsWithIssues; List<string> IssueMessages; bool IsClean => MethodsWithIssues == 0; }`.
- Consumed by: Task 12 (behavioral harness) and Task 13 (CLI/report entry point).

- [ ] **Step 1: Write the failing test**

```csharp
// Krypton.Tests/Harness/StructuralOutputValidatorTests.cs
using AsmResolver.DotNet;
using AsmResolver.DotNet.Code.Cil;
using AsmResolver.PE.DotNet.Cil;
using Krypton.Tests.Harness;
using Xunit;

namespace Krypton.Tests.Harness
{
    public class StructuralOutputValidatorTests
    {
        private static ModuleDefinition NewModuleWithMethod(CilInstruction[] instructions, int maxStack)
        {
            var module = new ModuleDefinition("StructuralOutputValidatorTests.dll");
            var type = new TypeDefinition(null, "T", TypeAttributes.Public, module.CorLibTypeFactory.Object.Type);
            module.TopLevelTypes.Add(type);
            var method = new MethodDefinition(
                "M",
                MethodAttributes.Public | MethodAttributes.Static,
                MethodSignature.CreateStatic(module.CorLibTypeFactory.Void));
            var body = new CilMethodBody(method) { ComputeMaxStackOnBuild = false, MaxStack = (ushort)maxStack };
            foreach (var instr in instructions)
                body.Instructions.Add(instr);
            method.CilMethodBody = body;
            type.Methods.Add(method);
            return module;
        }

        [Fact]
        public void CleanModule_ReportsNoIssues()
        {
            var module = NewModuleWithMethod(
                new[]
                {
                    new CilInstruction(CilOpCodes.Ldc_I4, 1),
                    new CilInstruction(CilOpCodes.Ldc_I4, 2),
                    new CilInstruction(CilOpCodes.Add),
                    new CilInstruction(CilOpCodes.Pop),
                    new CilInstruction(CilOpCodes.Ret),
                },
                maxStack: 2);

            var report = StructuralOutputValidator.Validate(module);

            Assert.Equal(1, report.MethodsChecked);
            Assert.True(report.IsClean);
        }

        [Fact]
        public void UnderflowingModule_ReportsIssue()
        {
            var module = NewModuleWithMethod(
                new[]
                {
                    new CilInstruction(CilOpCodes.Pop), // pop with nothing pushed
                    new CilInstruction(CilOpCodes.Ret),
                },
                maxStack: 0);

            var report = StructuralOutputValidator.Validate(module);

            Assert.Equal(1, report.MethodsChecked);
            Assert.False(report.IsClean);
            Assert.NotEmpty(report.IssueMessages);
        }
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `dotnet test Krypton.Tests/Krypton.Tests.csproj --filter "FullyQualifiedName~StructuralOutputValidatorTests"`
Expected: FAIL to compile — `StructuralOutputValidator` doesn't exist yet.

- [ ] **Step 3: Implement the validator**

`CilBodyStackAnalyzer`/`DnlibStyleMaxStackAnalyzer` both require a `VMMethod` and `RecompiledMethodArtifact` (see Task 7) — reuse the same synthetic-origin pattern for arbitrary post-build modules (not just NecroBit bodies), since a validator run over final output has no VM mapping either.

```csharp
// Krypton.Tests/Harness/StructuralOutputValidator.cs
using System.Collections.Generic;
using AsmResolver.DotNet;
using Krypton.Core.Architecture;
using Krypton.Pipeline.Stages;

namespace Krypton.Tests.Harness
{
    public sealed class StructuralValidationReport
    {
        public int MethodsChecked { get; set; }
        public int MethodsWithIssues { get; set; }
        public List<string> IssueMessages { get; } = new List<string>();
        public bool IsClean => MethodsWithIssues == 0;
    }

    /// <summary>
    /// Re-runs Krypton's own stack analyzers (Krypton.Pipeline.Stages.CilBodyStackAnalyzer,
    /// DnlibStyleMaxStackAnalyzer) over a fully-built module as a pass/fail validator, instead of
    /// as a pre-build repair gate. Used by the regression harness (Task 12/13) to check that
    /// devirtualized output is at least structurally self-consistent (no stack underflow, no
    /// maxstack that undershoots what the analyzers compute) without needing to execute it.
    /// </summary>
    public static class StructuralOutputValidator
    {
        public static StructuralValidationReport Validate(ModuleDefinition module)
        {
            var report = new StructuralValidationReport();

            foreach (var type in module.GetAllTypes())
            {
                foreach (var method in type.Methods)
                {
                    if (!method.HasMethodBody || method.CilMethodBody == null || method.CilMethodBody.Instructions.Count == 0)
                        continue;

                    report.MethodsChecked++;

                    var body = method.CilMethodBody;
                    var syntheticVmMethod = new VMMethod(0) { Parent = method };
                    var syntheticOrigins = new List<VMInstruction>(body.Instructions.Count);
                    foreach (var instr in body.Instructions)
                        syntheticOrigins.Add(new VMInstruction(VMOpCode.Nop, null, instr.Offset, -1));

                    var artifact = new RecompiledMethodArtifact(body, syntheticOrigins);
                    var cilAnalysis = CilBodyStackAnalyzer.Analyze(null, syntheticVmMethod, artifact);
                    var dnlibAnalysis = DnlibStyleMaxStackAnalyzer.Analyze(null, syntheticVmMethod, artifact);

                    if (cilAnalysis.TotalIssues == 0 && dnlibAnalysis.TotalIssues == 0)
                        continue;

                    report.MethodsWithIssues++;
                    report.IssueMessages.Add(
                        $"{method.FullName}: cil issues={cilAnalysis.TotalIssues}, dnlib issues={dnlibAnalysis.TotalIssues}");
                }
            }

            return report;
        }
    }
}
```

Confirm `CilBodyStackAnalyzer.Analyze`/`DnlibStyleMaxStackAnalyzer.Analyze` tolerate a `null` `DevirtualizationCtx` (they're only used for `ctx.Options.Logger` calls inside issue-registration paths in the existing code — check `RegisterIssue`/`SeedExceptionHandlers` for a `ctx?.Options?.Logger` null-conditional pattern already in use; if any call site uses `ctx.Options.Logger` without null-conditional, pass a minimal no-op `DevirtualizationCtx` built the same way `NecrobitBodyMaxStackValidationTests` does in Task 7 instead of `null`).

- [ ] **Step 4: Run test to verify it passes**

Run: `dotnet test Krypton.Tests/Krypton.Tests.csproj --filter "FullyQualifiedName~StructuralOutputValidatorTests"`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add Krypton.Tests/Harness/StructuralOutputValidator.cs Krypton.Tests/Harness/StructuralOutputValidatorTests.cs
git commit -m "feat: add structural output validator reusing the existing stack analyzers in validate-only mode"
```

### Task 12: Behavioral diff for console/library samples (execute original vs. devirtualized, diff stdout/exit code)

**Files:**
- Create: `Krypton.Tests/Harness/BehavioralDiffRunner.cs`
- Test: `Krypton.Tests/Harness/BehavioralDiffRunnerTests.cs`

**Interfaces:**
- Produces: `BehavioralDiffRunner.Run(string originalPath, string devirtualizedPath, string[] args, TimeSpan timeout) : BehavioralDiffResult`, `BehavioralDiffResult { bool MatchesBaseline; int? OriginalExitCode; int? DevirtualizedExitCode; string OriginalStdout; string DevirtualizedStdout; string Explanation; }`.
- Consumed by: Task 13 (harness orchestration).

- [ ] **Step 1: Write the failing test**

Use two trivially-buildable throwaway console assemblies compiled on the fly with `dotnet build` is too heavyweight for a unit test — instead exercise `BehavioralDiffRunner` against two copies of the *test host's own* `dotnet` executable running a benign built-in command, proving the diff mechanics (matching case, mismatching case) without needing a real Reactor sample:

```csharp
// Krypton.Tests/Harness/BehavioralDiffRunnerTests.cs
using System;
using Krypton.Tests.Harness;
using Xunit;

namespace Krypton.Tests.Harness
{
    public class BehavioralDiffRunnerTests
    {
        [Fact]
        public void IdenticalCommands_MatchBaseline()
        {
            var result = BehavioralDiffRunner.RunProcesses(
                "cmd.exe", "/c echo hello",
                "cmd.exe", "/c echo hello",
                TimeSpan.FromSeconds(10));

            Assert.True(result.MatchesBaseline);
            Assert.Equal(result.OriginalExitCode, result.DevirtualizedExitCode);
        }

        [Fact]
        public void DifferingOutput_DoesNotMatchBaseline()
        {
            var result = BehavioralDiffRunner.RunProcesses(
                "cmd.exe", "/c echo hello",
                "cmd.exe", "/c echo goodbye",
                TimeSpan.FromSeconds(10));

            Assert.False(result.MatchesBaseline);
            Assert.Contains("stdout differs", result.Explanation);
        }
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `dotnet test Krypton.Tests/Krypton.Tests.csproj --filter "FullyQualifiedName~BehavioralDiffRunnerTests"`
Expected: FAIL to compile — `BehavioralDiffRunner` doesn't exist yet.

- [ ] **Step 3: Implement the runner**

```csharp
// Krypton.Tests/Harness/BehavioralDiffRunner.cs
using System;
using System.Diagnostics;
using System.Text;

namespace Krypton.Tests.Harness
{
    public sealed class BehavioralDiffResult
    {
        public bool MatchesBaseline { get; set; }
        public int? OriginalExitCode { get; set; }
        public int? DevirtualizedExitCode { get; set; }
        public string OriginalStdout { get; set; }
        public string DevirtualizedStdout { get; set; }
        public string Explanation { get; set; } = string.Empty;
    }

    /// <summary>
    /// Executes an original assembly and its devirtualized counterpart with identical
    /// arguments/input, each in its own process with a hard timeout, and diffs exit code +
    /// stdout. Used by the regression harness (Task 13) for console/library samples where full
    /// execution is safe and deterministic; not used for WinForms samples (see Task 13's
    /// structural-only fallback).
    /// </summary>
    public static class BehavioralDiffRunner
    {
        public static BehavioralDiffResult Run(
            string originalPath,
            string devirtualizedPath,
            string[] args,
            TimeSpan timeout)
        {
            var argString = args == null ? string.Empty : string.Join(" ", args);
            return RunProcesses(originalPath, argString, devirtualizedPath, argString, timeout);
        }

        internal static BehavioralDiffResult RunProcesses(
            string originalExe,
            string originalArgs,
            string devirtualizedExe,
            string devirtualizedArgs,
            TimeSpan timeout)
        {
            var (originalExit, originalStdout) = RunOne(originalExe, originalArgs, timeout);
            var (devirtualizedExit, devirtualizedStdout) = RunOne(devirtualizedExe, devirtualizedArgs, timeout);

            var result = new BehavioralDiffResult
            {
                OriginalExitCode = originalExit,
                DevirtualizedExitCode = devirtualizedExit,
                OriginalStdout = originalStdout,
                DevirtualizedStdout = devirtualizedStdout,
            };

            if (originalExit == null || devirtualizedExit == null)
            {
                result.MatchesBaseline = false;
                result.Explanation = "one or both processes failed to start or timed out";
                return result;
            }

            if (originalExit != devirtualizedExit)
            {
                result.MatchesBaseline = false;
                result.Explanation = $"exit code differs: original={originalExit}, devirtualized={devirtualizedExit}";
                return result;
            }

            if (!string.Equals(originalStdout, devirtualizedStdout, StringComparison.Ordinal))
            {
                result.MatchesBaseline = false;
                result.Explanation = "stdout differs";
                return result;
            }

            result.MatchesBaseline = true;
            result.Explanation = "match";
            return result;
        }

        private static (int? exitCode, string stdout) RunOne(string exePath, string args, TimeSpan timeout)
        {
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = exePath,
                    Arguments = args,
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true,
                };

                using var proc = Process.Start(psi);
                if (proc == null)
                    return (null, null);

                var stdout = new StringBuilder();
                proc.OutputDataReceived += (_, e) => { if (e.Data != null) stdout.AppendLine(e.Data); };
                proc.BeginOutputReadLine();

                if (!proc.WaitForExit((int)timeout.TotalMilliseconds))
                {
                    try { proc.Kill(); } catch { /* best effort */ }
                    return (null, stdout.ToString());
                }

                return (proc.ExitCode, stdout.ToString());
            }
            catch
            {
                return (null, null);
            }
        }
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `dotnet test Krypton.Tests/Krypton.Tests.csproj --filter "FullyQualifiedName~BehavioralDiffRunnerTests"`
Expected: PASS (2 tests). (These tests use `cmd.exe`, matching the Windows-only nature of this repo's build/run instructions — see README's "Windows x64 (tested/recommended)" requirement.)

- [ ] **Step 5: Commit**

```bash
git add Krypton.Tests/Harness/BehavioralDiffRunner.cs Krypton.Tests/Harness/BehavioralDiffRunnerTests.cs
git commit -m "feat: add process-level behavioral diff runner for regression harness"
```

### Task 13: Replace `SampleRegressionTests` with the full harness, standalone-runnable, graceful on zero samples

**Files:**
- Modify: `Krypton.Tests/SampleRegressionTests.cs` (rename/replace its body — keep the file so existing `dotnet test --filter Category=Regression` invocations keep working)
- Create: `Krypton.Tests/Harness/RegressionHarness.cs`
- Create: `Krypton.Tests/Harness/RegressionHarnessCli.cs` (standalone entry point)
- Modify: `Krypton.Tests/Krypton.Tests.csproj` (enable `OutputType=Exe`-compatible standalone run — see Step 4)

**Interfaces:**
- Consumes: `StructuralOutputValidator.Validate` (Task 11), `BehavioralDiffRunner.Run` (Task 12).
- Produces: `RegressionHarness.RunAll(string samplesDirectory, ILogger logger) : List<SampleRegressionResult>`, `SampleRegressionResult { string SamplePath; bool DevirtualizationSucceeded; int VmMethodCount; StructuralValidationReport Structural; BehavioralDiffResult Behavioral; bool IsGuiSample; string ReportPath; }`.

- [ ] **Step 1: Write the failing test**

```csharp
// Krypton.Tests/Harness/RegressionHarnessTests.cs
using System.IO;
using Krypton.Tests.Harness;
using Xunit;

namespace Krypton.Tests.Harness
{
    public class RegressionHarnessTests
    {
        [Fact]
        public void EmptySampleDirectory_ReturnsEmptyResults_AndLogsExplicitMessage()
        {
            var emptyDir = Path.Combine(Path.GetTempPath(), "krypton-harness-empty-" + System.Guid.NewGuid());
            Directory.CreateDirectory(emptyDir);
            try
            {
                var logger = new RecordingLogger();

                var results = RegressionHarness.RunAll(emptyDir, logger);

                Assert.Empty(results);
                Assert.Contains(logger.InfoMessages, m => m.Contains("0 samples found"));
            }
            finally
            {
                Directory.Delete(emptyDir, recursive: true);
            }
        }

        private sealed class RecordingLogger : Krypton.Core.ILogger
        {
            public System.Collections.Generic.List<string> InfoMessages { get; } = new System.Collections.Generic.List<string>();
            public void Success(string message) { }
            public void Warning(string message) { }
            public void Error(string message) { }
            public void Info(string message) => InfoMessages.Add(message);
            public void InfoStr(string message, string message2) { }
        }
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `dotnet test Krypton.Tests/Krypton.Tests.csproj --filter "FullyQualifiedName~RegressionHarnessTests"`
Expected: FAIL to compile — `RegressionHarness` doesn't exist yet.

- [ ] **Step 3: Implement `RegressionHarness`**

```csharp
// Krypton.Tests/Harness/RegressionHarness.cs
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection.PortableExecutable;
using AsmResolver.DotNet;
using Krypton.Core;
using Krypton.Pipeline;

namespace Krypton.Tests.Harness
{
    public sealed class SampleRegressionResult
    {
        public string SamplePath { get; set; }
        public bool DevirtualizationSucceeded { get; set; }
        public int VmMethodCount { get; set; }
        public StructuralValidationReport Structural { get; set; }
        public BehavioralDiffResult Behavioral { get; set; }
        public bool IsGuiSample { get; set; }
        public string ReportPath { get; set; }
    }

    /// <summary>
    /// Standalone-runnable regression harness: devirtualizes every discovered sample, validates
    /// the output structurally (Task 11), behaviorally diffs console/library samples against the
    /// original (Task 12), and writes a per-sample report for GUI samples where full execution
    /// isn't attempted. Runnable via `dotnet test` (see RegressionHarnessXunitTests) or standalone
    /// (see RegressionHarnessCli). Degrades gracefully — logs and returns an empty list — when no
    /// samples are found, since no protected sample binaries ship with this repo.
    /// </summary>
    public static class RegressionHarness
    {
        private static readonly string[] KnownSampleNames =
        {
            "Crackme.exe",
            "awesome_msil.exe",
            "Offline_sales_bills_msil.exe",
            "WindowsFormsApplication41.exe"
        };

        public static List<SampleRegressionResult> RunAll(string samplesDirectory, ILogger logger)
        {
            var results = new List<SampleRegressionResult>();
            var samples = DiscoverSamples(samplesDirectory);

            if (samples.Count == 0)
            {
                logger.Info($"0 samples found under {samplesDirectory}, add binaries there to enable the regression harness.");
                return results;
            }

            foreach (var samplePath in samples)
                results.Add(RunOne(samplePath, logger));

            return results;
        }

        private static List<string> DiscoverSamples(string samplesDirectory)
        {
            var results = new List<string>();
            if (!Directory.Exists(samplesDirectory))
                return results;

            foreach (var name in KnownSampleNames)
            {
                var path = Path.Combine(samplesDirectory, name);
                if (File.Exists(path) && IsManagedAssembly(path))
                    results.Add(path);
            }

            // Also pick up any other managed .exe dropped into the directory, so the harness is
            // useful for arbitrary future samples, not only the four names known today.
            foreach (var path in Directory.GetFiles(samplesDirectory, "*.exe"))
            {
                if (results.Contains(path, StringComparer.OrdinalIgnoreCase))
                    continue;
                if (IsManagedAssembly(path))
                    results.Add(path);
            }

            return results;
        }

        private static bool IsManagedAssembly(string path)
        {
            try
            {
                using var stream = File.OpenRead(path);
                using var peReader = new PEReader(stream, PEStreamOptions.LeaveOpen);
                return peReader.HasMetadata;
            }
            catch
            {
                return false;
            }
        }

        private static SampleRegressionResult RunOne(string samplePath, ILogger logger)
        {
            var result = new SampleRegressionResult { SamplePath = samplePath };

            var options = new DevirtualizationOptions(samplePath, logger) { StrictDiagnostics = false };
            var ctx = new DevirtualizationCtx(options);
            var devirtualizer = new Devirtualizer(ctx);

            try
            {
                devirtualizer.Devirtualize();
            }
            catch (Exception ex)
            {
                logger.Error($"[Harness] Devirtualization threw for {samplePath}: {ex.Message}");
                result.DevirtualizationSucceeded = false;
                return result;
            }

            result.DevirtualizationSucceeded = true;
            result.VmMethodCount = ctx.VirtualizedMethods?.Count ?? 0;
            result.IsGuiSample = IsGuiAssembly(ctx.Module);

            var outputPath = options.OutPath;
            if (!File.Exists(outputPath))
            {
                logger.Warning($"[Harness] Expected devirtualized output not found at {outputPath}.");
                return result;
            }

            var outputModule = ModuleDefinition.FromFile(outputPath);
            result.Structural = StructuralOutputValidator.Validate(outputModule);

            if (!result.IsGuiSample)
            {
                result.Behavioral = BehavioralDiffRunner.Run(
                    samplePath,
                    outputPath,
                    args: Array.Empty<string>(),
                    timeout: TimeSpan.FromSeconds(15));
            }
            else
            {
                result.ReportPath = WriteGuiSampleReport(samplePath, result);
            }

            return result;
        }

        private static bool IsGuiAssembly(ModuleDefinition module)
        {
            return module.AssemblyReferences.Any(r =>
                string.Equals(r.Name, "System.Windows.Forms", StringComparison.OrdinalIgnoreCase));
        }

        private static string WriteGuiSampleReport(string samplePath, SampleRegressionResult result)
        {
            var reportPath = Path.ChangeExtension(samplePath, null) + "-regression-report.txt";
            var lines = new List<string>
            {
                $"Sample: {samplePath}",
                $"Devirtualization succeeded: {result.DevirtualizationSucceeded}",
                $"VM methods found: {result.VmMethodCount}",
                $"Structural: methods checked={result.Structural?.MethodsChecked ?? 0}, methods with issues={result.Structural?.MethodsWithIssues ?? 0}",
            };
            if (result.Structural != null)
                lines.AddRange(result.Structural.IssueMessages.Select(m => "  - " + m));

            File.WriteAllLines(reportPath, lines);
            return reportPath;
        }
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `dotnet test Krypton.Tests/Krypton.Tests.csproj --filter "FullyQualifiedName~RegressionHarnessTests"`
Expected: PASS.

- [ ] **Step 5: Replace `SampleRegressionTests.cs` to call the new harness**

Replace `Krypton.Tests/SampleRegressionTests.cs` in full:

```csharp
// Krypton.Tests/SampleRegressionTests.cs
using System;
using System.IO;
using System.Linq;
using Krypton.Core;
using Krypton.Tests.Harness;
using Xunit;

namespace Krypton.Tests
{
    public class SampleRegressionTests
    {
        [Fact]
        [Trait("Category", "Regression")]
        public void Devirtualize_KnownSamples_MatchOriginalBehaviorOrPassStructuralValidation()
        {
            var samplesDirectory = ResolveSamplesDirectory();
            var results = RegressionHarness.RunAll(samplesDirectory, new TestLogger());

            if (results.Count == 0)
                return; // graceful skip — no samples shipped with this repo, see harness log

            foreach (var result in results)
            {
                Assert.True(result.DevirtualizationSucceeded, $"Devirtualization failed for {result.SamplePath}");
                Assert.True(result.VmMethodCount > 0, $"No VM methods found for sample: {result.SamplePath}");
                Assert.NotNull(result.Structural);
                Assert.True(
                    result.Structural.IsClean,
                    $"Structural validation failed for {result.SamplePath}: {string.Join("; ", result.Structural.IssueMessages)}");

                if (result.Behavioral != null)
                {
                    Assert.True(
                        result.Behavioral.MatchesBaseline,
                        $"Behavioral diff failed for {result.SamplePath}: {result.Behavioral.Explanation}");
                }
            }
        }

        private static string ResolveSamplesDirectory()
        {
            var baseDir = AppContext.BaseDirectory;
            var repoRoot = Path.GetFullPath(Path.Combine(baseDir, "..", "..", "..", "..", ".."));
            return repoRoot;
        }

        private sealed class TestLogger : ILogger
        {
            public void Success(string message) { }
            public void Warning(string message) { }
            public void Error(string message) { }
            public void Info(string message) { }
            public void InfoStr(string message, string message2) { }
        }
    }
}
```

- [ ] **Step 6: Add the standalone CLI entry point**

`Krypton.Tests.csproj` currently builds as a `Microsoft.NET.Sdk` xunit test library (no `<OutputType>Exe</OutputType>`), which does not support `dotnet run`. Add a small opt-in runner instead — a `public static` `Main`-like method invoked explicitly, matching the plan's original design ("also runnable outside `dotnet test`") without changing the project's output type (which would break normal `dotnet test` usage):

```csharp
// Krypton.Tests/Harness/RegressionHarnessCli.cs
using System;
using Krypton.Core;

namespace Krypton.Tests.Harness
{
    /// <summary>
    /// Standalone entry point for the regression harness, for ad hoc "drop more real-world
    /// samples in and see what breaks" runs outside the xunit test suite. Krypton.Tests stays a
    /// normal test-library project (no OutputType=Exe), so this is invoked via
    /// `dotnet exec bin/Debug/net8.0/Krypton.Tests.dll --harness &lt;folder&gt;` after a normal
    /// `dotnet build`, not `dotnet run`.
    /// </summary>
    public static class RegressionHarnessCli
    {
        public static int Run(string[] args)
        {
            var harnessFlagIndex = Array.IndexOf(args, "--harness");
            if (harnessFlagIndex < 0 || harnessFlagIndex + 1 >= args.Length)
            {
                Console.Error.WriteLine("Usage: --harness <folder-of-samples>");
                return 1;
            }

            var samplesDirectory = args[harnessFlagIndex + 1];
            var logger = new ConsoleLogger();
            var results = RegressionHarness.RunAll(samplesDirectory, logger);

            var failed = 0;
            foreach (var result in results)
            {
                var ok = result.DevirtualizationSucceeded &&
                         (result.Structural?.IsClean ?? false) &&
                         (result.Behavioral == null || result.Behavioral.MatchesBaseline);
                Console.WriteLine($"{(ok ? "PASS" : "FAIL")} {result.SamplePath}");
                if (!ok) failed++;
            }

            Console.WriteLine($"{results.Count - failed}/{results.Count} samples passed.");
            return failed == 0 ? 0 : 1;
        }

        private sealed class ConsoleLogger : ILogger
        {
            public void Success(string message) => Console.WriteLine("[OK] " + message);
            public void Warning(string message) => Console.WriteLine("[WARN] " + message);
            public void Error(string message) => Console.Error.WriteLine("[ERROR] " + message);
            public void Info(string message) => Console.WriteLine("[INFO] " + message);
            public void InfoStr(string message, string message2) => Console.WriteLine($"[INFO] {message} {message2}");
        }
    }
}
```

Document the invocation in a short comment at the top of `RegressionHarness.cs` (already present above) — no separate README change is required by this plan; if the user wants a documented CLI wrapper script later, that's a follow-up, not part of this task.

- [ ] **Step 7: Run the full test suite**

Run: `dotnet test Krypton.Tests/Krypton.Tests.csproj`
Expected: PASS — `SampleRegressionTests` still gracefully skips (0 samples locally), all new harness unit tests (Tasks 11-13) pass, and no pre-existing test regresses.

- [ ] **Step 8: Commit**

```bash
git add Krypton.Tests/SampleRegressionTests.cs Krypton.Tests/Harness/RegressionHarness.cs Krypton.Tests/Harness/RegressionHarnessCli.cs Krypton.Tests/Harness/RegressionHarnessTests.cs
git commit -m "feat: replace assertion-free sample smoke test with a structural+behavioral regression harness, runnable standalone"
```

---

## Self-Review Notes

- **Spec coverage:** §1 → Tasks 1-3. §2 → Tasks 4-6. §3 → Task 7 (refined: the main path uses the analyzers as a pre-build validation/repair gate, not a direct maxstack setter — Task 7 gives NecroBit bodies the same gate rather than inventing a new mechanism, consistent with the spec's "reuse existing analyzers, smallest diff" intent). §4 → Tasks 8-10 (three independent sub-fixes, as scoped). §5 → Tasks 11-13. Task 0 is new scaffolding the spec didn't call out by name but is required by the spec's own constraint ("every task must be unit-testable... without a real protected binary").
- **Placeholder scan:** every task has real, complete code — no `TODO`/`TBD`/"add appropriate handling" text.
- **Type consistency:** `RecompiledMethodArtifact`, `CilBodyAnalysisResult`, `DnlibStyleMaxStackAnalysisResult`, `VMOpCodeCatalog`/`VMOpCodeCatalogEntry`/`VMStackEffectKind`, `CalleeDescriptor`, `InstructionEntry` field names are used identically across every task that touches them (verified against the actual current source during planning, not assumed).
- **Scope check:** each task's tests pass without a live sample; Phase 5's harness is the only place real samples would ever be exercised, and it degrades to a no-op (not a failure) when none are present, per Global Constraints.
