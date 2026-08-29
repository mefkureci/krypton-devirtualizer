using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using AsmResolver.DotNet;
using AsmResolver.DotNet.Code.Cil;
using AsmResolver.DotNet.Signatures.Types;
using AsmResolver.PE.DotNet.Cil;
using Krypton.Core;

namespace Krypton.Pipeline.Stages
{
    public sealed class PostDeobfuscation : IStage
    {
        public string Name => nameof(PostDeobfuscation);

        public void Run(DevirtualizationCtx ctx)
        {
            if (!IsEnabled())
                return;

            var module = ctx.Module;
            if (module == null)
                return;

            var options = BuildOptions();

            if (options.InlineTrivialWrappers || options.ResolveDelegateCalls)
                InlineTrivialWrapperCalls(ctx, module, options);

            if (options.ResolveDelegateCalls)
                InlineResolvedDelegateCalls(ctx, module, options);

            if (options.InlineConstStrings)
                InlineConstStringCalls(ctx, module);

            if (options.SimplifyWrappers)
                RenameTrivialWrappers(ctx, module);

            if (options.RenameObfuscated)
                RenameObfuscatedMembers(ctx, module);

            if (options.RemoveNops || options.SimplifyBranches || options.SafeCflowCleanup)
                SimplifyMethodBodies(ctx, module, options);

            if (options.SimplifyEntryPoint)
                SimplifyEntryPoint(ctx, module, options);

            if (options.SimplifyCctors)
                SimplifyStaticConstructors(ctx, module, options);

            if (options.FixDnSpyStackIssues)
                FixDnSpyStackIssues(ctx, module, options);

            if (options.RewrapBigMethods)
                RewrapBigMethods(ctx, module, options);
        }

        private sealed class CleanOptions
        {
            public bool RemoveNops { get; set; }
            public bool SimplifyBranches { get; set; }
            public bool SafeCflowCleanup { get; set; }
            public bool SafeCflowIncludeNonRecompiled { get; set; }
            public bool ReactorDispatcherRecovery { get; set; }
            public bool SimplifyWrappers { get; set; }
            public bool InlineTrivialWrappers { get; set; }
            public bool ResolveDelegateCalls { get; set; }
            public bool RenameObfuscated { get; set; }
            public bool InlineConstStrings { get; set; }
            public string CleanNamespace { get; set; }
            public bool OnlyRecompiled { get; set; }
            public bool SimplifyEntryPoint { get; set; }
            public bool SimplifyCctors { get; set; }
            public bool FixDnSpyStackIssues { get; set; }
            public bool RewrapBigMethods { get; set; }
        }

        private sealed class TrivialWrapperInfo
        {
            public IMethodDescriptor Target { get; set; }
            public bool UseCallVirt { get; set; }
            public IReadOnlyList<int> LoadedArgumentIndices { get; set; }
            public IReadOnlyList<TypeSignature> WrapperArgumentTypes { get; set; }
        }

        private sealed class ResolvedDelegateTarget
        {
            public FieldDefinition Field { get; set; }
            public IMethodDescriptor Target { get; set; }
            public bool UseCallVirt { get; set; }
        }

        private static bool IsEnabled()
        {
            // KRYPTON_CLEAN_ENABLE=0 is the master kill-switch.
            var cleanEnable = Environment.GetEnvironmentVariable("KRYPTON_CLEAN_ENABLE");
            if (!string.IsNullOrWhiteSpace(cleanEnable))
                return string.Equals(cleanEnable, "1", StringComparison.Ordinal);

            // Stage is on by default — individual transforms are controlled by their own vars.
            return true;
        }

        private static CleanOptions BuildOptions()
        {
            bool DefaultOn(string name, bool defaultValue)
            {
                var raw = Environment.GetEnvironmentVariable(name);
                if (string.IsNullOrWhiteSpace(raw))
                    return defaultValue;
                return string.Equals(raw, "1", StringComparison.Ordinal);
            }

            var strictMapping = DefaultOn("KRYPTON_STRICT_MAPPING", false);

            return new CleanOptions
            {
                RemoveNops = DefaultOn("KRYPTON_CLEAN_REMOVE_NOPS", true),
                SimplifyBranches = DefaultOn("KRYPTON_CLEAN_SIMPLIFY_BRANCHES", false),
                SafeCflowCleanup = DefaultOn("KRYPTON_CLEAN_CFLOW_SAFE", true),
                SafeCflowIncludeNonRecompiled = DefaultOn("KRYPTON_CLEAN_CFLOW_INCLUDE_NONRECOMPILED", true),
                ReactorDispatcherRecovery = DefaultOn("KRYPTON_CLEAN_REACTOR_DISPATCHER", true),
                SimplifyWrappers = DefaultOn("KRYPTON_CLEAN_SIMPLIFY_WRAPPERS", false),
                InlineTrivialWrappers = DefaultOn("KRYPTON_CLEAN_INLINE_WRAPPERS", false),
                ResolveDelegateCalls = DefaultOn("KRYPTON_CLEAN_RESOLVE_DELEGATES", false),
                RenameObfuscated = DefaultOn("KRYPTON_CLEAN_RENAME", true),
                InlineConstStrings = DefaultOn("KRYPTON_CLEAN_INLINE_CONST_STRINGS", false),
                CleanNamespace = Environment.GetEnvironmentVariable("KRYPTON_CLEAN_NAMESPACE") ?? string.Empty,
                OnlyRecompiled = DefaultOn("KRYPTON_CLEAN_ONLY_RECOMPILED", true),
                // Keep risky transforms opt-in to preserve runtime stability in "safe-clean".
                SimplifyEntryPoint = DefaultOn("KRYPTON_CLEAN_ENTRYPOINT", false),
                SimplifyCctors = DefaultOn("KRYPTON_CLEAN_SIMPLIFY_CCTORS", false),
                FixDnSpyStackIssues = DefaultOn("KRYPTON_CLEAN_FIX_DNSPY", false),
                RewrapBigMethods = DefaultOn("KRYPTON_CLEAN_REWRAP_BIG", strictMapping)
            };
        }

        private static void SimplifyMethodBodies(DevirtualizationCtx ctx, ModuleDefinition module, CleanOptions options)
        {
            var cleaned = 0;
            var safeCflowCleaned = 0;
            var reactorCleaned = 0;
            var methodAllow = BuildMethodAllowList(ctx, module, options);
            var safeCflowAllow = BuildSafeCflowAllowList(ctx, module, options);
            var reactorFieldConstants = options.ReactorDispatcherRecovery
                ? DiscoverReactorFieldConstants(module)
                : new Dictionary<FieldDefinition, int>();
            foreach (var method in module.GetAllTypes().SelectMany(t => t.Methods))
            {
                if (!method.HasMethodBody)
                    continue;
                if (method.CilMethodBody == null)
                    continue;

                var body = method.CilMethodBody;
                if (options.ReactorDispatcherRecovery && safeCflowAllow(method))
                    reactorCleaned += InlineKnownReactorFieldConstants(body, reactorFieldConstants);
                if (options.SafeCflowCleanup && safeCflowAllow(method))
                    safeCflowCleaned += ApplySafeControlFlowCleanup(method);

                if (methodAllow(method))
                {
                    if (options.RemoveNops)
                        cleaned += RemoveNopsAndRetarget(method);
                    if (options.SimplifyBranches)
                        cleaned += RemoveTrivialBranches(body);
                }
            }

            if (cleaned > 0)
                ctx.Options.Logger.Info($"Post-deobf simplified {cleaned} instruction(s).");
            if (safeCflowCleaned > 0)
                ctx.Options.Logger.Info($"Post-deobf safe-cflow simplified {safeCflowCleaned} control-flow item(s).");
            if (reactorCleaned > 0)
                ctx.Options.Logger.Info($"Post-deobf Reactor recovery inlined {reactorCleaned} constant field access(es) from {reactorFieldConstants.Count} discovered field value(s).");
        }

        private static int RemoveNopsAndRetarget(MethodDefinition method)
        {
            var body = method.CilMethodBody;
            var instructions = body.Instructions;
            if (instructions.Count == 0)
                return 0;

            // A trailing Nop with nothing after it usually stands in for the VM's
            // return point. Branches/labels that still target it would otherwise
            // go dangling once it is stripped below, which resolves to offset 0
            // at write time instead of the intended fall-through return.
            if (instructions[instructions.Count - 1].OpCode == CilOpCodes.Nop &&
                string.Equals(method.Signature?.ReturnType?.FullName, "System.Void", StringComparison.Ordinal))
            {
                instructions.Add(new CilInstruction(CilOpCodes.Ret));
            }

            // Specialized dispatcher bodies contain many structurally identical
            // clones. A NOP must be retargeted within its own clone, so key this
            // table by instruction identity rather than value equality.
            var nextNonNop = new Dictionary<CilInstruction, CilInstruction>(
                ReferenceEqualityComparer.Instance);
            for (int i = instructions.Count - 1; i >= 0; i--)
            {
                var current = instructions[i];
                if (current.OpCode != CilOpCodes.Nop)
                    nextNonNop[current] = current;
                else if (i + 1 < instructions.Count)
                    nextNonNop[current] = nextNonNop.TryGetValue(instructions[i + 1], out var next) ? next : instructions[i + 1];
                else
                    nextNonNop[current] = current;
            }

            var retargeted = 0;
            foreach (var instr in instructions)
            {
                if (instr.Operand is CilInstruction target && target.OpCode == CilOpCodes.Nop)
                {
                    instr.Operand = nextNonNop[target];
                    retargeted++;
                }
                else if (instr.Operand is CilInstructionLabel label &&
                         label.Instruction != null &&
                         label.Instruction.OpCode == CilOpCodes.Nop &&
                         nextNonNop.TryGetValue(label.Instruction, out var nextTarget))
                {
                    instr.Operand = new CilInstructionLabel(nextTarget);
                    retargeted++;
                }
                else if (instr.Operand is IList<CilInstruction> targets)
                {
                    for (int i = 0; i < targets.Count; i++)
                    {
                        var t = targets[i];
                        if (t.OpCode == CilOpCodes.Nop)
                        {
                            targets[i] = nextNonNop[t];
                            retargeted++;
                        }
                    }
                }
                else if (instr.Operand is IList<ICilLabel> labels)
                {
                    for (int i = 0; i < labels.Count; i++)
                    {
                        if (!(labels[i] is CilInstructionLabel targetLabel) ||
                            targetLabel.Instruction == null ||
                            targetLabel.Instruction.OpCode != CilOpCodes.Nop ||
                            !nextNonNop.TryGetValue(targetLabel.Instruction, out var nextLabelTarget))
                        {
                            continue;
                        }

                        labels[i] = new CilInstructionLabel(nextLabelTarget);
                        retargeted++;
                    }
                }
            }

            var removed = 0;
            for (int i = instructions.Count - 1; i >= 0; i--)
            {
                if (instructions[i].OpCode == CilOpCodes.Nop)
                {
                    instructions.RemoveAt(i);
                    removed++;
                }
            }

            return removed + retargeted;
        }

        private static int RemoveTrivialBranches(CilMethodBody body)
        {
            var instructions = body.Instructions;
            if (instructions.Count == 0)
                return 0;

            var removed = 0;
            for (int i = instructions.Count - 2; i >= 0; i--)
            {
                var instr = instructions[i];
                if (instr.OpCode != CilOpCodes.Br && instr.OpCode != CilOpCodes.Br_S)
                    continue;

                if (instr.Operand is CilInstruction target)
                {
                    var next = instructions[i + 1];
                    if (ReferenceEquals(target, next))
                    {
                        instructions.RemoveAt(i);
                        removed++;
                    }
                }
            }

            return removed;
        }

        private static int ApplySafeControlFlowCleanup(MethodDefinition method)
        {
            var body = method?.CilMethodBody;
            if (body?.Instructions == null || body.Instructions.Count == 0)
                return 0;

            var total = 0;
            for (var iter = 0; iter < 12; iter++)
            {
                var round = 0;
                round += RecoverReactorDispatcherTransitions(method);
                round += RecoverDirectReactorSwitchTransitions(method);
                round += EliminateOpaquePredicates(body);
                round += RemoveDiscardedConstants(body);
                round += ThreadBranchTargets(body);
                round += SimplifyUniformSwitchDispatch(body);
                round += RemoveTrivialBranches(body);
                if (body.ExceptionHandlers.Count == 0)
                    round += RemoveUnreachableInstructions(body);
                if (round == 0)
                    break;
                total += round;
            }

            // Dead-code removal is kept separate (opt-in via RemoveNops) because
            // CilOffsetLabel-based exception handler boundaries in old-format PE files
            // are not resolved by ResolveLabelInstruction and would become dangling.
            return total;
        }

        private static int RemoveDiscardedConstants(CilMethodBody body)
        {
            var instructions = body.Instructions;
            var targeted = BuildTargetedInstructionSet(body);
            var changed = 0;
            for (var i = 0; i < instructions.Count; i++)
            {
                if (!TryGetConstInt32(instructions[i], out _) || targeted.Contains(instructions[i]))
                    continue;

                var popIndex = NextNonNopIndex(instructions, i + 1);
                if (popIndex < 0 || instructions[popIndex].OpCode != CilOpCodes.Pop)
                    continue;

                var hasTargetedInterior = false;
                for (var j = i + 1; j <= popIndex; j++)
                    hasTargetedInterior |= targeted.Contains(instructions[j]);
                if (hasTargetedInterior)
                    continue;

                MakeNop(instructions[i]);
                MakeNop(instructions[popIndex]);
                changed += 2;
                i = popIndex;
            }
            return changed;
        }

        /// <summary>
        /// Reconnects constant state transitions produced by .NET Reactor control-flow
        /// flattening.  Reactor commonly funnels both the method entry and every case
        /// through this shape:
        ///
        ///     ldc.i4 state; br store
        /// store: stloc selector
        ///        ldloc selector
        ///        switch (...)
        ///
        /// Some variants branch directly to the switch with the state still on the
        /// evaluation stack.  Once opaque predicates have been folded, both shapes can
        /// be replaced with a direct edge to the selected case.  Out-of-range states are
        /// resolved through the small equality-test chain that Reactor puts after the
        /// switch (its default dispatcher).
        /// </summary>
        private static int RecoverReactorDispatcherTransitions(MethodDefinition method)
        {
            var body = method?.CilMethodBody;
            if (body == null || body.ExceptionHandlers.Count != 0 || body.Instructions.Count < 4)
                return 0;

            var instructions = body.Instructions;
            var changed = 0;

            // Work on one dispatcher at a time.  The outer cleanup loop will revisit the
            // method after unreachable blocks have disappeared.
            for (var switchIndex = 1; switchIndex < instructions.Count; switchIndex++)
            {
                var switchInstruction = instructions[switchIndex];
                if (switchInstruction.OpCode != CilOpCodes.Switch ||
                    !TryGetSwitchTargets(switchInstruction.Operand, out var cases) ||
                    cases.Count == 0)
                {
                    continue;
                }

                var loadIndex = PreviousNonNopIndex(instructions, switchIndex - 1);
                if (loadIndex < 0 || !TryGetLdlocVariable(body, instructions[loadIndex], out var selector))
                    continue;

                var storeIndex = PreviousNonNopIndex(instructions, loadIndex - 1);
                if (storeIndex < 0 ||
                    !TryGetStlocVariable(body, instructions[storeIndex], out var storedSelector) ||
                    !ReferenceEquals(selector, storedSelector))
                {
                    continue;
                }

                var storeInstruction = instructions[storeIndex];
                var branchRewrites = new List<Tuple<CilInstruction, CilInstruction, CilInstruction>>();
                var allStoreIncomingRecognized = true;

                foreach (var branch in instructions)
                {
                    if (!IsUnconditionalBranch(branch.OpCode) ||
                        !TryGetBranchTarget(branch.Operand, out var branchTarget) ||
                        (!ReferenceEquals(branchTarget, storeInstruction) &&
                         !ReferenceEquals(branchTarget, switchInstruction)))
                    {
                        continue;
                    }

                    var branchIndex = instructions.IndexOf(branch);
                    var constantIndex = PreviousNonNopIndex(instructions, branchIndex - 1);
                    if (constantIndex < 0 ||
                        !TryGetConstInt32(instructions[constantIndex], out var state) ||
                        !OnlyNopsBetween(instructions, constantIndex, branchIndex))
                    {
                        if (ReferenceEquals(branchTarget, storeInstruction))
                            allStoreIncomingRecognized = false;
                        continue;
                    }

                    var destination = ResolveReactorDispatcherTarget(
                        body, switchIndex, selector, cases, state);
                    if (destination == null ||
                        ReferenceEquals(destination, storeInstruction) ||
                        ReferenceEquals(destination, instructions[loadIndex]) ||
                        ReferenceEquals(destination, switchInstruction))
                    {
                        if (ReferenceEquals(branchTarget, storeInstruction))
                            allStoreIncomingRecognized = false;
                        continue;
                    }

                    branchRewrites.Add(Tuple.Create(instructions[constantIndex], branch, destination));
                }

                // Entry fallthrough: ldc state; stloc selector; ldloc selector; switch.
                var entryConstantIndex = PreviousNonNopIndex(instructions, storeIndex - 1);
                CilInstruction entryDestination = null;
                if (entryConstantIndex >= 0 &&
                    TryGetConstInt32(instructions[entryConstantIndex], out var entryState) &&
                    OnlyNopsBetween(instructions, entryConstantIndex, storeIndex))
                {
                    entryDestination = ResolveReactorDispatcherTarget(
                        body, switchIndex, selector, cases, entryState);
                }

                // Replacing the shared store is safe only when every explicit incoming
                // edge was understood and redirected.
                if (entryDestination == null || !allStoreIncomingRecognized)
                    continue;

                var snapshot = instructions
                    .Select(instruction => Tuple.Create(instruction, instruction.OpCode, instruction.Operand))
                    .ToList();

                foreach (var rewrite in branchRewrites)
                {
                    MakeNop(rewrite.Item1);
                    rewrite.Item2.OpCode = CilOpCodes.Br;
                    rewrite.Item2.Operand = new CilInstructionLabel(rewrite.Item3);
                    changed += 2;
                }

                MakeNop(instructions[entryConstantIndex]);
                storeInstruction.OpCode = CilOpCodes.Br;
                storeInstruction.Operand = new CilInstructionLabel(entryDestination);
                changed += 2;

                // Reactor can carry a non-selector payload underneath the state value.
                // Keep the reconstruction only when both independent stack analyses say
                // it did not make the method less verifiable.
                if (!HasValidStack(body))
                {
                    foreach (var item in snapshot)
                    {
                        item.Item1.OpCode = item.Item2;
                        item.Item1.Operand = item.Item3;
                    }
                    return 0;
                }
                return changed;
            }

            return changed;
        }

        /// <summary>
        /// Finishes a dispatcher after its shared state store was removed. At that
        /// point the remaining real edges commonly use ldc.i4 state; br switch.
        /// </summary>
        private static int RecoverDirectReactorSwitchTransitions(MethodDefinition method)
        {
            var body = method?.CilMethodBody;
            if (body == null || body.ExceptionHandlers.Count != 0 || body.Instructions.Count < 3)
                return 0;

            var instructions = body.Instructions;
            for (var switchIndex = 1; switchIndex < instructions.Count; switchIndex++)
            {
                var switchInstruction = instructions[switchIndex];
                if (switchInstruction.OpCode != CilOpCodes.Switch ||
                    !TryGetSwitchTargets(switchInstruction.Operand, out var cases) ||
                    cases.Count == 0)
                {
                    continue;
                }

                var loadIndex = PreviousNonNopIndex(instructions, switchIndex - 1);
                if (loadIndex < 0 || !TryGetLdlocVariable(body, instructions[loadIndex], out var selector))
                    continue;

                var rewrites = new List<Tuple<CilInstruction, CilInstruction, CilInstruction>>();
                foreach (var branch in instructions)
                {
                    if (!IsUnconditionalBranch(branch.OpCode) ||
                        !TryGetBranchTarget(branch.Operand, out var target) ||
                        !ReferenceEquals(target, switchInstruction))
                    {
                        continue;
                    }

                    var branchIndex = instructions.IndexOf(branch);
                    var constantIndex = PreviousNonNopIndex(instructions, branchIndex - 1);
                    if (constantIndex < 0 ||
                        !TryGetConstInt32(instructions[constantIndex], out var state) ||
                        !OnlyNopsBetween(instructions, constantIndex, branchIndex))
                    {
                        continue;
                    }

                    var destination = ResolveReactorDispatcherTarget(
                        body, switchIndex, selector, cases, state);
                    if (destination != null &&
                        !ReferenceEquals(destination, instructions[loadIndex]) &&
                        !ReferenceEquals(destination, switchInstruction))
                    {
                        rewrites.Add(Tuple.Create(instructions[constantIndex], branch, destination));
                    }
                }

                if (rewrites.Count == 0)
                    continue;

                var snapshot = instructions
                    .Select(instruction => Tuple.Create(instruction, instruction.OpCode, instruction.Operand))
                    .ToList();
                foreach (var rewrite in rewrites)
                {
                    MakeNop(rewrite.Item1);
                    rewrite.Item2.OpCode = CilOpCodes.Br;
                    rewrite.Item2.Operand = new CilInstructionLabel(rewrite.Item3);
                }

                if (!HasValidStack(body))
                {
                    foreach (var item in snapshot)
                    {
                        item.Item1.OpCode = item.Item2;
                        item.Item1.Operand = item.Item3;
                    }
                    continue;
                }

                return rewrites.Count * 2;
            }

            return 0;
        }

        private static bool HasValidStack(CilMethodBody body)
        {
            try
            {
                body.VerifyLabels(calculateOffsets: true);
                body.ComputeMaxStack(calculateOffsets: false);
                return true;
            }
            catch
            {
                return false;
            }
        }

        private static CilInstruction ResolveReactorDispatcherTarget(
            CilMethodBody body,
            int switchIndex,
            CilLocalVariable selector,
            IReadOnlyList<CilInstruction> cases,
            int state)
        {
            if (state >= 0 && state < cases.Count)
                return FollowBranchChain(cases[state]) ?? cases[state];

            var instructions = body.Instructions;
            var index = switchIndex + 1;
            var visited = new HashSet<int>();
            while (index >= 0 && index < instructions.Count && visited.Add(index))
            {
                index = NextNonNopIndex(instructions, index);
                if (index < 0)
                    return null;

                var current = instructions[index];
                if (IsUnconditionalBranch(current.OpCode) &&
                    TryGetBranchTarget(current.Operand, out var direct))
                {
                    return FollowBranchChain(direct) ?? direct;
                }

                if (!TryGetLdlocVariable(body, current, out var loaded) ||
                    !ReferenceEquals(loaded, selector))
                {
                    return null;
                }

                var constantIndex = NextNonNopIndex(instructions, index + 1);
                var branchIndex = constantIndex < 0
                    ? -1
                    : NextNonNopIndex(instructions, constantIndex + 1);
                if (constantIndex < 0 || branchIndex < 0 ||
                    !TryGetConstInt32(instructions[constantIndex], out var compared) ||
                    !TryGetBranchTarget(instructions[branchIndex].Operand, out var target))
                {
                    return null;
                }

                var code = instructions[branchIndex].OpCode.Code;
                var isEqualBranch = code == CilCode.Beq || code == CilCode.Beq_S;
                var isNotEqualBranch = code == CilCode.Bne_Un || code == CilCode.Bne_Un_S;
                if (!isEqualBranch && !isNotEqualBranch)
                    return null;

                var taken = isEqualBranch ? state == compared : state != compared;
                if (taken)
                    return FollowBranchChain(target) ?? target;

                index = branchIndex + 1;
            }

            return null;
        }

        private static int PreviousNonNopIndex(CilInstructionCollection instructions, int index)
        {
            while (index >= 0 && instructions[index].OpCode == CilOpCodes.Nop)
                index--;
            return index;
        }

        private static int NextNonNopIndex(CilInstructionCollection instructions, int index)
        {
            while (index < instructions.Count && instructions[index].OpCode == CilOpCodes.Nop)
                index++;
            return index < instructions.Count ? index : -1;
        }

        private static bool OnlyNopsBetween(CilInstructionCollection instructions, int first, int second)
        {
            for (var i = first + 1; i < second; i++)
            {
                if (instructions[i].OpCode != CilOpCodes.Nop)
                    return false;
            }
            return true;
        }

        private static Dictionary<FieldDefinition, int> DiscoverReactorFieldConstants(ModuleDefinition module)
        {
            var result = new Dictionary<FieldDefinition, int>();
            if (module == null)
                return result;

            foreach (var method in module.GetAllTypes().SelectMany(type => type.Methods))
            {
                var body = method?.CilMethodBody;
                if (body == null || body.ExceptionHandlers.Count > 0 || body.Instructions.Count < 4)
                    continue;

                var instructions = body.Instructions;
                for (var i = 1; i < instructions.Count; i++)
                {
                    if (instructions[i].OpCode != CilOpCodes.Stfld ||
                        !(instructions[i].Operand is IFieldDescriptor targetDescriptor))
                    {
                        continue;
                    }

                    var target = targetDescriptor.Resolve() as FieldDefinition;
                    if (target == null ||
                        !string.Equals(target.Signature?.FieldType?.FullName, "System.Int32", StringComparison.Ordinal))
                    {
                        continue;
                    }

                    var objectLoadIndex = i - 1;
                    while (objectLoadIndex >= 0 &&
                           instructions[objectLoadIndex].OpCode != CilOpCodes.Ldsfld &&
                           instructions[objectLoadIndex].OpCode != CilOpCodes.Stfld &&
                           instructions[objectLoadIndex].OpCode != CilOpCodes.Stsfld &&
                           !IsTerminal(instructions[objectLoadIndex].OpCode))
                    {
                        objectLoadIndex--;
                    }

                    if (objectLoadIndex < 0 || instructions[objectLoadIndex].OpCode != CilOpCodes.Ldsfld)
                        continue;
                    if (!TryEvaluateInt32Expression(instructions, objectLoadIndex + 1, i - 1, out var value))
                        continue;

                    result[target] = value;
                }
            }

            return result;
        }

        private static bool TryEvaluateInt32Expression(
            CilInstructionCollection instructions,
            int start,
            int end,
            out int value)
        {
            value = 0;
            if (instructions == null || start < 0 || end < start || end >= instructions.Count)
                return false;

            var stack = new Stack<int>();
            for (var i = start; i <= end; i++)
            {
                var instruction = instructions[i];
                if (TryGetConstInt32(instruction, out var constant))
                {
                    stack.Push(constant);
                    continue;
                }

                unchecked
                {
                    switch (instruction.OpCode.Code)
                    {
                        case CilCode.Neg:
                            if (stack.Count < 1) return false;
                            stack.Push(-stack.Pop());
                            break;
                        case CilCode.Not:
                            if (stack.Count < 1) return false;
                            stack.Push(~stack.Pop());
                            break;
                        case CilCode.Add:
                        case CilCode.Sub:
                        case CilCode.Mul:
                        case CilCode.Xor:
                        case CilCode.And:
                        case CilCode.Or:
                        case CilCode.Shl:
                        case CilCode.Shr:
                        case CilCode.Shr_Un:
                            if (stack.Count < 2) return false;
                            var right = stack.Pop();
                            var left = stack.Pop();
                            switch (instruction.OpCode.Code)
                            {
                                case CilCode.Add: stack.Push(left + right); break;
                                case CilCode.Sub: stack.Push(left - right); break;
                                case CilCode.Mul: stack.Push(left * right); break;
                                case CilCode.Xor: stack.Push(left ^ right); break;
                                case CilCode.And: stack.Push(left & right); break;
                                case CilCode.Or: stack.Push(left | right); break;
                                case CilCode.Shl: stack.Push(left << (right & 31)); break;
                                case CilCode.Shr: stack.Push(left >> (right & 31)); break;
                                case CilCode.Shr_Un: stack.Push((int)((uint)left >> (right & 31))); break;
                            }
                            break;
                        default:
                            return false;
                    }
                }
            }

            if (stack.Count != 1)
                return false;
            value = stack.Pop();
            return true;
        }

        private static int InlineKnownReactorFieldConstants(
            CilMethodBody body,
            IReadOnlyDictionary<FieldDefinition, int> constants)
        {
            if (body?.Instructions == null || body.Instructions.Count < 2 || constants == null || constants.Count == 0)
                return 0;

            var targeted = BuildTargetedInstructionSet(body);
            var instructions = body.Instructions;
            var changed = 0;
            for (var i = 1; i < instructions.Count; i++)
            {
                var fieldLoad = instructions[i];
                if (fieldLoad.OpCode != CilOpCodes.Ldfld ||
                    !(fieldLoad.Operand is IFieldDescriptor descriptor) ||
                    !(descriptor.Resolve() is FieldDefinition field) ||
                    !constants.TryGetValue(field, out var value))
                {
                    continue;
                }

                var instanceLoad = instructions[i - 1];
                if (instanceLoad.OpCode != CilOpCodes.Ldsfld || targeted.Contains(fieldLoad))
                    continue;

                MakeNop(instanceLoad);
                fieldLoad.OpCode = CilOpCodes.Ldc_I4;
                fieldLoad.Operand = value;
                changed++;
            }

            return changed;
        }

        /// <summary>
        /// Folds branch conditions whose result is statically determinable from constant operands.
        ///
        /// Patterns handled:
        ///   ldc.i4 N; brtrue/brfalse target         → br target / nop;nop
        ///   ldnull;   brtrue/brfalse target          → br target / nop;nop
        ///   ldc.i4 L; ldc.i4 R; beq/bne/blt/… target → nop;nop;br/nop
        ///   ldc.i4 L; ldc.i4 R; ceq/clt/cgt; brtrue/brfalse → nop×3;br/nop
        ///   ldc.i4 N; switch [t0,t1,…]              → br tN / nop;nop
        /// </summary>
        private static int EliminateOpaquePredicates(CilMethodBody body)
        {
            var instr = body.Instructions;
            var changed = 0;
            var targeted = BuildTargetedInstructionSet(body);

            for (int i = 0; i < instr.Count; i++)
            {
                var ins0 = instr[i];

                // ── 4-instruction: const; const; ceq/clt/cgt; brtrue/brfalse ──────
                if (i + 3 < instr.Count &&
                    TryGetConstInt32(ins0, out var v4L) &&
                    TryGetConstInt32(instr[i + 1], out var v4R))
                {
                    var cmpIns = instr[i + 2];
                    var brIns  = instr[i + 3];
                    int? cmpResult = EvalCompare(cmpIns.OpCode.Code, v4L, v4R);
                    if (!HasTargetedInterior(instr, targeted, i, i + 3) &&
                        cmpResult.HasValue && TryEvalBranch1(cmpResult.Value, brIns, out var taken4, out var tgt4))
                    {
                        FoldNop(instr, i); FoldNop(instr, i + 1); FoldNop(instr, i + 2);
                        FoldConditional(brIns, taken4, tgt4);
                        changed += 4;
                        i += 3;
                        continue;
                    }
                }

                // ── 3-instruction: const; const; beq/bne/blt/… ───────────────────
                if (i + 2 < instr.Count &&
                    TryGetConstInt32(ins0, out var vL) &&
                    TryGetConstInt32(instr[i + 1], out var vR))
                {
                    var brIns = instr[i + 2];
                    if (!HasTargetedInterior(instr, targeted, i, i + 2) &&
                        TryEvalBranch2(vL, vR, brIns, out var taken3, out var tgt3))
                    {
                        FoldNop(instr, i); FoldNop(instr, i + 1);
                        FoldConditional(brIns, taken3, tgt3);
                        changed += 3;
                        i += 2;
                        continue;
                    }
                }

                // ── 2-instruction: const; brtrue/brfalse ─────────────────────────
                if (i + 1 < instr.Count && TryGetConstInt32(ins0, out var v1))
                {
                    var brIns = instr[i + 1];
                    if (!HasTargetedInterior(instr, targeted, i, i + 1) &&
                        TryEvalBranch1(v1, brIns, out var taken2, out var tgt2))
                    {
                        FoldNop(instr, i);
                        FoldConditional(brIns, taken2, tgt2);
                        changed += 2;
                        i++;
                        continue;
                    }
                }

                // ── 2-instruction: ldnull; brtrue/brfalse ────────────────────────
                if (i + 1 < instr.Count && ins0.OpCode == CilOpCodes.Ldnull)
                {
                    var brIns = instr[i + 1];
                    // ldnull == null → brfalse always taken, brtrue never taken
                    if (!HasTargetedInterior(instr, targeted, i, i + 1) &&
                        TryEvalBranch1(0, brIns, out var takenN, out var tgtN))
                    {
                        FoldNop(instr, i);
                        FoldConditional(brIns, takenN, tgtN);
                        changed += 2;
                        i++;
                        continue;
                    }
                }

                // ── 2-instruction: const; switch ─────────────────────────────────
                if (i + 1 < instr.Count &&
                    TryGetConstInt32(ins0, out var vSw) &&
                    instr[i + 1].OpCode == CilOpCodes.Switch &&
                    TryGetSwitchTargets(instr[i + 1].Operand, out var swTargets) &&
                    !HasTargetedInterior(instr, targeted, i, i + 1))
                {
                    FoldNop(instr, i);
                    if (vSw >= 0 && vSw < swTargets.Count)
                    {
                        instr[i + 1].OpCode = CilOpCodes.Br;
                        instr[i + 1].Operand = new CilInstructionLabel(swTargets[vSw]);
                    }
                    else
                    {
                        FoldNop(instr, i + 1);
                    }
                    changed += 2;
                    i++;
                    continue;
                }
            }

            return changed;
        }

        private static bool HasTargetedInterior(
            CilInstructionCollection instructions,
            ISet<CilInstruction> targeted,
            int start,
            int end)
        {
            for (var i = start + 1; i <= end; i++)
            {
                if (targeted.Contains(instructions[i]))
                    return true;
            }
            return false;
        }

        private static bool TryEvalBranch1(int val, CilInstruction brIns, out bool taken, out CilInstruction target)
        {
            taken = false;
            target = null;
            if (!TryGetBranchTarget(brIns.Operand, out var t))
                return false;
            target = t;
            var code = brIns.OpCode.Code;
            if (code == CilCode.Brtrue || code == CilCode.Brtrue_S)  { taken = val != 0; return true; }
            if (code == CilCode.Brfalse || code == CilCode.Brfalse_S) { taken = val == 0; return true; }
            return false;
        }

        private static bool TryEvalBranch2(int lhs, int rhs, CilInstruction brIns, out bool taken, out CilInstruction target)
        {
            taken = false;
            target = null;
            if (!TryGetBranchTarget(brIns.Operand, out var t))
                return false;
            target = t;
            var code = brIns.OpCode.Code;
            switch (code)
            {
                case CilCode.Beq:    case CilCode.Beq_S:    taken = lhs == rhs; return true;
                case CilCode.Bne_Un: case CilCode.Bne_Un_S: taken = lhs != rhs; return true;
                case CilCode.Blt:    case CilCode.Blt_S:    taken = lhs < rhs;  return true;
                case CilCode.Bgt:    case CilCode.Bgt_S:    taken = lhs > rhs;  return true;
                case CilCode.Ble:    case CilCode.Ble_S:    taken = lhs <= rhs; return true;
                case CilCode.Bge:    case CilCode.Bge_S:    taken = lhs >= rhs; return true;
                case CilCode.Blt_Un: case CilCode.Blt_Un_S: taken = (uint)lhs < (uint)rhs;  return true;
                case CilCode.Bgt_Un: case CilCode.Bgt_Un_S: taken = (uint)lhs > (uint)rhs;  return true;
                case CilCode.Ble_Un: case CilCode.Ble_Un_S: taken = (uint)lhs <= (uint)rhs; return true;
                case CilCode.Bge_Un: case CilCode.Bge_Un_S: taken = (uint)lhs >= (uint)rhs; return true;
                default: return false;
            }
        }

        private static int? EvalCompare(CilCode code, int lhs, int rhs)
        {
            switch (code)
            {
                case CilCode.Ceq:    return lhs == rhs ? 1 : 0;
                case CilCode.Clt:    return lhs < rhs  ? 1 : 0;
                case CilCode.Cgt:    return lhs > rhs  ? 1 : 0;
                case CilCode.Clt_Un: return (uint)lhs < (uint)rhs  ? 1 : 0;
                case CilCode.Cgt_Un: return (uint)lhs > (uint)rhs  ? 1 : 0;
                default: return null;
            }
        }

        private static bool TryGetConstInt32(CilInstruction ins, out int value)
        {
            value = 0;
            var code = ins.OpCode.Code;
            switch (code)
            {
                case CilCode.Ldc_I4:   value = (int)ins.Operand;    return true;
                case CilCode.Ldc_I4_S: value = (sbyte)ins.Operand;  return true;
                case CilCode.Ldc_I4_M1: value = -1; return true;
                case CilCode.Ldc_I4_0:  value = 0;  return true;
                case CilCode.Ldc_I4_1:  value = 1;  return true;
                case CilCode.Ldc_I4_2:  value = 2;  return true;
                case CilCode.Ldc_I4_3:  value = 3;  return true;
                case CilCode.Ldc_I4_4:  value = 4;  return true;
                case CilCode.Ldc_I4_5:  value = 5;  return true;
                case CilCode.Ldc_I4_6:  value = 6;  return true;
                case CilCode.Ldc_I4_7:  value = 7;  return true;
                case CilCode.Ldc_I4_8:  value = 8;  return true;
                default: return false;
            }
        }

        private static void FoldNop(CilInstructionCollection instr, int i)
        {
            instr[i].OpCode = CilOpCodes.Nop;
            instr[i].Operand = null;
        }

        private static void FoldConditional(CilInstruction brIns, bool taken, CilInstruction target)
        {
            if (taken)
            {
                brIns.OpCode = CilOpCodes.Br;
                brIns.Operand = new CilInstructionLabel(target);
            }
            else
            {
                brIns.OpCode = CilOpCodes.Nop;
                brIns.Operand = null;
            }
        }

        private static bool TryGetBranchTarget(object operand, out CilInstruction target)
        {
            target = operand as CilInstruction;
            if (target != null)
                return true;
            target = (operand as CilInstructionLabel)?.Instruction;
            return target != null;
        }

        private static bool TryGetSwitchTargets(object operand, out List<CilInstruction> targets)
        {
            targets = new List<CilInstruction>();
            if (operand is IList<CilInstruction> rawTargets)
            {
                targets.AddRange(rawTargets);
                return targets.Count > 0 && targets.All(target => target != null);
            }

            if (!(operand is IList<ICilLabel> labels))
                return false;
            foreach (var label in labels)
            {
                var target = (label as CilInstructionLabel)?.Instruction;
                if (target == null)
                    return false;
                targets.Add(target);
            }
            return targets.Count > 0;
        }

        private static void SetSwitchTarget(CilInstruction switchInstruction, int index, CilInstruction target)
        {
            if (switchInstruction?.Operand is IList<CilInstruction> rawTargets)
            {
                rawTargets[index] = target;
                return;
            }
            if (switchInstruction?.Operand is IList<ICilLabel> labels)
                labels[index] = new CilInstructionLabel(target);
        }

        private static int ThreadBranchTargets(CilMethodBody body)
        {
            var changed = 0;
            var instructions = body.Instructions;
            if (instructions.Count == 0)
                return 0;

            foreach (var ins in instructions)
            {
                if (TryGetBranchTarget(ins.Operand, out var target))
                {
                    var rewritten = FollowBranchChain(target);
                    if (rewritten != null && !ReferenceEquals(rewritten, target))
                    {
                        ins.Operand = new CilInstructionLabel(rewritten);
                        changed++;
                    }
                }
                else if (TryGetSwitchTargets(ins.Operand, out var targets))
                {
                    for (int i = 0; i < targets.Count; i++)
                    {
                        var rewritten = FollowBranchChain(targets[i]);
                        if (rewritten != null && !ReferenceEquals(rewritten, targets[i]))
                        {
                            SetSwitchTarget(ins, i, rewritten);
                            changed++;
                        }
                    }
                }
            }

            return changed;
        }

        private static int SimplifyUniformSwitchDispatch(CilMethodBody body)
        {
            var instructions = body.Instructions;
            if (instructions.Count == 0)
                return 0;

            var changed = 0;
            for (int i = 0; i < instructions.Count; i++)
            {
                var ins = instructions[i];
                if (ins.OpCode != CilOpCodes.Switch || !TryGetSwitchTargets(ins.Operand, out var rawTargets) || rawTargets.Count == 0)
                    continue;

                var normalized = new List<CilInstruction>(rawTargets.Count);
                foreach (var t in rawTargets)
                    normalized.Add(FollowBranchChain(t) ?? t);

                var first = normalized[0];
                var allSame = true;
                for (int j = 1; j < normalized.Count; j++)
                {
                    if (!ReferenceEquals(normalized[j], first))
                    {
                        allSame = false;
                        break;
                    }
                }

                if (!allSame || first == null)
                    continue;

                // switch pops selector; preserve stack by replacing with pop + br target.
                ins.OpCode = CilOpCodes.Pop;
                ins.Operand = null;
                instructions.Insert(i + 1, new CilInstruction(CilOpCodes.Br, new CilInstructionLabel(first)));
                changed += 2;
                i++;
            }

            return changed;
        }

        private static CilInstruction FollowBranchChain(CilInstruction target)
        {
            if (target == null)
                return null;

            var current = target;
            var visited = new HashSet<CilInstruction>(ReferenceEqualityComparer.Instance);
            while (current != null && visited.Add(current))
            {
                if ((current.OpCode == CilOpCodes.Br || current.OpCode == CilOpCodes.Br_S) &&
                    TryGetBranchTarget(current.Operand, out var next))
                {
                    current = next;
                    continue;
                }

                break;
            }

            return current;
        }

        private static int RemoveUnreachableInstructions(CilMethodBody body)
        {
            var instructions = body.Instructions;
            if (instructions.Count == 0)
                return 0;

            var reachable = ComputeReachableInstructions(body);
            var removed = 0;
            for (int i = instructions.Count - 1; i >= 0; i--)
            {
                if (!reachable.Contains(instructions[i]))
                {
                    instructions.RemoveAt(i);
                    removed++;
                }
            }

            return removed;
        }

        private static void RenameTrivialWrappers(DevirtualizationCtx ctx, ModuleDefinition module)
        {
            var renamed = 0;
            var options = BuildOptions();
            var methodAllow = BuildMethodAllowList(ctx, module, options);
            foreach (var method in module.GetAllTypes().SelectMany(t => t.Methods))
            {
                if (!methodAllow(method))
                    continue;
                if (!IsTrivialWrapper(method, out var targetName))
                    continue;

                var newName = $"Call_{targetName}";
                if (string.Equals(method.Name, newName, StringComparison.Ordinal))
                    continue;

                method.Name = MakeUniqueMethodName(method.DeclaringType, newName);
                renamed++;
            }

            if (renamed > 0)
                ctx.Options.Logger.Info($"Post-deobf renamed {renamed} trivial wrapper method(s).");
        }

        private static void InlineTrivialWrapperCalls(
            DevirtualizationCtx ctx,
            ModuleDefinition module,
            CleanOptions options)
        {
            var wrappers = new Dictionary<MethodDefinition, TrivialWrapperInfo>();
            foreach (var method in module.GetAllTypes().SelectMany(t => t.Methods))
            {
                if (TryGetStrictTrivialWrapper(method, out var info))
                    wrappers[method] = info;
            }

            if (wrappers.Count == 0)
                return;

            var replaced = 0;
            var methodAllow = BuildMethodAllowList(ctx, module, options);
            foreach (var method in module.GetAllTypes().SelectMany(t => t.Methods))
            {
                if (!methodAllow(method))
                    continue;
                if (!method.HasMethodBody || method.CilMethodBody == null)
                    continue;

                var instructions = method.CilMethodBody.Instructions;
                for (var i = 0; i < instructions.Count; i++)
                {
                    var ins = instructions[i];
                    if (ins.OpCode != CilOpCodes.Call && ins.OpCode != CilOpCodes.Callvirt)
                        continue;

                    if (!(ins.Operand is IMethodDescriptor callee))
                        continue;

                    var calleeDefinition = callee.Resolve() as MethodDefinition;
                    if (calleeDefinition == null || ReferenceEquals(calleeDefinition, method))
                        continue;

                    if (!wrappers.TryGetValue(calleeDefinition, out var wrapper))
                        continue;

                    if (CanReplaceWrapperCallDirectly(wrapper))
                    {
                        ins.OpCode = wrapper.UseCallVirt ? CilOpCodes.Callvirt : CilOpCodes.Call;
                        ins.Operand = wrapper.Target;
                    }
                    else
                    {
                        var replacement = BuildWrapperCallExpansion(method.CilMethodBody, wrapper);
                        if (replacement == null || replacement.Count == 0)
                            continue;

                        instructions.RemoveAt(i);
                        for (var j = 0; j < replacement.Count; j++)
                            instructions.Insert(i + j, replacement[j]);
                        i += replacement.Count - 1;
                    }

                    replaced++;
                }
            }

            if (replaced > 0)
                ctx.Options.Logger.Info($"Post-deobf inlined {replaced} trivial wrapper call(s).");
        }

        private static void InlineResolvedDelegateCalls(
            DevirtualizationCtx ctx,
            ModuleDefinition module,
            CleanOptions options)
        {
            var targets = BuildResolvedDelegateTargets(module);
            if (targets.Count == 0)
            {
                ctx.Options.Logger.Info("Post-deobf delegate resolver found no static delegate map.");
                return;
            }

            var replaced = 0;
            var methodAllow = BuildMethodAllowList(ctx, module, options);
            foreach (var method in module.GetAllTypes().SelectMany(t => t.Methods))
            {
                if (!methodAllow(method))
                    continue;
                if (!method.HasMethodBody || method.CilMethodBody == null)
                    continue;

                var body = method.CilMethodBody;
                var instructions = body.Instructions;
                var targeted = BuildTargetedInstructionSet(body);
                for (var i = 0; i < instructions.Count; i++)
                {
                    var call = instructions[i];
                    if (call.OpCode != CilOpCodes.Callvirt)
                        continue;
                    if (!(call.Operand is IMethodDescriptor invoke) || !IsDelegateInvokeMethod(invoke))
                        continue;

                    var invokeSignature = invoke.Signature ?? invoke.Resolve()?.Signature;
                    if (invokeSignature == null)
                        continue;

                    var delegateLoadIndex = i - invokeSignature.ParameterTypes.Count - 1;
                    if (delegateLoadIndex < 0 || delegateLoadIndex >= instructions.Count)
                        continue;

                    if (!TryResolveDelegateFieldForInvoke(
                            body,
                            delegateLoadIndex,
                            targeted,
                            out var field,
                            out var removableProducerIndices))
                    {
                        continue;
                    }

                    if (!targets.TryGetValue(field, out var target))
                        continue;
                    if (!IsCompatibleResolvedDelegateTarget(invoke, target))
                        continue;

                    MakeNop(instructions[delegateLoadIndex]);
                    foreach (var producerIndex in removableProducerIndices)
                    {
                        if (producerIndex >= 0 && producerIndex < instructions.Count)
                            MakeNop(instructions[producerIndex]);
                    }

                    var targetSignature = target.Target.Signature ?? target.Target.Resolve()?.Signature;
                    var useCallVirt = targetSignature?.HasThis == true && target.UseCallVirt;
                    call.OpCode = useCallVirt ? CilOpCodes.Callvirt : CilOpCodes.Call;
                    call.Operand = target.Target;

                    if (TryGetReceiverCastType(target.Target, out var castType))
                    {
                        var receiverLoadIndex = delegateLoadIndex + 1;
                        if (receiverLoadIndex < i &&
                            IsSimpleStackProducer(instructions[receiverLoadIndex]) &&
                            !IsSameCast(instructions, receiverLoadIndex + 1, castType))
                        {
                            instructions.Insert(
                                receiverLoadIndex + 1,
                                new CilInstruction(CilOpCodes.Castclass, castType));
                            i++;
                        }
                    }

                    replaced++;
                }
            }

            if (replaced > 0)
                ctx.Options.Logger.Info($"Post-deobf resolved {replaced} delegate invoke call(s) from {targets.Count} mapped field(s).");
            else
                ctx.Options.Logger.Info($"Post-deobf decoded {targets.Count} delegate field target(s), but no compatible invoke sites were rewritten.");
        }

        private static Dictionary<FieldDefinition, ResolvedDelegateTarget> BuildResolvedDelegateTargets(ModuleDefinition module)
        {
            var result = new Dictionary<FieldDefinition, ResolvedDelegateTarget>();
            if (module == null)
                return result;

            var resolverMethods = FindReactorDelegateResolverMethods(module).ToList();
            foreach (var resolver in resolverMethods)
            {
                if (!TryGetDelegateMapResourceName(resolver, out var resourceName))
                    continue;

                var resource = module.Resources.FirstOrDefault(r =>
                    string.Equals(r.Name, resourceName, StringComparison.Ordinal));
                if (resource == null)
                    continue;

                byte[] data;
                try
                {
                    data = resource.GetData();
                }
                catch
                {
                    continue;
                }

                if (!TryDecodeReactorDelegateMap(data, out var rawMap))
                    continue;

                foreach (var entry in rawMap)
                {
                    if (!(TryLookupMember(module, entry.Key) is IFieldDescriptor fieldDescriptor))
                        continue;
                    var field = fieldDescriptor.Resolve() as FieldDefinition;
                    if (field == null || !IsStaticDelegateField(field))
                        continue;

                    var encodedTarget = unchecked((uint)entry.Value);
                    var targetToken = unchecked((int)(encodedTarget & 0x3FFFFFFFu));
                    if (!(TryLookupMember(module, targetToken) is IMethodDescriptor targetMethod))
                        continue;
                    if (!IsCompatibleDelegateFieldTarget(field, targetMethod))
                        continue;

                    result[field] = new ResolvedDelegateTarget
                    {
                        Field = field,
                        Target = targetMethod,
                        UseCallVirt = (encodedTarget & 0x40000000u) != 0
                    };
                }
            }

            return result;
        }

        private static IEnumerable<MethodDefinition> FindReactorDelegateResolverMethods(ModuleDefinition module)
        {
            var seen = new HashSet<MethodDefinition>();
            foreach (var type in module.GetAllTypes())
            {
                if (!IsDelegateType(type))
                    continue;

                var cctor = type.Methods.FirstOrDefault(m =>
                    m.IsStatic && m.IsConstructor && m.CilMethodBody != null);
                if (cctor == null)
                    continue;

                foreach (var instruction in cctor.CilMethodBody.Instructions)
                {
                    if (instruction.OpCode != CilOpCodes.Call && instruction.OpCode != CilOpCodes.Callvirt)
                        continue;
                    if (!(instruction.Operand is IMethodDescriptor descriptor))
                        continue;

                    var resolver = descriptor.Resolve() as MethodDefinition;
                    if (resolver == null || !seen.Add(resolver))
                        continue;
                    if (!LooksLikeReactorDelegateResolver(resolver))
                        continue;

                    yield return resolver;
                }
            }
        }

        private static bool LooksLikeReactorDelegateResolver(MethodDefinition method)
        {
            if (method == null || method.Signature == null || method.CilMethodBody == null)
                return false;
            if (method.Signature.ParameterTypes.Count != 1 ||
                method.Signature.ParameterTypes[0].FullName != "System.RuntimeTypeHandle")
            {
                return false;
            }

            var hasResourceStream = false;
            var hasResolveMethod = false;
            var hasMetadataToken = false;
            var hasSetValue = false;
            var hasCreateDelegate = false;

            foreach (var instruction in method.CilMethodBody.Instructions)
            {
                if (!(instruction.Operand is IMethodDescriptor descriptor))
                    continue;

                var fullName = descriptor.FullName ?? string.Empty;
                if (fullName.IndexOf("GetManifestResourceStream", StringComparison.OrdinalIgnoreCase) >= 0)
                    hasResourceStream = true;
                else if (fullName.IndexOf("ResolveMethod", StringComparison.OrdinalIgnoreCase) >= 0)
                    hasResolveMethod = true;
                else if (fullName.IndexOf("get_MetadataToken", StringComparison.OrdinalIgnoreCase) >= 0)
                    hasMetadataToken = true;
                else if (fullName.IndexOf("FieldInfo::SetValue", StringComparison.OrdinalIgnoreCase) >= 0)
                    hasSetValue = true;
                else if (fullName.IndexOf("CreateDelegate", StringComparison.OrdinalIgnoreCase) >= 0)
                    hasCreateDelegate = true;
            }

            return hasResourceStream && hasResolveMethod && hasMetadataToken && hasSetValue && hasCreateDelegate;
        }

        private static bool TryGetDelegateMapResourceName(MethodDefinition resolver, out string resourceName)
        {
            resourceName = null;
            var instructions = resolver?.CilMethodBody?.Instructions;
            if (instructions == null)
                return false;

            for (var i = 0; i < instructions.Count; i++)
            {
                var instruction = instructions[i];
                if (instruction.OpCode != CilOpCodes.Callvirt && instruction.OpCode != CilOpCodes.Call)
                    continue;
                if (!(instruction.Operand is IMethodDescriptor descriptor))
                    continue;

                var fullName = descriptor.FullName ?? string.Empty;
                if (fullName.IndexOf("GetManifestResourceStream", StringComparison.OrdinalIgnoreCase) < 0)
                    continue;

                for (var j = i - 1; j >= 0 && j >= i - 8; j--)
                {
                    if (instructions[j].OpCode == CilOpCodes.Ldstr &&
                        instructions[j].Operand is string candidate &&
                        !string.IsNullOrEmpty(candidate))
                    {
                        resourceName = candidate;
                        return true;
                    }
                }
            }

            return false;
        }

        private static bool TryDecodeReactorDelegateMap(byte[] data, out Dictionary<int, int> map)
        {
            map = new Dictionary<int, int>();
            if (data == null || data.Length < 8)
                return false;

            var decoded = DecodeReactorDelegateMapBytes(data);
            if (decoded == null || decoded.Length < 8)
                return false;

            var plausible = 0;
            for (var offset = 0; offset + 7 < decoded.Length; offset += 8)
            {
                var fieldToken = BitConverter.ToInt32(decoded, offset);
                var rawTarget = BitConverter.ToInt32(decoded, offset + 4);
                var targetToken = unchecked((int)(((uint)rawTarget) & 0x3FFFFFFFu));
                if ((fieldToken & unchecked((int)0xFF000000u)) != 0x04000000)
                    continue;
                if (!IsMethodLikeMetadataToken(targetToken))
                    continue;

                map[fieldToken] = rawTarget;
                plausible++;
            }

            return plausible > 0;
        }

        private static byte[] DecodeReactorDelegateMapBytes(byte[] data)
        {
            var decoded = new byte[data.Length];
            var remainder = data.Length % 4;
            var blockCount = data.Length / 4;
            if (remainder > 0)
                blockCount++;

            var key = 0u;
            for (var block = 0; block < blockCount; block++)
            {
                var offset = block * 4;
                var isPartial = remainder > 0 && block == blockCount - 1;
                uint encrypted;
                if (isPartial)
                {
                    encrypted = 0;
                    for (var i = 0; i < remainder; i++)
                    {
                        if (i > 0)
                            encrypted <<= 8;
                        encrypted |= data[data.Length - 1 - i];
                    }
                }
                else
                {
                    encrypted =
                        ((uint)data[offset + 3] << 24) |
                        ((uint)data[offset + 2] << 16) |
                        ((uint)data[offset + 1] << 8) |
                        data[offset];
                }

                key = unchecked(key + NextReactorDelegateMapKey(key));
                var plain = unchecked(key ^ encrypted);

                if (isPartial)
                {
                    var mask = 255u;
                    var shift = 0;
                    for (var i = 0; i < remainder; i++)
                    {
                        decoded[offset + i] = (byte)((plain & mask) >> (shift & 31));
                        mask <<= 8;
                        shift += 8;
                    }
                }
                else
                {
                    decoded[offset] = (byte)(plain & 0xFF);
                    decoded[offset + 1] = (byte)((plain >> 8) & 0xFF);
                    decoded[offset + 2] = (byte)((plain >> 16) & 0xFF);
                    decoded[offset + 3] = (byte)((plain >> 24) & 0xFF);
                }
            }

            return decoded;
        }

        private static uint NextReactorDelegateMapKey(uint seed)
        {
            unchecked
            {
                var a = 1618788125u;
                var b = 1412620532u;
                var c = 925178030u;
                var x = seed;
                var d = 1819975771u;

                var mixedNibble =
                    (((x & 252645135u) >> 4) | ((x & 4042322160u) << 4)) ^ b;
                x = (x << 15) | (x >> 17);
                c = 455086988u * (c & 7u) - (c >> 3);
                x = 278739720u * (x & 7u) + (x >> 3);
                b = 28404u * b + a;

                var modulus = (ulong)(x * x);
                if (modulus == 0)
                    modulus = ulong.MaxValue;
                b = (uint)((ulong)(b * b) % modulus);

                c ^= x;

                modulus = (ulong)(892863255u * 872579814u);
                if (modulus == 0)
                    modulus = ulong.MaxValue;
                d = (uint)((ulong)(d * d) % modulus);

                x ^= x << 23;
                x += b;
                x ^= x << 8;
                x += c;
                x ^= x >> 9;
                x += d;
                x = (((x << 21) + a) ^ c) + x;

                return x + (mixedNibble & 0u);
            }
        }

        private static bool TryResolveDelegateFieldForInvoke(
            CilMethodBody body,
            int delegateLoadIndex,
            ISet<CilInstruction> targeted,
            out FieldDefinition field,
            out IReadOnlyList<int> removableProducerIndices)
        {
            field = null;
            removableProducerIndices = Array.Empty<int>();
            var instructions = body?.Instructions;
            if (instructions == null ||
                delegateLoadIndex < 0 ||
                delegateLoadIndex >= instructions.Count ||
                targeted.Contains(instructions[delegateLoadIndex]))
            {
                return false;
            }

            if (TryGetFieldFromLdsfld(instructions[delegateLoadIndex], out field))
                return true;

            if (!TryGetLdlocVariable(body, instructions[delegateLoadIndex], out var local))
                return false;

            var storeIndex = FindNearestStoreToLocal(body, local, delegateLoadIndex - 1);
            if (storeIndex <= 0)
                return false;
            if (!TryGetFieldFromLdsfld(instructions[storeIndex - 1], out field))
                return false;

            if (!targeted.Contains(instructions[storeIndex]) &&
                !targeted.Contains(instructions[storeIndex - 1]) &&
                CountLdlocUses(body, local) == 1)
            {
                removableProducerIndices = new[] { storeIndex - 1, storeIndex };
            }

            return true;
        }

        private static bool TryGetFieldFromLdsfld(CilInstruction instruction, out FieldDefinition field)
        {
            field = null;
            if (instruction == null || instruction.OpCode != CilOpCodes.Ldsfld)
                return false;
            if (!(instruction.Operand is IFieldDescriptor descriptor))
                return false;

            field = descriptor.Resolve() as FieldDefinition;
            return field != null && IsStaticDelegateField(field);
        }

        private static bool IsCompatibleResolvedDelegateTarget(
            IMethodDescriptor invoke,
            ResolvedDelegateTarget target)
        {
            if (invoke == null || target?.Target == null)
                return false;

            var invokeSignature = invoke.Signature ?? invoke.Resolve()?.Signature;
            var targetSignature = target.Target.Signature ?? target.Target.Resolve()?.Signature;
            if (invokeSignature == null || targetSignature == null)
                return false;

            var invokeReturn = invokeSignature.ReturnType?.FullName ?? string.Empty;
            var targetReturn = targetSignature.ReturnType?.FullName ?? string.Empty;
            if (!string.Equals(invokeReturn, targetReturn, StringComparison.Ordinal))
                return false;

            var targetStackArgs = targetSignature.ParameterTypes.Count + (targetSignature.HasThis ? 1 : 0);
            if (targetStackArgs != invokeSignature.ParameterTypes.Count)
                return false;

            if (targetSignature.HasThis && IsValueTypeDeclaringType(target.Target))
                return false;

            return true;
        }

        private static bool IsCompatibleDelegateFieldTarget(FieldDefinition field, IMethodDescriptor target)
        {
            if (field == null || target == null)
                return false;

            var invoke = field.DeclaringType?.Methods.FirstOrDefault(m =>
                string.Equals(m.Name, "Invoke", StringComparison.Ordinal));
            if (invoke == null)
                return false;

            return IsCompatibleResolvedDelegateTarget(
                invoke,
                new ResolvedDelegateTarget
                {
                    Field = field,
                    Target = target,
                    UseCallVirt = true
                });
        }

        private static bool IsDelegateInvokeMethod(IMethodDescriptor method)
        {
            if (method == null || !string.Equals(method.Name, "Invoke", StringComparison.Ordinal))
                return false;

            var declaringType = (method as IMethodDefOrRef)?.DeclaringType?.Resolve() ??
                                method.Resolve()?.DeclaringType;
            return IsDelegateType(declaringType);
        }

        private static bool IsStaticDelegateField(FieldDefinition field)
        {
            if (field == null || !field.IsStatic || field.Signature?.FieldType == null)
                return false;
            if (!IsDelegateType(field.DeclaringType))
                return false;

            var fieldTypeName = field.Signature.FieldType.FullName ?? string.Empty;
            var declaringName = field.DeclaringType?.FullName ?? string.Empty;
            return string.Equals(fieldTypeName, declaringName, StringComparison.Ordinal);
        }

        private static bool IsDelegateType(TypeDefinition type)
        {
            if (type == null)
                return false;

            var baseName = type.BaseType?.FullName ?? string.Empty;
            return string.Equals(baseName, "System.MulticastDelegate", StringComparison.Ordinal);
        }

        private static bool IsMethodLikeMetadataToken(int token)
        {
            var table = token & unchecked((int)0xFF000000u);
            return table == 0x06000000 ||
                   table == 0x0A000000 ||
                   table == 0x2B000000;
        }

        private static IMetadataMember TryLookupMember(ModuleDefinition module, int token)
        {
            try
            {
                return module?.LookupMember(token);
            }
            catch
            {
                return null;
            }
        }

        private static bool TryGetReceiverCastType(IMethodDescriptor target, out ITypeDefOrRef castType)
        {
            castType = null;
            var signature = target?.Signature ?? target?.Resolve()?.Signature;
            if (signature == null || !signature.HasThis)
                return false;

            var methodDefOrRef = target as IMethodDefOrRef;
            castType = methodDefOrRef?.DeclaringType ?? target.Resolve()?.DeclaringType;
            if (castType == null)
                return false;

            if (string.Equals(castType.FullName, "System.Object", StringComparison.Ordinal))
                return false;
            if (IsValueTypeDeclaringType(target))
                return false;

            return true;
        }

        private static bool IsValueTypeDeclaringType(IMethodDescriptor method)
        {
            var methodDefOrRef = method as IMethodDefOrRef;
            var declaringType = methodDefOrRef?.DeclaringType?.Resolve() ??
                                method?.Resolve()?.DeclaringType;
            return declaringType?.IsValueType == true;
        }

        private static bool IsSimpleStackProducer(CilInstruction instruction)
        {
            if (instruction == null)
                return false;

            var code = instruction.OpCode.Code;
            return code == CilCode.Ldarg ||
                   code == CilCode.Ldarg_0 ||
                   code == CilCode.Ldarg_1 ||
                   code == CilCode.Ldarg_2 ||
                   code == CilCode.Ldarg_3 ||
                   code == CilCode.Ldarg_S ||
                   code == CilCode.Ldloc ||
                   code == CilCode.Ldloc_0 ||
                   code == CilCode.Ldloc_1 ||
                   code == CilCode.Ldloc_2 ||
                   code == CilCode.Ldloc_3 ||
                   code == CilCode.Ldloc_S ||
                   code == CilCode.Ldfld ||
                   code == CilCode.Call ||
                   code == CilCode.Callvirt;
        }

        private static bool IsSameCast(
            IList<CilInstruction> instructions,
            int index,
            ITypeDefOrRef castType)
        {
            if (instructions == null || index < 0 || index >= instructions.Count)
                return false;
            var instruction = instructions[index];
            if (instruction.OpCode != CilOpCodes.Castclass)
                return false;

            var operandName = (instruction.Operand as ITypeDescriptor)?.FullName ?? instruction.Operand?.ToString();
            return string.Equals(operandName, castType.FullName, StringComparison.Ordinal);
        }

        private static void MakeNop(CilInstruction instruction)
        {
            if (instruction == null)
                return;

            instruction.OpCode = CilOpCodes.Nop;
            instruction.Operand = null;
        }

        private static HashSet<CilInstruction> BuildTargetedInstructionSet(CilMethodBody body)
        {
            var targeted = new HashSet<CilInstruction>(ReferenceEqualityComparer.Instance);
            if (body == null)
                return targeted;

            foreach (var instruction in body.Instructions)
            {
                if (TryGetBranchTarget(instruction.Operand, out var target))
                {
                    targeted.Add(target);
                }
                else if (TryGetSwitchTargets(instruction.Operand, out var targets))
                {
                    foreach (var t in targets)
                    {
                        if (t != null)
                            targeted.Add(t);
                    }
                }
            }

            foreach (var handler in body.ExceptionHandlers)
            {
                var tryStart = ResolveLabelInstruction(handler.TryStart);
                var handlerStart = ResolveLabelInstruction(handler.HandlerStart);
                var filterStart = ResolveLabelInstruction(handler.FilterStart);
                if (tryStart != null)
                    targeted.Add(tryStart);
                if (handlerStart != null)
                    targeted.Add(handlerStart);
                if (filterStart != null)
                    targeted.Add(filterStart);
            }

            return targeted;
        }

        private static bool TryGetLdlocVariable(
            CilMethodBody body,
            CilInstruction instruction,
            out CilLocalVariable local)
        {
            local = null;
            if (body == null || instruction == null)
                return false;

            if ((instruction.OpCode == CilOpCodes.Ldloc || instruction.OpCode == CilOpCodes.Ldloc_S) &&
                instruction.Operand is CilLocalVariable operandLocal)
            {
                local = operandLocal;
                return true;
            }

            var index = -1;
            if (instruction.OpCode == CilOpCodes.Ldloc_0)
                index = 0;
            else if (instruction.OpCode == CilOpCodes.Ldloc_1)
                index = 1;
            else if (instruction.OpCode == CilOpCodes.Ldloc_2)
                index = 2;
            else if (instruction.OpCode == CilOpCodes.Ldloc_3)
                index = 3;

            if (index < 0 || index >= body.LocalVariables.Count)
                return false;

            local = body.LocalVariables[index];
            return true;
        }

        private static bool TryGetStlocVariable(
            CilMethodBody body,
            CilInstruction instruction,
            out CilLocalVariable local)
        {
            local = null;
            if (body == null || instruction == null)
                return false;

            if ((instruction.OpCode == CilOpCodes.Stloc || instruction.OpCode == CilOpCodes.Stloc_S) &&
                instruction.Operand is CilLocalVariable operandLocal)
            {
                local = operandLocal;
                return true;
            }

            var index = -1;
            if (instruction.OpCode == CilOpCodes.Stloc_0)
                index = 0;
            else if (instruction.OpCode == CilOpCodes.Stloc_1)
                index = 1;
            else if (instruction.OpCode == CilOpCodes.Stloc_2)
                index = 2;
            else if (instruction.OpCode == CilOpCodes.Stloc_3)
                index = 3;

            if (index < 0 || index >= body.LocalVariables.Count)
                return false;

            local = body.LocalVariables[index];
            return true;
        }

        private static int FindNearestStoreToLocal(CilMethodBody body, CilLocalVariable local, int startIndex)
        {
            if (body == null || local == null)
                return -1;

            var instructions = body.Instructions;
            for (var i = Math.Min(startIndex, instructions.Count - 1); i >= 0; i--)
            {
                if (TryGetStlocVariable(body, instructions[i], out var current) &&
                    ReferenceEquals(current, local))
                {
                    return i;
                }
            }

            return -1;
        }

        private static int CountLdlocUses(CilMethodBody body, CilLocalVariable local)
        {
            if (body == null || local == null)
                return 0;

            var count = 0;
            foreach (var instruction in body.Instructions)
            {
                if (TryGetLdlocVariable(body, instruction, out var current) &&
                    ReferenceEquals(current, local))
                {
                    count++;
                }
            }

            return count;
        }

        private static bool TryGetStrictTrivialWrapper(
            MethodDefinition method,
            out TrivialWrapperInfo info)
        {
            info = null;
            if (method == null || !method.HasMethodBody || method.CilMethodBody == null)
                return false;
            if (method.IsConstructor || (method.IsStatic && method.Name == ".cctor"))
                return false;

            var instructions = method.CilMethodBody.Instructions;
            if (instructions.Count < 2 || instructions.Count > 8)
                return false;

            var expectedStackArgs = GetMethodStackArgumentCount(method);
            if (expectedStackArgs <= 0)
                return false;

            var wrapperArgumentTypes = BuildWrapperArgumentTypes(method);
            if (wrapperArgumentTypes.Count != expectedStackArgs)
                return false;

            var index = GetReachableWrapperStartIndex(method, instructions);
            var loadedArgumentIndices = new List<int>();
            for (; index < instructions.Count && IsLdargForMethod(method, instructions[index], out var argIndex); index++)
            {
                if (argIndex < 0 || argIndex >= expectedStackArgs)
                    return false;
                loadedArgumentIndices.Add(argIndex);
            }

            if (loadedArgumentIndices.Count == 0 || index >= instructions.Count)
                return false;

            var call = instructions[index];
            if (call.OpCode != CilOpCodes.Call && call.OpCode != CilOpCodes.Callvirt)
                return false;

            if (!(call.Operand is IMethodDescriptor target))
                return false;

            var targetDefinition = target.Resolve() as MethodDefinition;
            if (targetDefinition != null && ReferenceEquals(targetDefinition, method))
                return false;

            index++;
            if (index != instructions.Count - 1 || instructions[index].OpCode != CilOpCodes.Ret)
                return false;

            var useCallVirt = call.OpCode == CilOpCodes.Callvirt;
            if (!HasCompatibleWrapperSignature(method, target, useCallVirt, loadedArgumentIndices.Count))
                return false;

            info = new TrivialWrapperInfo
            {
                Target = target,
                UseCallVirt = useCallVirt,
                LoadedArgumentIndices = loadedArgumentIndices,
                WrapperArgumentTypes = wrapperArgumentTypes
            };
            return true;
        }

        private static bool HasCompatibleWrapperSignature(
            MethodDefinition wrapper,
            IMethodDescriptor target,
            bool targetCallVirt,
            int loadedArgumentCount)
        {
            var wrapperSignature = wrapper?.Signature;
            var targetSignature = target?.Signature ?? target?.Resolve()?.Signature;
            if (wrapperSignature == null || targetSignature == null)
                return false;

            if (loadedArgumentCount != GetCallStackArgumentCount(target, targetCallVirt))
                return false;

            var wrapperReturn = wrapperSignature.ReturnType?.FullName ?? string.Empty;
            var targetReturn = targetSignature.ReturnType?.FullName ?? string.Empty;
            return string.Equals(wrapperReturn, targetReturn, StringComparison.Ordinal);
        }

        private static bool CanReplaceWrapperCallDirectly(TrivialWrapperInfo wrapper)
        {
            if (wrapper?.LoadedArgumentIndices == null ||
                wrapper.WrapperArgumentTypes == null ||
                wrapper.LoadedArgumentIndices.Count != wrapper.WrapperArgumentTypes.Count)
            {
                return false;
            }

            for (var i = 0; i < wrapper.LoadedArgumentIndices.Count; i++)
            {
                if (wrapper.LoadedArgumentIndices[i] != i)
                    return false;
            }

            return true;
        }

        private static List<CilInstruction> BuildWrapperCallExpansion(
            CilMethodBody callerBody,
            TrivialWrapperInfo wrapper)
        {
            if (callerBody == null || wrapper?.WrapperArgumentTypes == null || wrapper.LoadedArgumentIndices == null)
                return null;

            callerBody.InitializeLocals = true;
            var locals = new List<CilLocalVariable>(wrapper.WrapperArgumentTypes.Count);
            foreach (var type in wrapper.WrapperArgumentTypes)
            {
                var local = new CilLocalVariable(type);
                callerBody.LocalVariables.Add(local);
                locals.Add(local);
            }

            var replacement = new List<CilInstruction>();
            for (var i = locals.Count - 1; i >= 0; i--)
                replacement.Add(new CilInstruction(CilOpCodes.Stloc, locals[i]));

            foreach (var argumentIndex in wrapper.LoadedArgumentIndices)
            {
                if (argumentIndex < 0 || argumentIndex >= locals.Count)
                    return null;
                replacement.Add(new CilInstruction(CilOpCodes.Ldloc, locals[argumentIndex]));
            }

            replacement.Add(new CilInstruction(
                wrapper.UseCallVirt ? CilOpCodes.Callvirt : CilOpCodes.Call,
                wrapper.Target));
            return replacement;
        }

        private static int GetReachableWrapperStartIndex(MethodDefinition method, IList<CilInstruction> instructions)
        {
            var index = 0;
            while (index < instructions.Count && instructions[index].OpCode == CilOpCodes.Nop)
                index++;

            if (index < instructions.Count &&
                (instructions[index].OpCode == CilOpCodes.Br || instructions[index].OpCode == CilOpCodes.Br_S) &&
                instructions[index].Operand is CilInstruction target)
            {
                var targetIndex = IndexOfInstruction(instructions, target);
                if (targetIndex > index)
                    return targetIndex;
            }

            if (index < instructions.Count &&
                (instructions[index].OpCode == CilOpCodes.Br || instructions[index].OpCode == CilOpCodes.Br_S))
            {
                for (var i = index + 1; i < instructions.Count; i++)
                {
                    if (IsLdargForMethod(method, instructions[i], out _))
                        return i;
                }
            }

            return index;
        }

        private static int IndexOfInstruction(IList<CilInstruction> instructions, CilInstruction target)
        {
            for (var i = 0; i < instructions.Count; i++)
            {
                if (ReferenceEquals(instructions[i], target))
                    return i;
            }

            return -1;
        }

        private static IReadOnlyList<TypeSignature> BuildWrapperArgumentTypes(MethodDefinition method)
        {
            var types = new List<TypeSignature>();
            if (method == null || method.Signature == null)
                return types;

            if (!method.IsStatic)
                types.Add(new TypeDefOrRefSignature(method.DeclaringType));

            foreach (var parameterType in method.Signature.ParameterTypes)
                types.Add(parameterType);

            return types;
        }

        private static int GetMethodStackArgumentCount(MethodDefinition method)
        {
            if (method?.Signature == null)
                return -1;

            var count = method.Signature.ParameterTypes.Count;
            if (!method.IsStatic)
                count++;
            return count;
        }

        private static int GetCallStackArgumentCount(IMethodDescriptor method, bool callVirt)
        {
            var signature = method?.Signature ?? method?.Resolve()?.Signature;
            if (signature == null)
                return -1;

            return signature.ParameterTypes.Count + ((signature.HasThis || callVirt) ? 1 : 0);
        }

        private static bool IsLdargForMethod(
            MethodDefinition method,
            CilInstruction instruction,
            out int index)
        {
            if (IsLdarg(instruction, out index) && index >= 0)
                return true;

            if (instruction.OpCode != CilOpCodes.Ldarg && instruction.OpCode != CilOpCodes.Ldarg_S)
                return false;

            if (!(instruction.Operand is ParameterDefinition parameter))
            {
                var parsedOperandIndex = TryParseParameterIndex(instruction.Operand?.ToString());
                if (parsedOperandIndex < 0)
                    return false;

                index = method.IsStatic ? parsedOperandIndex : parsedOperandIndex + 1;
                return true;
            }

            var parameterIndex = -1;
            for (var i = 0; i < method.ParameterDefinitions.Count; i++)
            {
                if (ReferenceEquals(method.ParameterDefinitions[i], parameter))
                {
                    parameterIndex = i;
                    break;
                }
            }

            if (parameterIndex < 0)
                parameterIndex = TryParseParameterIndex(parameter);

            if (parameterIndex < 0)
                return false;

            index = method.IsStatic ? parameterIndex : parameterIndex + 1;
            return true;
        }

        private static int TryParseParameterIndex(ParameterDefinition parameter)
        {
            return TryParseParameterIndex(parameter?.Name?.ToString());
        }

        private static int TryParseParameterIndex(string name)
        {
            if (string.IsNullOrWhiteSpace(name))
                return -1;

            var underscore = name.LastIndexOf('_');
            if (underscore >= 0 && underscore + 1 < name.Length)
                name = name.Substring(underscore + 1);

            return int.TryParse(name, out var parsed) ? parsed : -1;
        }

        private static bool IsTrivialWrapper(MethodDefinition method, out string targetName)
        {
            targetName = string.Empty;
            if (!method.HasMethodBody || method.CilMethodBody == null)
                return false;
            if (method.IsConstructor || (method.IsStatic && method.Name == ".cctor"))
                return false;

            var body = method.CilMethodBody;
            var instr = body.Instructions;
            if (instr.Count < 2 || instr.Count > 6)
                return false;

            // Pattern: ldarg* ... call/callvirt target ... ret
            int index = 0;
            var expectedArgs = method.Signature?.ParameterTypes.Count ?? 0;
            var seenArgs = 0;
            while (index < instr.Count && IsLdarg(instr[index], out _))
            {
                seenArgs++;
                index++;
            }

            if (seenArgs == 0 || index >= instr.Count)
                return false;

            var call = instr[index];
            if (call.OpCode != CilOpCodes.Call && call.OpCode != CilOpCodes.Callvirt)
                return false;
            var target = call.Operand as IMethodDescriptor;
            if (target == null)
                return false;

            index++;
            if (index >= instr.Count || instr[index].OpCode != CilOpCodes.Ret)
                return false;

            targetName = target.Name ?? "Target";
            return true;
        }

        private static bool IsLdarg(CilInstruction instr, out int index)
        {
            index = -1;
            if (instr.OpCode == CilOpCodes.Ldarg_0) { index = 0; return true; }
            if (instr.OpCode == CilOpCodes.Ldarg_1) { index = 1; return true; }
            if (instr.OpCode == CilOpCodes.Ldarg_2) { index = 2; return true; }
            if (instr.OpCode == CilOpCodes.Ldarg_3) { index = 3; return true; }
            if (instr.OpCode == CilOpCodes.Ldarg || instr.OpCode == CilOpCodes.Ldarg_S)
            {
                switch (instr.Operand)
                {
                    case int i:
                        index = i;
                        return true;
                    case byte b:
                        index = b;
                        return true;
                    case sbyte sb:
                        index = sb;
                        return true;
                    case ParameterDefinition _:
                        return true;
                }
            }
            return false;
        }

        private static void RenameObfuscatedMembers(DevirtualizationCtx ctx, ModuleDefinition module)
        {
            var typeIndex = 0;
            var methodIndex = 0;
            var fieldIndex = 0;
            var propIndex = 0;
            var renamed = 0;

            foreach (var type in module.GetAllTypes())
            {
                if (type.IsModuleType || type.Name == "<Module>" || type.Name == "<PrivateImplementationDetails>")
                    continue;

                if (IsObfuscatedName(type.Name))
                {
                    type.Name = MakeUniqueTypeName(module, $"Type_{++typeIndex}");
                    renamed++;
                }

                foreach (var field in type.Fields)
                {
                    if (IsObfuscatedName(field.Name))
                    {
                        field.Name = MakeUniqueFieldName(type, $"field_{++fieldIndex}");
                        renamed++;
                    }
                }

                foreach (var prop in type.Properties)
                {
                    if (IsObfuscatedName(prop.Name))
                    {
                        prop.Name = $"Prop_{++propIndex}";
                        renamed++;
                    }
                }

                foreach (var method in type.Methods)
                {
                    if (method.IsConstructor || (method.IsStatic && method.Name == ".cctor"))
                        continue;
                    if (IsObfuscatedName(method.Name))
                    {
                        method.Name = MakeUniqueMethodName(type, $"method_{++methodIndex}");
                        renamed++;
                    }
                }
            }

            if (renamed > 0)
                ctx.Options.Logger.Info($"Post-deobf renamed {renamed} obfuscated member(s).");
        }

        private static bool IsObfuscatedName(string name)
        {
            if (string.IsNullOrWhiteSpace(name))
                return false;
            // compiler-generated or well-known runtime names
            if (name.StartsWith("<", StringComparison.Ordinal))
                return false;
            if (name.StartsWith("get_", StringComparison.Ordinal) || name.StartsWith("set_", StringComparison.Ordinal) ||
                name.StartsWith("add_", StringComparison.Ordinal) || name.StartsWith("remove_", StringComparison.Ordinal))
                return false;

            // non-ASCII chars — NET Reactor uses Unicode garbage names
            foreach (var ch in name)
            {
                if (ch > 0x7F)
                    return true;
            }

            // names that are pure digits or start with a digit are invalid C# identifiers
            if (char.IsDigit(name[0]))
                return true;

            // names that are all underscores (not a real identifier)
            if (name.All(c => c == '_'))
                return true;

            // very short names (1-3 chars) — uncommon for types/methods
            if (name.Length <= 3)
                return true;

            // names whose characters are all lowercase + maybe digits with no vowel
            // e.g. "bndxp", "grtk2" — unpronounceable → likely obfuscated
            if (name.Length <= 8 && IsUnpronounceable(name))
                return true;

            // all-hex identifier of length >= 8 (looks like a hash/GUID fragment)
            if (name.Length >= 8 && name.All(c => (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')))
                return true;

            return false;
        }

        private static bool IsUnpronounceable(string name)
        {
            // All lowercase letters (no digits, no underscores, no uppercase)
            if (!name.All(c => c >= 'a' && c <= 'z'))
                return false;
            // Has no vowels at all — impossible to pronounce in any language
            const string vowels = "aeiou";
            return !name.Any(c => vowels.IndexOf(c) >= 0);
        }

        private static string MakeUniqueTypeName(ModuleDefinition module, string baseName)
        {
            var name = baseName;
            var suffix = 1;
            var existing = new HashSet<string>(module.GetAllTypes().Select(t => t.Name.ToString()), StringComparer.Ordinal);
            while (existing.Contains(name))
                name = $"{baseName}_{suffix++}";
            return name;
        }

        private static string MakeUniqueMethodName(TypeDefinition type, string baseName)
        {
            var name = baseName;
            var suffix = 1;
            var existing = new HashSet<string>(type.Methods.Select(m => m.Name.ToString()), StringComparer.Ordinal);
            while (existing.Contains(name))
                name = $"{baseName}_{suffix++}";
            return name;
        }

        private static string MakeUniqueFieldName(TypeDefinition type, string baseName)
        {
            var name = baseName;
            var suffix = 1;
            var existing = new HashSet<string>(type.Fields.Select(f => f.Name.ToString()), StringComparer.Ordinal);
            while (existing.Contains(name))
                name = $"{baseName}_{suffix++}";
            return name;
        }

        private static void InlineConstStringCalls(DevirtualizationCtx ctx, ModuleDefinition module)
        {
            var constMethods = new Dictionary<MethodDefinition, string>();
            foreach (var method in module.GetAllTypes().SelectMany(t => t.Methods))
            {
                if (!TryGetConstString(method, out var value))
                    continue;
                constMethods[method] = value;
            }

            if (constMethods.Count == 0)
                return;

            var replaced = 0;
            var options = BuildOptions();
            var methodAllow = BuildMethodAllowList(ctx, module, options);
            foreach (var method in module.GetAllTypes().SelectMany(t => t.Methods))
            {
                if (!method.HasMethodBody || method.CilMethodBody == null)
                    continue;
                if (!methodAllow(method))
                    continue;
                var instr = method.CilMethodBody.Instructions;
                for (int i = 0; i < instr.Count; i++)
                {
                    var ins = instr[i];
                    if (ins.OpCode != CilOpCodes.Call && ins.OpCode != CilOpCodes.Callvirt)
                        continue;
                    var callee = ins.Operand as IMethodDescriptor;
                    if (callee == null)
                        continue;
                    var def = callee.Resolve() as MethodDefinition;
                    if (def == null)
                        continue;
                    if (!constMethods.TryGetValue(def, out var value))
                        continue;

                    ins.OpCode = CilOpCodes.Ldstr;
                    ins.Operand = value;
                    replaced++;
                }
            }

            if (replaced > 0)
                ctx.Options.Logger.Info($"Post-deobf inlined {replaced} constant string call(s).");
        }

        private static bool TryGetConstString(MethodDefinition method, out string value)
        {
            value = string.Empty;
            if (!method.HasMethodBody || method.CilMethodBody == null)
                return false;
            if (method.Signature?.ReturnType?.FullName != "System.String")
                return false;
            if (method.Signature.ParameterTypes.Count != 0)
                return false;

            var instr = method.CilMethodBody.Instructions;
            if (instr.Count >= 2 && instr.Count <= 4)
            {
                // Simple: ldstr "x"; ret
                if (instr[0].OpCode == CilOpCodes.Ldstr && instr[^1].OpCode == CilOpCodes.Ret)
                {
                    var text = instr[0].Operand as string;
                    if (text == null)
                        return false;
                    value = text;
                    return true;
                }
            }

            return false;
        }

        private static Func<MethodDefinition, bool> BuildMethodAllowList(DevirtualizationCtx ctx, ModuleDefinition module, CleanOptions options)
        {
            var recompiled = new HashSet<MethodDefinition>();
            if (options.OnlyRecompiled && ctx?.VirtualizedMethods != null)
            {
                foreach (var vm in ctx.VirtualizedMethods)
                {
                    if (vm?.Parent != null && vm.RecompiledBody != null)
                        recompiled.Add(vm.Parent);
                }
            }

            return method =>
            {
                if (method == null)
                    return false;
                if (!IsInNamespace(method.DeclaringType, options.CleanNamespace))
                    return false;
                if (!options.OnlyRecompiled)
                    return true;
                return recompiled.Contains(method);
            };
        }

        private static Func<MethodDefinition, bool> BuildSafeCflowAllowList(
            DevirtualizationCtx ctx,
            ModuleDefinition module,
            CleanOptions options)
        {
            var strictAllow = BuildMethodAllowList(ctx, module, options);
            if (!options.SafeCflowIncludeNonRecompiled)
                return strictAllow;

            var entry = module?.ManagedEntryPoint as MethodDefinition;
            return method =>
            {
                if (method == null || !method.HasMethodBody || method.CilMethodBody == null)
                    return false;
                if (strictAllow(method))
                    return true;
                if (entry != null && ReferenceEquals(method, entry))
                    return true;
                if (!IsInNamespace(method.DeclaringType, options.CleanNamespace))
                    return false;
                return true;
            };
        }

        private static bool IsInNamespace(TypeDefinition type, string nsPrefix)
        {
            if (type == null)
                return false;
            if (string.IsNullOrWhiteSpace(nsPrefix))
                return true;
            var ns = type.Namespace?.ToString() ?? string.Empty;
            return ns.StartsWith(nsPrefix, StringComparison.Ordinal);
        }

        private static void SimplifyEntryPoint(DevirtualizationCtx ctx, ModuleDefinition module, CleanOptions options)
        {
            var entry = module.ManagedEntryPoint as MethodDefinition;
            if (entry == null)
                return;
            if (!entry.HasMethodBody || entry.CilMethodBody == null)
                return;

            var body = entry.CilMethodBody;
            var instr = body.Instructions;
            if (instr.Count == 0)
                return;

            // Try to harvest existing references so we don't have to import.
            IMethodDescriptor enableStyles = null;
            IMethodDescriptor setCompatible = null;
            IMethodDescriptor runMethod = null;
            IMethodDescriptor formCtor = null;

            foreach (var ins in instr)
            {
                if (ins.OpCode == CilOpCodes.Call || ins.OpCode == CilOpCodes.Callvirt)
                {
                    var md = ins.Operand as IMethodDescriptor;
                    if (md == null)
                        continue;

                    var resolved = md.Resolve() as MethodDefinition;
                    if (resolved != null && TryResolveTrivialWrapper(resolved, out var unwrapped))
                        md = unwrapped;

                    var full = md.FullName ?? string.Empty;
                    if (full.Contains("System.Windows.Forms.Application::EnableVisualStyles"))
                        enableStyles = md;
                    else if (full.Contains("System.Windows.Forms.Application::SetCompatibleTextRenderingDefault"))
                        setCompatible = md;
                    else if (full.Contains("System.Windows.Forms.Application::Run"))
                        runMethod = md;
                }
                else if (ins.OpCode == CilOpCodes.Newobj)
                {
                    var ctor = ins.Operand as IMethodDescriptor;
                    if (ctor == null)
                        continue;
                    var decl = ctor.DeclaringType?.Resolve();
                    if (decl != null && decl.BaseType != null && decl.BaseType.FullName == "System.Windows.Forms.Form")
                        formCtor = ctor;
                }
            }

            if (enableStyles == null)
                enableStyles = FindMethodReferenceInModule(module, "System.Windows.Forms.Application::EnableVisualStyles");
            if (setCompatible == null)
                setCompatible = FindMethodReferenceInModule(module, "System.Windows.Forms.Application::SetCompatibleTextRenderingDefault");
            if (runMethod == null)
                runMethod = FindMethodReferenceInModule(module, "System.Windows.Forms.Application::Run");
            if (formCtor == null)
                formCtor = FindFirstFormCtor(module);

            if (runMethod != null && formCtor != null)
            {
                var newBody = new CilMethodBody(entry);
                var newInstr = newBody.Instructions;

                if (enableStyles != null)
                    newInstr.Add(new CilInstruction(CilOpCodes.Call, enableStyles));

                if (setCompatible != null)
                {
                    newInstr.Add(new CilInstruction(CilOpCodes.Ldc_I4_0));
                    newInstr.Add(new CilInstruction(CilOpCodes.Call, setCompatible));
                }

                newInstr.Add(new CilInstruction(CilOpCodes.Newobj, formCtor));
                newInstr.Add(new CilInstruction(CilOpCodes.Call, runMethod));
                newInstr.Add(new CilInstruction(CilOpCodes.Ret));

                entry.CilMethodBody = newBody;
                ctx.Options.Logger.Info("Post-deobf simplified entry point.");
                return;
            }

            if (TryBuildWrapperEntryPoint(module, entry, out var wrapperBody))
            {
                entry.CilMethodBody = wrapperBody;
                ctx.Options.Logger.Info("Post-deobf simplified entry point (wrapper cleanup).");
            }
        }

        private static bool TryResolveTrivialWrapper(MethodDefinition method, out IMethodDescriptor target)
        {
            target = null;
            if (method == null)
                return false;
            if (!method.HasMethodBody || method.CilMethodBody == null)
                return false;
            if (method.IsConstructor || (method.IsStatic && method.Name == ".cctor"))
                return false;

            var instr = method.CilMethodBody.Instructions;
            if (instr.Count < 2 || instr.Count > 6)
                return false;

            int index = 0;
            var seenArgs = 0;
            while (index < instr.Count && IsLdarg(instr[index], out _))
            {
                seenArgs++;
                index++;
            }

            if (seenArgs == 0 || index >= instr.Count)
                return false;

            var call = instr[index];
            if (call.OpCode != CilOpCodes.Call && call.OpCode != CilOpCodes.Callvirt)
                return false;
            var md = call.Operand as IMethodDescriptor;
            if (md == null)
                return false;

            index++;
            if (index >= instr.Count || instr[index].OpCode != CilOpCodes.Ret)
                return false;

            target = md;
            return true;
        }

        private static IMethodDescriptor FindMethodReferenceInModule(ModuleDefinition module, string contains)
        {
            foreach (var type in module.GetAllTypes())
            {
                foreach (var method in type.Methods)
                {
                    if (!method.HasMethodBody || method.CilMethodBody == null)
                        continue;
                    foreach (var ins in method.CilMethodBody.Instructions)
                    {
                        if (ins.OpCode != CilOpCodes.Call &&
                            ins.OpCode != CilOpCodes.Callvirt &&
                            ins.OpCode != CilOpCodes.Newobj &&
                            ins.OpCode != CilOpCodes.Ldftn &&
                            ins.OpCode != CilOpCodes.Ldvirtftn)
                            continue;

                        var md = ins.Operand as IMethodDescriptor;
                        if (md == null)
                            continue;
                        var full = md.FullName ?? string.Empty;
                        if (full.Contains(contains))
                            return md;
                    }
                }
            }
            return null;
        }

        private static IMethodDescriptor FindFirstFormCtor(ModuleDefinition module)
        {
            foreach (var type in module.GetAllTypes())
            {
                if (type.BaseType == null || type.BaseType.FullName != "System.Windows.Forms.Form")
                    continue;
                foreach (var method in type.Methods)
                {
                    if (!method.IsConstructor || method.IsStatic)
                        continue;
                    if (method.Signature == null)
                        continue;
                    if (method.Signature.ParameterTypes.Count == 0)
                        return method;
                }
            }
            return null;
        }

        private static void SimplifyStaticConstructors(DevirtualizationCtx ctx, ModuleDefinition module, CleanOptions options)
        {
            var simplified = 0;
            foreach (var type in module.GetAllTypes())
            {
                if (!IsInNamespace(type, options.CleanNamespace))
                    continue;
                var cctor = type.Methods.FirstOrDefault(m => m.IsStatic && m.Name == ".cctor");
                if (cctor == null || !cctor.HasMethodBody || cctor.CilMethodBody == null)
                    continue;

                if (TrySimplifyCctor(module, cctor))
                    simplified++;
            }

            if (simplified > 0)
                ctx.Options.Logger.Info($"Post-deobf simplified {simplified} static constructor(s).");
        }

        private static bool TrySimplifyCctor(ModuleDefinition module, MethodDefinition cctor)
        {
            var body = cctor.CilMethodBody;
            var instr = body.Instructions;
            if (instr.Count == 0)
                return false;

            IMethodDescriptor initArray = null;
            IFieldDescriptor initWrapperField = null;
            IFieldDescriptor tokenField = null;
            FieldDefinition targetField = null;
            int arrayLen = -1;

            for (int i = 0; i < instr.Count; i++)
            {
                var ins = instr[i];
                if ((ins.OpCode == CilOpCodes.Call || ins.OpCode == CilOpCodes.Callvirt) &&
                    ins.Operand is IMethodDescriptor md)
                {
                    var full = md.FullName ?? string.Empty;
                    if (full.Contains("System.Runtime.CompilerServices.RuntimeHelpers::InitializeArray"))
                    {
                        initArray = md;
                        // look back for ldtoken and newarr length
                        for (int j = i - 1; j >= 0; j--)
                        {
                            var prev = instr[j];
                            if (tokenField == null && prev.OpCode == CilOpCodes.Ldtoken && prev.Operand is IFieldDescriptor fd)
                                tokenField = fd;
                            if (arrayLen < 0 && TryGetInt32Constant(prev, out var len))
                                arrayLen = len;
                            if (tokenField != null && arrayLen >= 0)
                                break;
                        }
                        // look forward for stsfld
                        for (int j = i + 1; j < instr.Count; j++)
                        {
                            var next = instr[j];
                            if (next.OpCode == CilOpCodes.Stsfld && next.Operand is FieldDefinition fld)
                            {
                                targetField = fld;
                                break;
                            }
                        }
                        break;
                    }

                    if (initArray == null && IsInitializeArrayWrapper(md))
                    {
                        initArray = md;
                        // try to locate token + wrapper field around the call
                        for (int j = i - 1; j >= 0; j--)
                        {
                            var prev = instr[j];
                            if (tokenField == null && prev.OpCode == CilOpCodes.Ldtoken && prev.Operand is IFieldDescriptor fd)
                                tokenField = fd;
                            if (initWrapperField == null && prev.OpCode == CilOpCodes.Ldsfld && prev.Operand is IFieldDescriptor wf)
                                initWrapperField = wf;
                            if (arrayLen < 0 && TryGetInt32Constant(prev, out var len))
                                arrayLen = len;
                            if (tokenField != null && arrayLen >= 0 && initWrapperField != null)
                                break;
                        }
                        for (int j = i + 1; j < instr.Count; j++)
                        {
                            var next = instr[j];
                            if (next.OpCode == CilOpCodes.Stsfld && next.Operand is FieldDefinition fld)
                            {
                                targetField = fld;
                                break;
                            }
                        }
                        break;
                    }
                }
            }

            if (arrayLen < 0 && tokenField != null)
                arrayLen = TryGetArrayLenFromToken(tokenField);

            if (initArray == null || tokenField == null || targetField == null || arrayLen < 0)
                return false;

            var corlib = module.CorLibTypeFactory;
            var arrayType = new SzArrayTypeSignature(corlib.Byte);
            var newBody = new CilMethodBody(cctor);
            newBody.InitializeLocals = true;
            var local = new CilLocalVariable(arrayType);
            newBody.LocalVariables.Add(local);

            var newInstr = newBody.Instructions;
            newInstr.Add(new CilInstruction(CilOpCodes.Ldc_I4, arrayLen));
            newInstr.Add(new CilInstruction(CilOpCodes.Newarr, corlib.Byte.Type));
            newInstr.Add(new CilInstruction(CilOpCodes.Stloc, local));
            newInstr.Add(new CilInstruction(CilOpCodes.Ldloc, local));
            newInstr.Add(new CilInstruction(CilOpCodes.Ldtoken, tokenField));
            if (RequiresWrapperField(initArray, initWrapperField))
                newInstr.Add(new CilInstruction(CilOpCodes.Ldsfld, initWrapperField));
            newInstr.Add(new CilInstruction(CilOpCodes.Call, initArray));
            newInstr.Add(new CilInstruction(CilOpCodes.Ldloc, local));
            newInstr.Add(new CilInstruction(CilOpCodes.Stsfld, targetField));
            newInstr.Add(new CilInstruction(CilOpCodes.Ret));

            cctor.CilMethodBody = newBody;
            return true;
        }

        private static bool TryGetInt32Constant(CilInstruction instruction, out int value)
        {
            value = 0;
            switch (instruction.OpCode.Code)
            {
                case CilCode.Ldc_I4_M1: value = -1; return true;
                case CilCode.Ldc_I4_0: value = 0; return true;
                case CilCode.Ldc_I4_1: value = 1; return true;
                case CilCode.Ldc_I4_2: value = 2; return true;
                case CilCode.Ldc_I4_3: value = 3; return true;
                case CilCode.Ldc_I4_4: value = 4; return true;
                case CilCode.Ldc_I4_5: value = 5; return true;
                case CilCode.Ldc_I4_6: value = 6; return true;
                case CilCode.Ldc_I4_7: value = 7; return true;
                case CilCode.Ldc_I4_8: value = 8; return true;
                case CilCode.Ldc_I4_S:
                    if (instruction.Operand is sbyte sb) { value = sb; return true; }
                    if (instruction.Operand is byte b) { value = b; return true; }
                    break;
                case CilCode.Ldc_I4:
                    if (instruction.Operand is int i) { value = i; return true; }
                    break;
            }
            return false;
        }

        private static bool IsInitializeArrayWrapper(IMethodDescriptor method)
        {
            if (method == null)
                return false;
            var sig = method.Signature;
            if (sig == null)
                return false;
            if (sig.ParameterTypes.Count < 2)
                return false;
            var second = sig.ParameterTypes[1]?.FullName ?? string.Empty;
            return second == "System.RuntimeFieldHandle";
        }

        private static bool RequiresWrapperField(IMethodDescriptor method, IFieldDescriptor wrapperField)
        {
            if (method == null)
                return false;
            var sig = method.Signature;
            if (sig == null)
                return false;
            if (sig.ParameterTypes.Count >= 3)
                return wrapperField != null;
            return false;
        }

        private static int TryGetArrayLenFromToken(IFieldDescriptor tokenField)
        {
            try
            {
                var decl = tokenField.DeclaringType?.Resolve();
                if (decl?.ClassLayout?.ClassSize > 0)
                    return (int) decl.ClassLayout.ClassSize;
            }
            catch
            {
                // ignore
            }
            return -1;
        }

        private static void FixDnSpyStackIssues(DevirtualizationCtx ctx, ModuleDefinition module, CleanOptions options)
        {
            // ApplyBasicDnSpyCleanup (unreachable-block NOP'ing, dup/pop and const-push/pop
            // stack-noise removal) is a sample-independent, idempotent structural cleanup - it
            // used to be gated behind finding one hand-picked method (by hardcoded token, or by
            // an equally hardcoded obfuscated name as fallback) from a single sample. Apply it
            // to every method with a body in the configured namespace instead, so it actually
            // helps on any sample rather than only the one it was hand-tuned against.
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

        private static int ApplyBasicDnSpyCleanup(CilMethodBody body)
        {
            if (body == null)
                return 0;
            var instr = body.Instructions;
            if (instr.Count == 0)
                return 0;

            var touched = 0;

            // Mark unreachable blocks as NOP to reduce stack inconsistencies in dnSpy.
            var reachable = ComputeReachableInstructions(body);
            for (int i = 0; i < instr.Count; i++)
            {
                var current = instr[i];
                if (reachable.Contains(current))
                    continue;
                if (current.OpCode != CilOpCodes.Nop)
                {
                    current.OpCode = CilOpCodes.Nop;
                    touched++;
                }
            }

            // Remove trivial stack noise: dup/pop and const+pop.
            for (int i = 0; i < instr.Count - 1; i++)
            {
                var a = instr[i];
                var b = instr[i + 1];
                if (a.OpCode == CilOpCodes.Dup && b.OpCode == CilOpCodes.Pop)
                {
                    if (a.OpCode != CilOpCodes.Nop)
                    {
                        a.OpCode = CilOpCodes.Nop;
                        touched++;
                    }
                    if (b.OpCode != CilOpCodes.Nop)
                    {
                        b.OpCode = CilOpCodes.Nop;
                        touched++;
                    }
                    i++;
                    continue;
                }

                if (IsConstPush(a) && b.OpCode == CilOpCodes.Pop)
                {
                    if (a.OpCode != CilOpCodes.Nop)
                    {
                        a.OpCode = CilOpCodes.Nop;
                        touched++;
                    }
                    if (b.OpCode != CilOpCodes.Nop)
                    {
                        b.OpCode = CilOpCodes.Nop;
                        touched++;
                    }
                    i++;
                }
            }

            return touched;
        }

        private static HashSet<CilInstruction> ComputeReachableInstructions(CilMethodBody body)
        {
            var reachable = new HashSet<CilInstruction>(ReferenceEqualityComparer.Instance);
            var instr = body.Instructions;
            if (instr.Count == 0)
                return reachable;

            var indexByInstruction = new Dictionary<CilInstruction, int>(
                instr.Count,
                ReferenceEqualityComparer.Instance);
            for (var i = 0; i < instr.Count; i++)
                indexByInstruction[instr[i]] = i;

            var work = new Stack<CilInstruction>();
            void Enqueue(CilInstruction i)
            {
                if (i == null)
                    return;
                if (reachable.Add(i))
                    work.Push(i);
            }

            Enqueue(instr[0]);

            foreach (var eh in body.ExceptionHandlers)
            {
                Enqueue(ResolveLabelInstruction(eh.TryStart));
                Enqueue(ResolveLabelInstruction(eh.TryEnd));
                Enqueue(ResolveLabelInstruction(eh.HandlerStart));
                Enqueue(ResolveLabelInstruction(eh.HandlerEnd));
                Enqueue(ResolveLabelInstruction(eh.FilterStart));
            }

            while (work.Count > 0)
            {
                var current = work.Pop();
                if (!indexByInstruction.TryGetValue(current, out var index))
                    continue;

                var next = index + 1 < instr.Count ? instr[index + 1] : null;
                var op = current.OpCode;

                // Branch targets.
                if (TryGetBranchTarget(current.Operand, out var target))
                    Enqueue(target);
                else if (TryGetSwitchTargets(current.Operand, out var targets))
                {
                    foreach (var t in targets)
                        Enqueue(t);
                }

                if (IsTerminal(op))
                    continue;

                if (IsUnconditionalBranch(op))
                    continue;

                // Fallthrough
                Enqueue(next);
            }

            return reachable;
        }

        private static bool IsTerminal(CilOpCode op)
        {
            var code = op.Code;
            return code == CilCode.Ret ||
                   code == CilCode.Throw ||
                   code == CilCode.Rethrow ||
                   code == CilCode.Endfinally;
        }

        private static bool IsUnconditionalBranch(CilOpCode op)
        {
            var code = op.Code;
            return code == CilCode.Br ||
                   code == CilCode.Br_S ||
                   code == CilCode.Leave ||
                   code == CilCode.Leave_S;
        }

        private static bool IsConstPush(CilInstruction ins)
        {
            var code = ins.OpCode.Code;
            return code == CilCode.Ldc_I4 ||
                   code == CilCode.Ldc_I4_0 ||
                   code == CilCode.Ldc_I4_1 ||
                   code == CilCode.Ldc_I4_2 ||
                   code == CilCode.Ldc_I4_3 ||
                   code == CilCode.Ldc_I4_4 ||
                   code == CilCode.Ldc_I4_5 ||
                   code == CilCode.Ldc_I4_6 ||
                   code == CilCode.Ldc_I4_7 ||
                   code == CilCode.Ldc_I4_8 ||
                   code == CilCode.Ldc_I4_M1 ||
                   code == CilCode.Ldc_I4_S ||
                   code == CilCode.Ldc_I8 ||
                   code == CilCode.Ldc_R4 ||
                   code == CilCode.Ldc_R8 ||
                   code == CilCode.Ldnull ||
                   code == CilCode.Ldstr;
        }

        private static CilInstruction ResolveLabelInstruction(ICilLabel label)
        {
            return (label as CilInstructionLabel)?.Instruction;
        }

        private static void RewrapBigMethods(DevirtualizationCtx ctx, ModuleDefinition module, CleanOptions options)
        {
            const int targetToken = 0x0600005B;
            MethodDefinition target = null;
            ctx.Options.Logger.Info("Post-deobf rewrap: scanning for target method...");
            foreach (var type in module.GetAllTypes())
            {
                foreach (var method in type.Methods)
                {
                    if (!method.HasMethodBody || method.CilMethodBody == null)
                        continue;
                    try
                    {
                        if (method.MetadataToken.ToInt32() == targetToken)
                        {
                            target = method;
                            break;
                        }
                    }
                    catch
                    {
                        // ignore
                    }
                }
                if (target != null)
                    break;
            }

            if (target == null)
            {
                // Fallback by name + signature.
                foreach (var type in module.GetAllTypes())
                {
                    foreach (var method in type.Methods)
                    {
                        if (!method.HasMethodBody || method.CilMethodBody == null)
                            continue;
                        if (!string.Equals(method.Name, "\u009D\u0095", StringComparison.Ordinal))
                            continue;
                        if (method.Signature == null || method.Signature.ParameterTypes.Count != 2)
                            continue;
                        target = method;
                        break;
                    }
                    if (target != null)
                        break;
                }
            }

            if (target == null)
            {
                ctx.Options.Logger.Info("Post-deobf rewrap target not found.");
                return;
            }

            if (!IsInNamespace(target.DeclaringType, options.CleanNamespace))
            {
                ctx.Options.Logger.Info($"Post-deobf rewrap target found but namespace filtered: {target.DeclaringType?.Namespace ?? "<null>"}.");
                // Continue anyway to keep the wrapper clean in dnSpy.
            }

            var oldBody = target.CilMethodBody;
            if (oldBody == null || oldBody.Instructions.Count == 0)
            {
                ctx.Options.Logger.Info($"Post-deobf rewrap target found but has empty body: {target.FullName}.");
                return;
            }

            var baseName = target.Name?.ToString() ?? "method";
            var helperName = MakeUniqueMethodName(target.DeclaringType, baseName + "_impl");
            var helper = new MethodDefinition(helperName, target.Attributes, target.Signature);
            helper.ImplAttributes = target.ImplAttributes;
            foreach (var attr in target.CustomAttributes)
                helper.CustomAttributes.Add(attr);

            target.DeclaringType.Methods.Add(helper);

            // Move body to helper.
            helper.CilMethodBody = oldBody;
            var vmMethod = ctx?.VirtualizedMethods?.FirstOrDefault(q => ReferenceEquals(q?.Parent, target));

            // Relax stack-validation flags on the big body so AsmResolver can write it
            // even when the recompiled CIL has a stack imbalance (common for large VM methods
            // with complex exception handlers). TryRelaxStackValidationOnWriteFailure only
            // covers the original methodsToPatch list; the helper is added after that stage.
            if (oldBody != null)
            {
                oldBody.ComputeMaxStackOnBuild = false;
                oldBody.VerifyLabelsOnBuild = false;
                oldBody.BuildFlags = oldBody.BuildFlags &
                    ~(CilMethodBodyBuildFlags.ComputeMaxStack |
                      CilMethodBodyBuildFlags.VerifyLabels |
                      CilMethodBodyBuildFlags.FullValidation);
                if (oldBody.MaxStack < 64)
                    oldBody.MaxStack = 64;

                if (string.Equals(Environment.GetEnvironmentVariable("KRYPTON_VERIFIABLE_IL_MODE"), "1", StringComparison.Ordinal) &&
                    vmMethod != null)
                {
                    var helperArtifact = new RecompiledMethodArtifact(
                        oldBody,
                        vmMethod.MethodBody.Instructions.ToList());
                    var helperRepair = VerifiableIlSanitizer.TryRepair(ctx, vmMethod, helperArtifact);
                    if (helperRepair.Improved && helperRepair.FinalArtifact?.Body != null)
                    {
                        helper.CilMethodBody = helperRepair.FinalArtifact.Body;
                        oldBody = helper.CilMethodBody;
                        ctx.Options.Logger.Info(
                            $"Post-deobf rewrap helper verifiable repair: cil {helperRepair.InitialCilIssues}->{helperRepair.FinalCilIssues}, dnlib {helperRepair.InitialDnlibIssues}->{helperRepair.FinalDnlibIssues}, iter={helperRepair.IterationsApplied}, changes={helperRepair.ChangesApplied}.");
                    }
                }

                var applyLegacyHelperCleanup = string.Equals(
                    Environment.GetEnvironmentVariable("KRYPTON_CLEAN_REWRAP_HELPER_BASIC_CLEANUP"),
                    "1",
                    StringComparison.Ordinal);
                if (applyLegacyHelperCleanup)
                {
                    var helperTouched = ApplyBasicDnSpyCleanup(oldBody);
                    if (helperTouched > 0)
                        ctx.Options.Logger.Info($"Post-deobf rewrap helper dnSpy cleanup applied: {helperTouched} change(s).");
                }
            }

            // Create wrapper body for target.
            var wrapper = new CilMethodBody(target);
            var instr = wrapper.Instructions;
            for (int i = 0; i < target.Signature.ParameterTypes.Count; i++)
            {
                instr.Add(new CilInstruction(CilOpCodes.Ldarg, target.Parameters[i]));
            }
            instr.Add(new CilInstruction(CilOpCodes.Call, helper));
            instr.Add(new CilInstruction(CilOpCodes.Ret));
            target.CilMethodBody = wrapper;

            ctx.Options.Logger.Info($"Post-deobf rewrapped big method {target.FullName} -> {helper.Name}.");
        }

        private static bool TryBuildWrapperEntryPoint(ModuleDefinition module, MethodDefinition entry, out CilMethodBody body)
        {
            body = null;
            var formCtor = FindFirstFormCtor(module) as MethodDefinition;
            if (formCtor == null)
                return false;

            var formType = formCtor.DeclaringType;
            if (formType == null)
                return false;

            MethodDefinition enableWrapper = null;
            FieldDefinition enableField = null;
            MethodDefinition setCompatWrapper = null;
            FieldDefinition setCompatField = null;
            MethodDefinition runWrapper = null;
            FieldDefinition runField = null;

            foreach (var ins in entry.CilMethodBody.Instructions)
            {
                if (ins.OpCode != CilOpCodes.Call && ins.OpCode != CilOpCodes.Callvirt)
                    continue;
                var md = ins.Operand as IMethodDescriptor;
                if (md == null)
                    continue;
                var def = md.Resolve() as MethodDefinition;
                if (def == null)
                    continue;
                var sig = def.Signature;
                if (sig == null)
                    continue;

                if (sig.ParameterTypes.Count == 1)
                {
                    var field = FindStaticFieldOfType(def.DeclaringType, sig.ParameterTypes[0]);
                    if (field != null)
                    {
                        enableWrapper = def;
                        enableField = field;
                    }
                }
                else if (sig.ParameterTypes.Count == 2)
                {
                    var p0 = sig.ParameterTypes[0];
                    var p1 = sig.ParameterTypes[1];

                    if (p0.FullName == "System.Boolean")
                    {
                        var field = FindStaticFieldOfType(def.DeclaringType, p1);
                        if (field != null)
                        {
                            setCompatWrapper = def;
                            setCompatField = field;
                        }
                    }
                    else if (IsFormParam(p0, formType))
                    {
                        var field = FindStaticFieldOfType(def.DeclaringType, p1);
                        if (field != null)
                        {
                            runWrapper = def;
                            runField = field;
                        }
                    }
                }
            }

            if (runWrapper == null || runField == null)
                return false;

            body = new CilMethodBody(entry);
            var instr = body.Instructions;

            if (enableWrapper != null && enableField != null)
            {
                instr.Add(new CilInstruction(CilOpCodes.Ldsfld, enableField));
                instr.Add(new CilInstruction(CilOpCodes.Call, enableWrapper));
            }

            if (setCompatWrapper != null && setCompatField != null)
            {
                instr.Add(new CilInstruction(CilOpCodes.Ldc_I4_0));
                instr.Add(new CilInstruction(CilOpCodes.Ldsfld, setCompatField));
                instr.Add(new CilInstruction(CilOpCodes.Call, setCompatWrapper));
            }

            instr.Add(new CilInstruction(CilOpCodes.Newobj, formCtor));
            instr.Add(new CilInstruction(CilOpCodes.Ldsfld, runField));
            instr.Add(new CilInstruction(CilOpCodes.Call, runWrapper));
            instr.Add(new CilInstruction(CilOpCodes.Ret));

            return true;
        }

        private static bool IsFormParam(ITypeDescriptor type, TypeDefinition formType)
        {
            if (type == null || formType == null)
                return false;
            var name = type.FullName ?? string.Empty;
            if (name == formType.FullName)
                return true;
            return name == "System.Windows.Forms.Form";
        }

        private static FieldDefinition FindStaticFieldOfType(TypeDefinition type, ITypeDescriptor fieldType)
        {
            if (type == null || fieldType == null)
                return null;
            var wanted = fieldType.FullName ?? string.Empty;
            foreach (var field in type.Fields)
            {
                if (!field.IsStatic || field.Signature == null)
                    continue;
                var ft = field.Signature.FieldType?.FullName ?? string.Empty;
                if (ft == wanted)
                    return field;
            }
            return null;
        }
    }
}
