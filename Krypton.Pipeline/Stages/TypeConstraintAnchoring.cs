using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using AsmResolver.DotNet;
using AsmResolver.DotNet.Signatures.Types;
using Krypton.Core;
using Krypton.Core.Architecture;

namespace Krypton.Pipeline.Stages
{
    internal enum StackTypeKind
    {
        Unknown,
        Int32,
        Int64,
        Float,
        String,
        ObjectRef,
        ManagedPointer,
        Array
    }

    internal enum AnchorSource
    {
        CallArgument,
        FieldStore,
        ElementStore,
        ElementIndex,
        ArrayLength,
        KnownPlaintext,
        GlobalStack
    }

    internal sealed class AnchorRecord
    {
        public int VmByte { get; set; }
        public VMOpCode OpCode { get; set; }
        public AnchorSource Source { get; set; }
        public int SiteCount { get; set; }
        public int Round { get; set; }
        public IList<string> Evidence { get; } = new List<string>();
    }

    internal sealed class ConstraintSite
    {
        public StackTypeKind RequiredKind { get; set; }
        public AnchorSource Source { get; set; }
        public string Description { get; set; }
    }

    internal sealed class AnchorPropagationResult
    {
        public IDictionary<int, AnchorRecord> Anchors { get; } = new Dictionary<int, AnchorRecord>();
        public IDictionary<int, HashSet<VMOpCode>> Candidates { get; } = new Dictionary<int, HashSet<VMOpCode>>();
        public IDictionary<int, int> SiteCounts { get; } = new Dictionary<int, int>();
        public IList<string> Contradictions { get; } = new List<string>();
        public IList<string> Violations { get; } = new List<string>();
        public IList<int> RoundGains { get; } = new List<int>();
        public int ObservedBytes { get; set; }
        public IDictionary<int, List<string>> EvidenceByByte { get; } = new Dictionary<int, List<string>>();
        public ISet<int> FamilyResolved { get; } = new HashSet<int>();
    }

    // Metadata signatures and payload operand encoding are the only facts here that
    // do not depend on the opcode table. This engine grows a set of anchors from
    // them monotonically: an anchor is only ever added, never revised, and a byte
    // is anchored only when pruning leaves exactly one candidate -- type
    // compatibility on its own is pruning, not proof. Because anchored bytes have
    // a known stack effect, each round can walk further back from a call site and
    // reach argument positions the previous round could not, which is what turns a
    // handful of seeds into leverage.
    internal static class TypeConstraintAnchoring
    {
        private const int MinimumAnchorSites = 6;
        private const int MaxRounds = 12;

        private static readonly IReadOnlyCollection<VMOpCode> Universe =
            VMOpCodeCatalog.CandidateUniverse;

        public static AnchorPropagationResult Propagate(
            DevirtualizationCtx ctx,
            IDictionary<int, HashSet<VMOpCode>> seedCandidates = null,
            IDictionary<int, AnchorRecord> seedAnchors = null)
        {
            var result = new AnchorPropagationResult();
            if (ctx?.VirtualizedMethods == null || ctx.Module == null)
                return result;

            var observed = new HashSet<int>();
            foreach (var method in ctx.VirtualizedMethods)
            {
                var instructions = method?.MethodBody?.Instructions;
                if (instructions == null)
                    continue;
                foreach (var instruction in instructions)
                {
                    if (instruction != null)
                        observed.Add(instruction.VmByte);
                }
            }

            result.ObservedBytes = observed.Count;

            // Round zero starts from payload facts alone: operand class and the
            // actual operand values a byte carries.
            var candidates = new Dictionary<int, HashSet<VMOpCode>>();
            foreach (var vmByte in observed)
            {
                var set = new HashSet<VMOpCode>();
                foreach (var candidate in Universe)
                {
                    if (!IsOperandShapeCompatible(ctx, vmByte, candidate))
                        continue;
                    if (!IsOperandUsageCompatible(ctx, vmByte, candidate))
                        continue;
                    set.Add(candidate);
                }

                if (seedCandidates != null && seedCandidates.TryGetValue(vmByte, out var seeded))
                    set.IntersectWith(seeded);

                candidates[vmByte] = set;
            }

            ApplyMethodEntryRefutations(ctx, candidates);
            ApplyOperandDomainFamilyRefutations(ctx, candidates, result);
            ApplyTypedLocalRefutations(ctx, candidates, result);

            var anchors = new Dictionary<int, VMOpCode>();
            if (seedAnchors != null)
            {
                foreach (var pair in seedAnchors)
                {
                    anchors[pair.Key] = pair.Value.OpCode;
                    result.Anchors[pair.Key] = pair.Value;
                    if (!candidates.TryGetValue(pair.Key, out var set))
                        continue;
                    if (!set.Contains(pair.Value.OpCode))
                    {
                        result.Contradictions.Add(
                            $"seed anchor vm 0x{pair.Key:X2} -> {pair.Value.OpCode} was removed by metadata constraints");
                    }
                    set.Clear();
                    set.Add(pair.Value.OpCode);
                }
            }
            for (var round = 1; round <= MaxRounds; round++)
            {
                var sites = CollectConstraints(ctx, anchors);
                var gained = 0;

                foreach (var pair in sites)
                {
                    var vmByte = pair.Key;
                    var byteSites = pair.Value;
                    if (!candidates.TryGetValue(vmByte, out var set) || byteSites.Count == 0)
                        continue;

                    // Only a candidate that would push a value can be refuted by a
                    // type requirement. If the preceding instruction is a sink the
                    // consumed value was produced earlier, so the requirement says
                    // nothing about it -- assuming otherwise is what manufactured a
                    // false anchor for the store opcode.
                    var required = Math.Max(1, (int) Math.Ceiling(byteSites.Count * 0.9));
                    set.RemoveWhere(op => PushesValue(op) &&
                                          byteSites.Count(s => CanProduce(op, s.RequiredKind)) < required);

                    result.SiteCounts[vmByte] = byteSites.Count;

                    if (set.Count != 1 || byteSites.Count < MinimumAnchorSites)
                        continue;

                    var proven = set.First();
                    if (anchors.TryGetValue(vmByte, out var existing))
                    {
                        if (existing != proven)
                        {
                            result.Contradictions.Add(
                                $"vm 0x{vmByte:X2} is already anchored to {existing} but round {round} proves {proven}; " +
                                "the anchor was kept and the new rule must be treated as too permissive");
                        }

                        continue;
                    }

                    anchors[vmByte] = proven;
                    if (result.Anchors.ContainsKey(vmByte))
                        continue;
                    result.Anchors[vmByte] = new AnchorRecord
                    {
                        VmByte = vmByte,
                        OpCode = proven,
                        Source = byteSites[0].Source,
                        SiteCount = byteSites.Count,
                        Round = round
                    };
                    if (result.EvidenceByByte.TryGetValue(vmByte, out var priorEvidence))
                    {
                        foreach (var line in priorEvidence)
                            result.Anchors[vmByte].Evidence.Add(line);
                    }

                    result.Anchors[vmByte].Evidence.Add($"CallArgument {byteSites.Count} sites");
                    gained++;
                }

                result.RoundGains.Add(gained);
                if (gained == 0)
                    break;
            }

            foreach (var known in KnownPlaintextCryptoAnchoring.Solve(ctx, candidates))
            {
                if (anchors.TryGetValue(known.VmByte, out var existingKnown))
                {
                    if (existingKnown != known.OpCode)
                    {
                        result.Contradictions.Add(
                            $"known-plaintext proves vm 0x{known.VmByte:X2} -> {known.OpCode}, " +
                            $"but the seed anchor is {existingKnown}");
                    }
                    continue;
                }
                candidates[known.VmByte].Clear();
                candidates[known.VmByte].Add(known.OpCode);
                anchors[known.VmByte] = known.OpCode;
                result.Anchors[known.VmByte] = new AnchorRecord
                {
                    VmByte = known.VmByte,
                    OpCode = known.OpCode,
                    Source = AnchorSource.KnownPlaintext,
                    SiteCount = known.Sites,
                    Round = result.RoundGains.Count
                };
                result.Anchors[known.VmByte].Evidence.Add(known.Evidence);
            }

            foreach (var pair in candidates)
                result.Candidates[pair.Key] = pair.Value;

            foreach (var pair in result.Candidates.OrderBy(p => p.Key))
            {
                if (pair.Value.Count == 0 || !ctx.PatternMatcher.IsOpCodeValueKnown(pair.Key))
                    continue;
                var current = ctx.PatternMatcher.GetOpCodeValue(pair.Key);
                if (!pair.Value.Contains(current) && result.SiteCounts.TryGetValue(pair.Key, out var count))
                {
                    result.Violations.Add(
                        $"vm 0x{pair.Key:X2} is mapped to {current}, which {count} constraint site(s) rule out; " +
                        $"remaining: {string.Join(", ", pair.Value.OrderBy(q => q.ToString()))}");
                }
            }

            return result;
        }

        private static bool PushesValue(VMOpCode opcode)
        {
            if (VMOpCodeCatalog.TryGet(opcode, out var semantic) &&
                semantic.HasFixedStackEffect)
            {
                return semantic.Push > 0;
            }

            switch (opcode)
            {
                case VMOpCode.Nop:
                case VMOpCode.Pop:
                case VMOpCode.Stloc:
                case VMOpCode.Stfld:
                case VMOpCode.Stsfld:
                case VMOpCode.Stelem_Ref:
                case VMOpCode.Stelem_I1:
                case VMOpCode.Br:
                case VMOpCode.BrTrue:
                case VMOpCode.BrFalse:
                case VMOpCode.Leave:
                case VMOpCode.Ret:
                case VMOpCode.EndFinally:
                    return false;
                default:
                    return true;
            }
        }

        // The first instruction of a method runs on an empty stack, so whatever
        // byte sits there cannot consume anything.
        private static void ApplyMethodEntryRefutations(
            DevirtualizationCtx ctx,
            IDictionary<int, HashSet<VMOpCode>> candidates)
        {
            foreach (var method in ctx.VirtualizedMethods)
            {
                var instructions = method?.MethodBody?.Instructions;
                if (instructions == null || instructions.Count == 0 || instructions[0] == null)
                    continue;

                var entry = instructions[0];
                if (!candidates.TryGetValue(entry.VmByte, out var set))
                    continue;

                set.RemoveWhere(op =>
                    TryGetAnchoredEffect(ctx, op, entry.Operand, out var pop, out _) && pop > 0);
            }
        }

        // Retired: this assumed a local cannot be read before it is written, which
        // only holds without .locals init. VM method bodies zero-initialise their
        // locals, so reading an unwritten slot is legal and the rule refuted the
        // load opcode at perfectly valid sites.
        // ReSharper disable once UnusedMember.Local
        private static void ApplyDefiniteAssignmentRefutations(
            DevirtualizationCtx ctx,
            IDictionary<int, HashSet<VMOpCode>> candidates)
        {
            var firstTouchCounts = new Dictionary<int, int>();

            foreach (var method in ctx.VirtualizedMethods)
            {
                var instructions = method?.MethodBody?.Instructions;
                var localCount = method?.MethodBody?.Locals?.Count ?? 0;
                if (instructions == null || localCount == 0)
                    continue;

                var seenLocals = new HashSet<int>();
                foreach (var instruction in instructions)
                {
                    if (instruction == null || !(instruction.Operand is int slot))
                        continue;
                    if (slot < 0 || slot >= localCount)
                        continue;
                    if (!candidates.TryGetValue(instruction.VmByte, out var set))
                        continue;
                    if (!set.Contains(VMOpCode.Ldloc) && !set.Contains(VMOpCode.Stloc) && !set.Contains(VMOpCode.Ldloca))
                        continue;
                    if (!seenLocals.Add(slot))
                        continue;

                    firstTouchCounts.TryGetValue(instruction.VmByte, out var count);
                    firstTouchCounts[instruction.VmByte] = count + 1;
                }
            }

            foreach (var pair in firstTouchCounts)
            {
                if (pair.Value < 4 || !candidates.TryGetValue(pair.Key, out var set))
                    continue;

                set.Remove(VMOpCode.Ldloc);
                set.Remove(VMOpCode.Ldloca);
            }
        }

        private static void AddEvidence(AnchorPropagationResult result, int vmByte, string line)
        {
            if (!result.EvidenceByByte.TryGetValue(vmByte, out var list))
            {
                list = new List<string>();
                result.EvidenceByByte[vmByte] = list;
            }

            list.Add(line);
        }

        // Family-level inference. A byte whose operands are always valid local slots
        // while its methods are orders of magnitude larger is not addressing
        // instructions. That is a very strong statistical argument from payload
        // encoding rather than a proof, so it only ever removes a family and never
        // fixes an opcode on its own.
        private static void ApplyOperandDomainFamilyRefutations(
            DevirtualizationCtx ctx,
            IDictionary<int, HashSet<VMOpCode>> candidates,
            AnchorPropagationResult result)
        {
            var occurrences = new Dictionary<int, int>();
            var maxOperand = new Dictionary<int, int>();
            var localCompatible = new Dictionary<int, int>();
            var largestMethod = 0;

            foreach (var method in ctx.VirtualizedMethods)
            {
                var instructions = method?.MethodBody?.Instructions;
                var localCount = method?.MethodBody?.Locals?.Count ?? 0;
                if (instructions == null)
                    continue;
                largestMethod = Math.Max(largestMethod, instructions.Count);

                foreach (var instruction in instructions)
                {
                    if (instruction == null || !(instruction.Operand is int value))
                        continue;

                    occurrences.TryGetValue(instruction.VmByte, out var seen);
                    occurrences[instruction.VmByte] = seen + 1;

                    maxOperand.TryGetValue(instruction.VmByte, out var high);
                    maxOperand[instruction.VmByte] = Math.Max(high, value);

                    if (value >= 0 && value < localCount)
                    {
                        localCompatible.TryGetValue(instruction.VmByte, out var ok);
                        localCompatible[instruction.VmByte] = ok + 1;
                    }
                }
            }

            foreach (var pair in occurrences)
            {
                var vmByte = pair.Key;
                if (pair.Value < 20 || !candidates.TryGetValue(vmByte, out var set))
                    continue;
                localCompatible.TryGetValue(vmByte, out var compatible);
                if (compatible != pair.Value)
                    continue;
                maxOperand.TryGetValue(vmByte, out var high);
                if (largestMethod < 200 || high * 4 >= largestMethod)
                    continue;

                var removed = set.RemoveWhere(IsBranchFamily);
                if (removed > 0)
                {
                    result.FamilyResolved.Add(vmByte);
                    AddEvidence(result, vmByte,
                        $"OperandDomain {compatible}/{pair.Value} local-compatible, max operand {high} vs {largestMethod} instructions -> branch family removed");
                }
            }
        }

        private static bool IsBranchFamily(VMOpCode opcode)
        {
            return IsBranchLike(opcode) ||
                   opcode == VMOpCode.Br ||
                   opcode == VMOpCode.BrTrue ||
                   opcode == VMOpCode.BrFalse;
        }

        // The payload carries the declared type of every VM local, which makes both
        // directions checkable: a load must produce that type for whatever consumes
        // it, and a store must accept the type the preceding instruction produced.
        // The store direction is what finally refutes a sink, which consumer-side
        // reasoning alone can never do.
        private static void ApplyTypedLocalRefutations(
            DevirtualizationCtx ctx,
            IDictionary<int, HashSet<VMOpCode>> candidates,
            AnchorPropagationResult result)
        {
            var storeRefutations = new Dictionary<int, int>();
            var loadRefutations = new Dictionary<int, int>();
            var branchCapable = CouldBeBranchBytes(ctx, new Dictionary<int, VMOpCode>());

            foreach (var method in ctx.VirtualizedMethods)
            {
                var instructions = method?.MethodBody?.Instructions;
                var locals = method?.MethodBody?.Locals;
                if (instructions == null || locals == null || locals.Count == 0)
                    continue;

                var joinPoints = CollectBranchTargets(instructions, branchCapable);

                for (var i = 0; i < instructions.Count; i++)
                {
                    var instruction = instructions[i];
                    if (instruction == null || !(instruction.Operand is int slot))
                        continue;
                    if (slot < 0 || slot >= locals.Count)
                        continue;
                    if (!candidates.TryGetValue(instruction.VmByte, out var set))
                        continue;

                    var localKind = ClassifyDescriptor(locals[slot]);
                    if (localKind == StackTypeKind.Unknown)
                        continue;

                    if (i > 0 && !joinPoints.Contains(i))
                    {
                        var produced = ProducedKind(ctx, instructions[i - 1], result);
                        if (!IsAssignable(produced, localKind))
                        {
                            storeRefutations.TryGetValue(instruction.VmByte, out var c);
                            storeRefutations[instruction.VmByte] = c + 1;
                        }
                    }

                    if (i + 1 < instructions.Count && !joinPoints.Contains(i + 1))
                    {
                        var requiredKind = TopRequirement(ctx, instructions[i + 1]);
                        if (!IsAssignable(localKind, requiredKind))
                        {
                            loadRefutations.TryGetValue(instruction.VmByte, out var c);
                            loadRefutations[instruction.VmByte] = c + 1;
                        }
                    }
                }
            }

            // One odd site is noise; a hypothesis is only dropped when several
            // independent sites contradict it.
            const int minimumRefutingSites = 3;

            foreach (var pair in storeRefutations)
            {
                if (pair.Value < minimumRefutingSites || !candidates.TryGetValue(pair.Key, out var set))
                    continue;
                if (set.Remove(VMOpCode.Stloc))
                    AddEvidence(result, pair.Key, $"TypedLocalStore refuted Stloc at {pair.Value} site(s)");
            }

            foreach (var pair in loadRefutations)
            {
                if (pair.Value < minimumRefutingSites || !candidates.TryGetValue(pair.Key, out var set))
                    continue;
                var removed = set.Remove(VMOpCode.Ldloc);
                removed |= set.Remove(VMOpCode.Ldloca);
                if (removed)
                    AddEvidence(result, pair.Key, $"TypedLocalLoad refuted Ldloc at {pair.Value} site(s)");
            }
        }

        // Only an anchored producer reports a type; anything else stays Unknown so it
        // cannot refute.
        private static StackTypeKind ProducedKind(
            DevirtualizationCtx ctx,
            VMInstruction instruction,
            AnchorPropagationResult result)
        {
            if (instruction == null || !result.Anchors.TryGetValue(instruction.VmByte, out var record))
                return StackTypeKind.Unknown;

            var declared = DeclaredProduction(record.OpCode);
            if (declared != StackTypeKind.Unknown)
                return declared;

            switch (record.OpCode)
            {
                case VMOpCode.Newobj:
                    if (instruction.Operand is int token && Lookup(ctx, token) is IMethodDescriptor descriptor)
                        return ClassifyDescriptor(descriptor.DeclaringType);
                    return StackTypeKind.Unknown;
                default:
                    return StackTypeKind.Unknown;
            }
        }

        private static StackTypeKind TopRequirement(DevirtualizationCtx ctx, VMInstruction consumer)
        {
            if (consumer == null || !(consumer.Operand is int token))
                return StackTypeKind.Unknown;
            if (!(Lookup(ctx, token) is IMethodDescriptor descriptor) || descriptor.Signature == null)
                return StackTypeKind.Unknown;

            var signature = descriptor.Signature;
            if (signature.ParameterTypes.Count > 0)
                return Classify(signature.ParameterTypes[signature.ParameterTypes.Count - 1]);
            if (signature.HasThis && !IsValueTypeDeclaring(descriptor))
                return StackTypeKind.ObjectRef;
            return StackTypeKind.Unknown;
        }

        private static StackTypeKind ClassifyDescriptor(ITypeDescriptor descriptor)
        {
            if (descriptor == null)
                return StackTypeKind.Unknown;

            // Object is also the disassembler fallback for unresolvable local
            // tokens, so it must never be read as a fact.
            var name = descriptor.FullName;
            if (string.IsNullOrEmpty(name) || string.Equals(name, "System.Object", StringComparison.Ordinal))
                return StackTypeKind.Unknown;

            try
            {
                return Classify(descriptor.ToTypeSignature());
            }
            catch
            {
                return StackTypeKind.Unknown;
            }
        }

        // Walks backwards from a consumer whose operand requirements are known,
        // attributing one stack slot at a time. It only steps over instructions
        // whose stack effect is certain (already anchored), and stops at the first
        // unknown -- an incomplete but sound resolver beats reintroducing the same
        // circularity in a new shape.
        private static IDictionary<int, List<ConstraintSite>> CollectConstraints(
            DevirtualizationCtx ctx,
            IReadOnlyDictionary<int, VMOpCode> anchors)
        {
            var sites = new Dictionary<int, List<ConstraintSite>>();

            var branchCapable = CouldBeBranchBytes(ctx, anchors);
            foreach (var method in ctx.VirtualizedMethods)
            {
                var instructions = method?.MethodBody?.Instructions;
                if (instructions == null)
                    continue;

                var joinPoints = CollectBranchTargets(instructions, branchCapable);

                for (var i = 1; i < instructions.Count; i++)
                {
                    var consumer = instructions[i];
                    if (consumer == null || joinPoints.Contains(i))
                        continue;

                    var requirements = DescribeConsumer(ctx, anchors, consumer, out var source, out var label);
                    if (requirements == null || requirements.Count == 0)
                        continue;

                    AttributeBackwards(
                        ctx, anchors, instructions, joinPoints, i, requirements, source, label, sites);
                }
            }

            return sites;
        }

        private static void AttributeBackwards(
            DevirtualizationCtx ctx,
            IReadOnlyDictionary<int, VMOpCode> anchors,
            IList<VMInstruction> instructions,
            ISet<int> joinPoints,
            int consumerIndex,
            IReadOnlyList<StackTypeKind> requirements,
            AnchorSource source,
            string label,
            IDictionary<int, List<ConstraintSite>> sites)
        {
            var slot = requirements.Count - 1;
            var pending = 0;

            for (var i = consumerIndex - 1; i >= 0 && slot >= 0; i--)
            {
                if (joinPoints.Contains(i))
                    return;

                var instruction = instructions[i];
                if (instruction == null)
                    return;

                if (!anchors.TryGetValue(instruction.VmByte, out var anchored))
                {
                    // The first byte we cannot step over still tells us something:
                    // if nothing is outstanding, it produces the slot we are on.
                    if (pending == 0 && requirements[slot] != StackTypeKind.Unknown)
                        Record(sites, instruction.VmByte, requirements[slot], source, label);
                    return;
                }

                if (!TryGetAnchoredEffect(ctx, anchored, instruction.Operand, out var pop, out var push))
                    return;

                if (push == 1)
                {
                    if (pending > 0)
                    {
                        pending--;
                    }
                    else
                    {
                        slot--;
                    }

                    pending += pop;
                }
                else if (push == 0 && pop == 0)
                {
                    // A no-op does not disturb the attribution.
                }
                else
                {
                    return;
                }
            }
        }

        private static void Record(
            IDictionary<int, List<ConstraintSite>> sites,
            int vmByte,
            StackTypeKind kind,
            AnchorSource source,
            string label)
        {
            if (!sites.TryGetValue(vmByte, out var list))
            {
                list = new List<ConstraintSite>();
                sites[vmByte] = list;
            }

            list.Add(new ConstraintSite { RequiredKind = kind, Source = source, Description = label });
        }

        // Requirements are ordered deepest-first, matching stack order.
        private static IReadOnlyList<StackTypeKind> DescribeConsumer(
            DevirtualizationCtx ctx,
            IReadOnlyDictionary<int, VMOpCode> anchors,
            VMInstruction consumer,
            out AnchorSource source,
            out string label)
        {
            source = AnchorSource.CallArgument;
            label = null;

            // Seed source: a token that resolves to a method describes its own
            // argument types without needing any opcode to be known first.
            if (consumer.Operand is int token)
            {
                var member = Lookup(ctx, token);
                if (member is IMethodDescriptor descriptor && descriptor.Signature != null)
                {
                    var signature = descriptor.Signature;
                    var required = new List<StackTypeKind>();
                    if (signature.HasThis && !IsValueTypeDeclaring(descriptor))
                        required.Add(StackTypeKind.ObjectRef);
                    foreach (var parameter in signature.ParameterTypes)
                        required.Add(Classify(parameter));

                    if (required.Count == 0)
                        return null;

                    label = descriptor.FullName;
                    source = AnchorSource.CallArgument;
                    return required;
                }

                if (member is IFieldDescriptor field &&
                    anchors.TryGetValue(consumer.VmByte, out var fieldOp))
                {
                    var fieldKind = Classify(field.Signature?.FieldType);
                    if (fieldKind == StackTypeKind.Unknown)
                        return null;
                    label = field.FullName;
                    source = AnchorSource.FieldStore;
                    if (fieldOp == VMOpCode.Stsfld)
                        return new[] { fieldKind };
                    if (fieldOp == VMOpCode.Stfld)
                        return new[] { StackTypeKind.ObjectRef, fieldKind };
                    return null;
                }

                if (member is ITypeDefOrRef &&
                    anchors.TryGetValue(consumer.VmByte, out var typeOp) &&
                    typeOp == VMOpCode.Newarr)
                {
                    label = "array length";
                    source = AnchorSource.ArrayLength;
                    return new[] { StackTypeKind.Int32 };
                }

                return null;
            }

            // Growth sources: once a byte is anchored, its own operand-free
            // semantics constrain whatever feeds it.
            if (!anchors.TryGetValue(consumer.VmByte, out var opcode))
                return null;

            switch (opcode)
            {
                case VMOpCode.Stelem_I1:
                    label = "byte array element store";
                    source = AnchorSource.ElementStore;
                    return new[] { StackTypeKind.Array, StackTypeKind.Int32, StackTypeKind.Int32 };
                case VMOpCode.Stelem_Ref:
                    label = "reference array element store";
                    source = AnchorSource.ElementStore;
                    return new[] { StackTypeKind.Array, StackTypeKind.Int32, StackTypeKind.ObjectRef };
                case VMOpCode.Ldelem_U1:
                case VMOpCode.Ldelem_Ref:
                    label = "array element load";
                    source = AnchorSource.ElementIndex;
                    return new[] { StackTypeKind.Array, StackTypeKind.Int32 };
                case VMOpCode.Ldlen:
                    label = "array length load";
                    source = AnchorSource.ElementIndex;
                    return new[] { StackTypeKind.Array };
                default:
                    return null;
            }
        }

        private static bool IsValueTypeDeclaring(IMethodDescriptor descriptor)
        {
            try
            {
                var declaring = descriptor.DeclaringType?.Resolve();
                return declaring == null || declaring.IsValueType;
            }
            catch
            {
                return true;
            }
        }

        private static bool TryGetAnchoredEffect(
            DevirtualizationCtx ctx,
            VMOpCode opcode,
            object operand,
            out int pop,
            out int push)
        {
            pop = 0;
            push = 0;

            if (VMOpCodeCatalog.TryGet(opcode, out var semantic) &&
                semantic.HasFixedStackEffect)
            {
                pop = semantic.Pop;
                push = semantic.Push;
                return true;
            }

            switch (opcode)
            {
                case VMOpCode.Ldc_I4:
                case VMOpCode.Ldc_R4:
                case VMOpCode.Ldc_R8:
                case VMOpCode.Ldstr:
                case VMOpCode.Ldnull:
                case VMOpCode.Ldloc:
                case VMOpCode.Ldloca:
                case VMOpCode.Ldarg:
                case VMOpCode.Ldsflda:
                case VMOpCode.Ldsfld:
                case VMOpCode.Ldtoken:
                    push = 1;
                    return true;

                case VMOpCode.Ldfld:
                case VMOpCode.Ldlen:
                case VMOpCode.Conv_I4:
                case VMOpCode.Conv_I8:
                case VMOpCode.Conv_U1:
                case VMOpCode.Not:
                case VMOpCode.Neg:
                case VMOpCode.Box:
                case VMOpCode.Newarr:
                case VMOpCode.Unbox_Any:
                case VMOpCode.Ldobj:
                case VMOpCode.Isinst:
                case VMOpCode.Castclass:
                case VMOpCode.Ldflda:
                    pop = 1;
                    push = 1;
                    return true;

                case VMOpCode.Add:
                case VMOpCode.Sub:
                case VMOpCode.Xor:
                case VMOpCode.Shl:
                case VMOpCode.Shr:
                case VMOpCode.Ceq:
                case VMOpCode.Ldelem_Ref:
                case VMOpCode.Ldelem_U1:
                    pop = 2;
                    push = 1;
                    return true;

                case VMOpCode.Nop:
                    return true;

                case VMOpCode.Call:
                case VMOpCode.Callvirt:
                case VMOpCode.Newobj:
                {
                    if (!(operand is int token) || !(Lookup(ctx, token) is IMethodDescriptor descriptor))
                        return false;
                    var signature = descriptor.Signature;
                    if (signature == null)
                        return false;

                    pop = signature.ParameterTypes.Count;
                    if (opcode == VMOpCode.Newobj)
                    {
                        push = 1;
                        return true;
                    }

                    if (signature.HasThis)
                        pop++;
                    push = Classify(signature.ReturnType) == StackTypeKind.Unknown &&
                           string.Equals(signature.ReturnType?.FullName, "System.Void", StringComparison.Ordinal)
                        ? 0
                        : 1;
                    if (string.Equals(signature.ReturnType?.FullName, "System.Void", StringComparison.Ordinal))
                        push = 0;
                    return true;
                }

                default:
                    return false;
            }
        }

        public static string FormatSummary(AnchorPropagationResult result)
        {
            var sb = new StringBuilder();
            sb.AppendLine("Type-anchor propagation");
            sb.AppendLine($"  observed VM bytes  : {result.ObservedBytes}");
            for (var i = 0; i < result.RoundGains.Count; i++)
                sb.AppendLine($"  round {i + 1,-2}          : +{result.RoundGains[i]}");
            sb.AppendLine($"  final anchors      : {result.Anchors.Count} / {result.ObservedBytes}");
            sb.AppendLine($"  family-resolved    : {result.FamilyResolved.Count}");
            sb.AppendLine($"  unresolved bytes   : {result.ObservedBytes - result.Anchors.Count}");
            sb.AppendLine($"  contradictions     : {result.Contradictions.Count}");
            sb.AppendLine($"  violations         : {result.Violations.Count}");
            var collisions = result.Candidates
                .Where(p => p.Value.Count == 1)
                .GroupBy(p => p.Value.First())
                .Where(g => g.Count() > 1)
                .OrderByDescending(g => g.Count());
            foreach (var group in collisions)
                sb.AppendLine($"  [collision] {group.Count()} bytes resolve to {group.Key}");

            foreach (var anchor in result.Anchors.Values.OrderBy(a => a.Round).ThenBy(a => a.VmByte))
            {
                sb.AppendLine($"  [anchor r{anchor.Round}] vm 0x{anchor.VmByte:X2} -> {anchor.OpCode}");
                foreach (var line in anchor.Evidence)
                    sb.AppendLine($"      evidence: {line}");
            }

            foreach (var contradiction in result.Contradictions)
                sb.AppendLine($"  [contradiction] {contradiction}");
            foreach (var violation in result.Violations)
                sb.AppendLine($"  [violation] {violation}");

            return sb.ToString().TrimEnd();
        }

        // Join points must be found without consulting the opcode table: using the
        // current mapping reintroduces exactly the circularity this engine exists to
        // avoid, and a byte wrongly mapped to Br makes every one of its operands look
        // like a branch target. A byte can only be a branch if its operands are
        // always valid instruction indices -- that is a payload fact. The set is
        // deliberately over-approximated, because a missed join point produces a
        // false anchor while a spurious one only costs coverage.
        private static HashSet<int> CouldBeBranchBytes(DevirtualizationCtx ctx, IReadOnlyDictionary<int, VMOpCode> anchors)
        {
            var inRange = new Dictionary<int, int>();
            var total = new Dictionary<int, int>();

            foreach (var method in ctx.VirtualizedMethods)
            {
                var instructions = method?.MethodBody?.Instructions;
                if (instructions == null)
                    continue;

                foreach (var instruction in instructions)
                {
                    if (instruction == null || !(instruction.Operand is int value))
                        continue;

                    total.TryGetValue(instruction.VmByte, out var seen);
                    total[instruction.VmByte] = seen + 1;
                    if (value >= 0 && value < instructions.Count)
                    {
                        inRange.TryGetValue(instruction.VmByte, out var ok);
                        inRange[instruction.VmByte] = ok + 1;
                    }
                }
            }

            var result = new HashSet<int>();
            foreach (var pair in total)
            {
                if (anchors.TryGetValue(pair.Key, out var anchored))
                {
                    if (IsBranchLike(anchored))
                        result.Add(pair.Key);
                    continue;
                }

                inRange.TryGetValue(pair.Key, out var ok);
                if (pair.Value > 0 && ok * 20 >= pair.Value * 19)
                    result.Add(pair.Key);
            }

            return result;
        }

        private static bool IsBranchLike(VMOpCode opcode)
        {
            switch (opcode)
            {
                case VMOpCode.Br:
                case VMOpCode.BrTrue:
                case VMOpCode.BrFalse:
                case VMOpCode.BrLessThan:
                case VMOpCode.BrGreaterThan:
                case VMOpCode.BrLessOrEqual:
                case VMOpCode.BrGreaterOrEqual:
                case VMOpCode.BrEqual:
                case VMOpCode.BrNotEqual:
                case VMOpCode.Leave:
                case VMOpCode.Switch:
                    return true;
                default:
                    return false;
            }
        }

        private static HashSet<int> CollectBranchTargets(
            IList<VMInstruction> instructions,
            ISet<int> branchCapableBytes)
        {
            var targets = new HashSet<int>();
            foreach (var instruction in instructions)
            {
                if (instruction == null || !branchCapableBytes.Contains(instruction.VmByte))
                    continue;

                if (instruction.Operand is int target && target >= 0 && target < instructions.Count)
                    targets.Add(target);
                else if (instruction.Operand is int[] switchTargets)
                {
                    foreach (var switchTarget in switchTargets)
                    {
                        if (switchTarget >= 0 && switchTarget < instructions.Count)
                            targets.Add(switchTarget);
                    }
                }
            }

            return targets;
        }

        private static StackTypeKind Classify(TypeSignature signature)
        {
            if (signature == null)
                return StackTypeKind.Unknown;

            if (signature is ByReferenceTypeSignature || signature is PointerTypeSignature)
                return StackTypeKind.ManagedPointer;
            if (signature is SzArrayTypeSignature || signature is ArrayTypeSignature)
                return StackTypeKind.Array;

            switch (signature.FullName)
            {
                case "System.String":
                    return StackTypeKind.String;
                case "System.Boolean":
                case "System.Char":
                case "System.SByte":
                case "System.Byte":
                case "System.Int16":
                case "System.UInt16":
                case "System.Int32":
                case "System.UInt32":
                    return StackTypeKind.Int32;
                case "System.Int64":
                case "System.UInt64":
                    return StackTypeKind.Int64;
                case "System.Single":
                case "System.Double":
                    return StackTypeKind.Float;
                case "System.Void":
                    return StackTypeKind.Unknown;
            }

            TypeDefinition resolved = null;
            try
            {
                resolved = signature.Resolve();
            }
            catch
            {
                // Unresolvable references cannot constrain anything.
            }

            if (resolved == null)
                return StackTypeKind.Unknown;
            if (resolved.IsEnum)
                return StackTypeKind.Int32;
            if (resolved.IsValueType)
                return StackTypeKind.Unknown;

            return StackTypeKind.ObjectRef;
        }

        // Assignability, not equality. A string or an array satisfies a parameter
        // declared as object, so demanding an exact kind match manufactures false
        // refutations. The reverse is not true: object does not satisfy string
        // without a cast, so that direction stays a valid refutation.
        private static bool IsAssignable(StackTypeKind produced, StackTypeKind required)
        {
            if (produced == StackTypeKind.Unknown || required == StackTypeKind.Unknown)
                return true;
            if (produced == required)
                return true;
            if (required == StackTypeKind.ObjectRef)
            {
                return produced == StackTypeKind.String ||
                       produced == StackTypeKind.Array ||
                       produced == StackTypeKind.ObjectRef;
            }

            return false;
        }

        private static StackTypeKind DeclaredProduction(VMOpCode opcode)
        {
            switch (opcode)
            {
                case VMOpCode.Ldc_I4:
                case VMOpCode.Ldlen:
                case VMOpCode.Conv_I1:
                case VMOpCode.Conv_I2:
                case VMOpCode.Conv_I4:
                case VMOpCode.Conv_U1:
                case VMOpCode.Conv_U2:
                case VMOpCode.Conv_U4:
                case VMOpCode.Conv_Ovf_I1:
                case VMOpCode.Conv_Ovf_I1_Un:
                case VMOpCode.Conv_Ovf_I2:
                case VMOpCode.Conv_Ovf_I2_Un:
                case VMOpCode.Conv_Ovf_I4:
                case VMOpCode.Conv_Ovf_I4_Un:
                case VMOpCode.Conv_Ovf_U1:
                case VMOpCode.Conv_Ovf_U1_Un:
                case VMOpCode.Conv_Ovf_U2:
                case VMOpCode.Conv_Ovf_U2_Un:
                case VMOpCode.Conv_Ovf_U4:
                case VMOpCode.Conv_Ovf_U4_Un:
                case VMOpCode.Ceq:
                case VMOpCode.Sizeof:
                case VMOpCode.Ldelem_I1:
                case VMOpCode.Ldelem_I2:
                case VMOpCode.Ldelem_I4:
                case VMOpCode.Ldelem_U1:
                case VMOpCode.Ldelem_U2:
                case VMOpCode.Ldelem_U4:
                    return StackTypeKind.Int32;
                case VMOpCode.Ldc_I8:
                case VMOpCode.Conv_I8:
                case VMOpCode.Conv_U8:
                case VMOpCode.Conv_Ovf_I8:
                case VMOpCode.Conv_Ovf_I8_Un:
                case VMOpCode.Conv_Ovf_U8:
                case VMOpCode.Conv_Ovf_U8_Un:
                case VMOpCode.Ldelem_I8:
                    return StackTypeKind.Int64;
                case VMOpCode.Ldc_R4:
                case VMOpCode.Ldc_R8:
                case VMOpCode.Conv_R4:
                case VMOpCode.Conv_R8:
                case VMOpCode.Conv_R_Un:
                case VMOpCode.Ldelem_R4:
                case VMOpCode.Ldelem_R8:
                    return StackTypeKind.Float;
                case VMOpCode.Ldstr:
                    return StackTypeKind.String;
                case VMOpCode.Ldloca:
                case VMOpCode.Ldsflda:
                case VMOpCode.Ldflda:
                case VMOpCode.Ldelema:
                case VMOpCode.Unbox:
                case VMOpCode.Localloc:
                case VMOpCode.Refanyval:
                    return StackTypeKind.ManagedPointer;
                case VMOpCode.Newarr:
                    return StackTypeKind.Array;
                case VMOpCode.Newobj:
                case VMOpCode.Box:
                case VMOpCode.Ldelem_Ref:
                case VMOpCode.Isinst:
                case VMOpCode.Castclass:
                    return StackTypeKind.ObjectRef;
                default:
                    return StackTypeKind.Unknown;
            }
        }

        private static bool CanProduce(VMOpCode opcode, StackTypeKind required)
        {
            if (!PushesValue(opcode))
                return false;

            // Ldnull fits any reference-shaped requirement.
            if (opcode == VMOpCode.Ldnull)
            {
                return required == StackTypeKind.String ||
                       required == StackTypeKind.ObjectRef ||
                       required == StackTypeKind.Array;
            }

            if (VMOpCodeCatalog.IsArithmetic(opcode))
            {
                return required == StackTypeKind.Int32 ||
                       required == StackTypeKind.Int64 ||
                       required == StackTypeKind.Float;
            }

            var produced = DeclaredProduction(opcode);
            if (produced == StackTypeKind.Unknown)
                return true;

            return IsAssignable(produced, required);
        }

        private static bool IsOperandUsageCompatible(DevirtualizationCtx ctx, int vmByte, VMOpCode candidate)
        {
            const int maxSamples = 256;
            var samples = 0;

            foreach (var method in ctx.VirtualizedMethods)
            {
                var instructions = method?.MethodBody?.Instructions;
                if (instructions == null)
                    continue;

                var localCount = method.MethodBody.Locals?.Count ?? 0;
                var argumentCount = (method.Parent?.Signature?.ParameterTypes?.Count ?? 0) +
                                    (method.Parent?.IsStatic == false ? 1 : 0);

                foreach (var instruction in instructions)
                {
                    if (instruction == null || instruction.VmByte != vmByte)
                        continue;
                    if (!(instruction.Operand is int value))
                        continue;
                    if (++samples > maxSamples)
                        return true;

                    var semantic = VMOpCodeCatalog.Get(candidate);
                    var member = semantic.TokenKind == VMMetadataTokenKind.String
                        ? null
                        : Lookup(ctx, value);
                    if (semantic.TokenKind == VMMetadataTokenKind.Method && !(member is IMethodDescriptor))
                        return false;
                    if (semantic.TokenKind == VMMetadataTokenKind.Field && !(member is IFieldDescriptor))
                        return false;
                    if (semantic.TokenKind == VMMetadataTokenKind.Type && !(member is ITypeDefOrRef))
                        return false;
                    if (semantic.TokenKind == VMMetadataTokenKind.Any &&
                        !(member is IMethodDescriptor) &&
                        !(member is IFieldDescriptor) &&
                        !(member is ITypeDefOrRef))
                    {
                        return false;
                    }
                    if ((semantic.Flow == VMFlowKind.UnconditionalBranch ||
                         semantic.Flow == VMFlowKind.ConditionalBranch ||
                         semantic.Flow == VMFlowKind.Leave) &&
                        (value < 0 || value >= instructions.Count))
                    {
                        return false;
                    }

                    switch (candidate)
                    {
                        case VMOpCode.Ldloc:
                        case VMOpCode.Ldloca:
                        case VMOpCode.Stloc:
                            if (value < 0 || value >= localCount)
                                return false;
                            break;

                        case VMOpCode.Ldarg:
                        case VMOpCode.Ldarga:
                        case VMOpCode.Starg:
                            if (value < 0 || value >= argumentCount)
                                return false;
                            break;

                        case VMOpCode.Call:
                        case VMOpCode.Callvirt:
                            if (!(Lookup(ctx, value) is IMethodDescriptor called))
                                return false;
                            if (candidate == VMOpCode.Callvirt && called.Signature?.HasThis != true)
                                return false;
                            break;

                        case VMOpCode.Newobj:
                            if (!(Lookup(ctx, value) is IMethodDescriptor constructor) ||
                                !string.Equals(constructor.Name?.ToString(), ".ctor", StringComparison.Ordinal))
                                return false;
                            break;

                        case VMOpCode.Ldstr:
                            if (KnownPlaintextCryptoAnchoring.TryResolveUserString(ctx.Options.FilePath, value) == null)
                                return false;
                            break;

                        case VMOpCode.Ldfld:
                        case VMOpCode.Ldsfld:
                        case VMOpCode.Stfld:
                        case VMOpCode.Stsfld:
                        case VMOpCode.Ldsflda:
                        case VMOpCode.Ldflda:
                            if (!(Lookup(ctx, value) is IFieldDescriptor field))
                                return false;
                            FieldDefinition resolvedField;
                            try
                            {
                                resolvedField = field.Resolve();
                            }
                            catch
                            {
                                return false;
                            }
                            if (resolvedField != null)
                            {
                                var wantsStatic = candidate == VMOpCode.Ldsfld ||
                                                  candidate == VMOpCode.Stsfld ||
                                                  candidate == VMOpCode.Ldsflda;
                                if (resolvedField.IsStatic != wantsStatic)
                                    return false;
                            }
                            break;

                        case VMOpCode.Newarr:
                        case VMOpCode.Box:
                        case VMOpCode.Unbox_Any:
                        case VMOpCode.Ldobj:
                        case VMOpCode.Ldtoken:
                        case VMOpCode.Isinst:
                        case VMOpCode.Castclass:
                        // These also carry a type token, and leaving them out let a
                        // prefix opcode survive on a byte whose operands are local
                        // slot indices -- stack rules can never refute a prefix.
                        case VMOpCode.Constrained:
                        case VMOpCode.Ldelema:
                        case VMOpCode.Stobj:
                            if (!(Lookup(ctx, value) is ITypeDefOrRef))
                                return false;
                            break;

                        case VMOpCode.Br:
                        case VMOpCode.BrTrue:
                        case VMOpCode.BrFalse:
                        case VMOpCode.Leave:
                            if (value < 0 || value >= instructions.Count)
                                return false;
                            break;
                    }
                }
            }

            return true;
        }

        private static object Lookup(DevirtualizationCtx ctx, int token)
        {
            try
            {
                return ctx.Module.LookupMember(token);
            }
            catch
            {
                return null;
            }
        }

        private static bool IsOperandShapeCompatible(DevirtualizationCtx ctx, int vmByte, VMOpCode candidate)
        {
            if (!ctx.TryGetOperandType(vmByte, out var operandType))
                return true;
            return VMOpCodeCatalog.TryGet(candidate, out var descriptor) &&
                   descriptor.SupportsOperandType(operandType);
        }
    }
}
