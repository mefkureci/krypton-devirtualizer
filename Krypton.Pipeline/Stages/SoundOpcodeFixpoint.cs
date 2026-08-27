using System;
using System.Collections.Generic;
using System.Linq;
using Krypton.Core;
using Krypton.Core.Architecture;

namespace Krypton.Pipeline.Stages
{
    internal sealed class SoundOpcodeFixpointResult
    {
        public AnchorPropagationResult Outcome { get; set; }
        public GlobalStackSolverResult LastStackResult { get; set; }
        public IDictionary<int, string> Families { get; set; } = new Dictionary<int, string>();
        public int Rounds { get; set; }
        public int NewExactAnchors { get; set; }
        public int NewFamilyAnchors { get; set; }
    }

    // Monotonic coordinator for independent-evidence solvers. Candidate sets only
    // shrink, exact anchors are only added at singleton proofs, and capped global
    // searches never contribute eliminations.
    internal static class SoundOpcodeFixpoint
    {
        private const int MaxRounds = 12;

        public static SoundOpcodeFixpointResult Run(
            DevirtualizationCtx ctx,
            AnchorPropagationResult seed)
        {
            var result = new SoundOpcodeFixpointResult { Outcome = seed };
            if (ctx == null || seed == null)
                return result;

            var initialExact = seed.Anchors.Count;
            var knownFamilies = SoundOpcodeFamilies.Classify(seed.Candidates);

            for (var round = 1; round <= MaxRounds; round++)
            {
                var before = Snapshot(seed.Candidates);
                var beforeAnchors = seed.Anchors.Count;

                var refined = TypeConstraintAnchoring.Propagate(
                    ctx, seed.Candidates, seed.Anchors);
                var stack = GlobalStackConstraintSolver.Solve(ctx, refined.Candidates);
                result.LastStackResult = stack;

                foreach (var pair in stack.Bytes)
                {
                    if (!refined.Candidates.TryGetValue(pair.Key, out var set) ||
                        pair.Value.Surviving.Count == 0)
                        continue;

                    set.IntersectWith(pair.Value.Surviving);
                    if (pair.Value.Status != ResolutionStatus.Anchored ||
                        set.Count != 1 ||
                        refined.Anchors.ContainsKey(pair.Key))
                        continue;

                    var record = new AnchorRecord
                    {
                        VmByte = pair.Key,
                        OpCode = set.First(),
                        Source = AnchorSource.GlobalStack,
                        SiteCount = 0,
                        Round = round
                    };
                    record.Evidence.Add(
                        "Exhaustive whole-method CLR stack/CFG search left one feasible semantic");
                    foreach (var elimination in pair.Value.Eliminations)
                        record.Evidence.Add(elimination);
                    refined.Anchors[pair.Key] = record;
                }

                // Re-run deterministic constant propagation after every metadata/stack
                // refinement. The known-plaintext solver only emits a mapping when all
                // surviving complete assignments agree at an independently validated
                // sink, so this remains a monotonic sound refinement.
                foreach (var proof in KnownPlaintextCryptoAnchoring.Solve(ctx, refined.Candidates))
                {
                    if (!refined.Candidates.TryGetValue(proof.VmByte, out var set) ||
                        !set.Contains(proof.OpCode))
                        continue;
                    if (refined.Anchors.TryGetValue(proof.VmByte, out var existing))
                    {
                        if (existing.OpCode == proof.OpCode)
                            existing.Evidence.Add(proof.Evidence);
                        continue;
                    }

                    set.Clear();
                    set.Add(proof.OpCode);
                    var record = new AnchorRecord
                    {
                        VmByte = proof.VmByte,
                        OpCode = proof.OpCode,
                        Source = AnchorSource.KnownPlaintext,
                        SiteCount = proof.Sites,
                        Round = round
                    };
                    record.Evidence.Add(proof.Evidence);
                    refined.Anchors[proof.VmByte] = record;
                }

                foreach (var anchor in refined.Anchors.Values)
                {
                    if (!refined.Candidates.TryGetValue(anchor.VmByte, out var set))
                        continue;
                    set.Clear();
                    set.Add(anchor.OpCode);
                }

                var families = SoundOpcodeFamilies.Classify(refined.Candidates);
                var newFamilies = families.Keys.Count(k => !knownFamilies.ContainsKey(k));
                var candidateChanges = CountChanges(before, refined.Candidates);
                var newExact = refined.Anchors.Count - beforeAnchors;

                ctx.Options.Logger.Info(
                    $"  sound fixpoint round {round}: exact +{newExact}, family +{newFamilies}, " +
                    $"candidate sets changed={candidateChanges}");

                seed = refined;
                knownFamilies = families;
                result.Rounds = round;

                if (newExact == 0 && newFamilies == 0 && candidateChanges == 0)
                    break;
            }

            result.Outcome = seed;
            result.Families = knownFamilies;
            result.NewExactAnchors = Math.Max(0, seed.Anchors.Count - initialExact);
            result.NewFamilyAnchors = knownFamilies.Count;
            ctx.Options.Logger.Info(
                $"  sound fixpoint complete: rounds={result.Rounds}, exact={seed.Anchors.Count}, " +
                $"families={knownFamilies.Count}");
            return result;
        }

        private static IDictionary<int, HashSet<VMOpCode>> Snapshot(
            IDictionary<int, HashSet<VMOpCode>> source)
        {
            return source.ToDictionary(p => p.Key, p => new HashSet<VMOpCode>(p.Value));
        }

        private static int CountChanges(
            IDictionary<int, HashSet<VMOpCode>> before,
            IDictionary<int, HashSet<VMOpCode>> after)
        {
            var changed = 0;
            foreach (var pair in after)
            {
                if (!before.TryGetValue(pair.Key, out var old) || !old.SetEquals(pair.Value))
                    changed++;
            }
            return changed;
        }
    }

    internal static class SoundOpcodeFamilies
    {
        private static readonly IDictionary<string, HashSet<VMOpCode>> Definitions =
            new Dictionary<string, HashSet<VMOpCode>>(StringComparer.Ordinal)
            {
                ["CALL"] = new HashSet<VMOpCode> { VMOpCode.Call, VMOpCode.Callvirt },
                ["LOCAL_READ"] = new HashSet<VMOpCode> { VMOpCode.Ldloc, VMOpCode.Ldloca },
                ["FIELD_LOAD"] = new HashSet<VMOpCode> { VMOpCode.Ldfld, VMOpCode.Ldsfld },
                ["FIELD_STORE"] = new HashSet<VMOpCode> { VMOpCode.Stfld, VMOpCode.Stsfld },
                ["ARRAY_LOAD"] = new HashSet<VMOpCode>
                    { VMOpCode.Ldelem_Ref, VMOpCode.Ldelem_U1, VMOpCode.Ldelema },
                ["ARRAY_STORE"] = new HashSet<VMOpCode>
                    { VMOpCode.Stelem_Ref, VMOpCode.Stelem_I1 },
                ["CONVERSION"] = new HashSet<VMOpCode>(
                    VMOpCodeCatalog.CandidateUniverse.Where(op =>
                        op.ToString().StartsWith("Conv_", StringComparison.Ordinal))),
                ["UNARY_ARITHMETIC"] = new HashSet<VMOpCode>
                    { VMOpCode.Neg, VMOpCode.Not }
            };

        public static IDictionary<int, string> Classify(
            IDictionary<int, HashSet<VMOpCode>> candidates)
        {
            var result = new Dictionary<int, string>();
            foreach (var pair in candidates)
            {
                if (pair.Value == null || pair.Value.Count < 2)
                    continue;
                foreach (var family in Definitions)
                {
                    if (pair.Value.IsSubsetOf(family.Value))
                    {
                        result[pair.Key] = family.Key;
                        break;
                    }
                }
            }
            return result;
        }
    }
}
