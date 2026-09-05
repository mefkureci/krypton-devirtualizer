using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using AsmResolver.DotNet;
using Krypton.Core;
using Krypton.Core.Architecture;

namespace Krypton.Pipeline.Stages
{
    // Static rules take the opcode table as far as validity can: a candidate that
    // breaks the stack, the types, the exception regions or reachability is gone.
    // What they cannot do is separate two assignments that are both valid IL --
    // Dup against Ldnull, Ret against Throw. Both compile; only one is what the
    // method does.
    //
    // The protected assembly is still the authority on that. Its interpreter runs
    // the original stream and returns a value, so this asks it, then evaluates the
    // surviving candidate assignments and keeps the ones that reproduce the value.
    // A byte is proven when every survivor agrees on it -- not scored, not voted.
    internal static class ReturnValueOracle
    {
        internal const string EvidenceSource = "return-oracle-override";

        private const int MaxRounds = 4;
        private const int MaxOracleCandidates = 256;
        private const int MaxOracleInstructions = 128;

        private sealed class OracleOutcome
        {
            public int MethodKey { get; set; }
            public string ObservedValue { get; set; }
            public string ObservedError { get; set; }
            public List<int> MatchingCandidates { get; set; }
            public int Evaluated { get; set; }
        }

        private sealed class OracleFile
        {
            public List<OracleOutcome> Methods { get; set; }
        }

        // Proving one byte shrinks the candidate space of every method that uses it,
        // which can bring a method that was too wide to measure within reach. So the
        // measurement repeats until a round proves nothing new.
        public static void Apply(DevirtualizationCtx ctx)
        {
            if (IsEnabled("KRYPTON_DISABLE_RETURN_VALUE_ORACLE"))
                return;
            if (ctx?.VirtualizedMethods == null || ctx.PatternMatcher == null || ctx.Module == null)
                return;

            var originalPath = ctx.Options?.FilePath;
            if (string.IsNullOrWhiteSpace(originalPath) || !File.Exists(originalPath))
                return;
            if (RunnerInvoker.FindExecutable() == null)
                return;

            var total = 0;
            for (var round = 1; round <= MaxRounds; round++)
            {
                var gained = RunRound(ctx, originalPath, round);
                total += gained;
                if (gained == 0)
                    break;
            }

            if (total > 0)
            {
                ctx.Options.Logger.Success(
                    $"Return-value oracle: proved {total} opcode(s) against what the protected assembly really returns.");
            }
        }

        private static int RunRound(DevirtualizationCtx ctx, string originalPath, int round)
        {

            // Bytes already settled by measurement are facts, not candidates: feeding
            // them back in is what lets a later round reach a method that was too wide
            // to enumerate before.
            var candidates = TypeConstraintAnchoring.Propagate(ctx, CollectMeasuredBytes(ctx)).Candidates;
            if (candidates == null || candidates.Count == 0)
                return 0;

            var plans = new List<(VMMethod Method, List<IReadOnlyDictionary<int, VMOpCode>> Assignments)>();
            foreach (var method in SelectOracleMethods(ctx))
            {
                var joint = TargetedJointSolver.Solve(ctx, candidates, new[] { "key:" + method.MethodKey });
                if (!joint.Exhaustive || joint.FeasibleAssignments.Count == 0)
                    continue;

                // Nothing to measure if the surviving assignments already agree on
                // every byte this method uses.
                var undecided = joint.FeasibleValues.Count(p => p.Value.Count > 1);
                if (undecided == 0 || joint.FeasibleAssignments.Count > MaxOracleCandidates)
                    continue;

                var merged = new List<IReadOnlyDictionary<int, VMOpCode>>();
                foreach (var assignment in joint.FeasibleAssignments)
                {
                    var full = new Dictionary<int, VMOpCode>(assignment);
                    foreach (var fixedPair in joint.Fixed)
                        full[fixedPair.Key] = fixedPair.Value;
                    merged.Add(full);
                }

                plans.Add((method, merged));
                ctx.Options.Logger.Info(
                    $"Return-value oracle: MethodKey {method.MethodKey} has {merged.Count} candidate assignment(s) " +
                    $"over {undecided} undecided byte(s).");
            }

            if (plans.Count == 0)
                return 0;

            var results = RunOracle(ctx, originalPath, plans, round);
            if (results == null)
                return 0;

            var proven = new Dictionary<int, VMOpCode>();
            var contested = new HashSet<int>();

            foreach (var (method, assignments) in plans)
            {
                var outcome = results.FirstOrDefault(r => r.MethodKey == method.MethodKey);
                if (outcome?.MatchingCandidates == null || outcome.MatchingCandidates.Count == 0)
                {
                    if (outcome?.ObservedError != null)
                    {
                        ctx.Options.Logger.Info(
                            $"Return-value oracle: MethodKey {method.MethodKey} could not be observed ({outcome.ObservedError}).");
                    }

                    continue;
                }

                var survivors = outcome.MatchingCandidates
                    .Where(i => i >= 0 && i < assignments.Count)
                    .Select(i => assignments[i])
                    .ToList();

                if (survivors.Count == 0)
                    continue;

                ctx.Options.Logger.Info(
                    $"Return-value oracle: MethodKey {method.MethodKey} returns \"{outcome.ObservedValue}\"; " +
                    $"{survivors.Count} of {outcome.Evaluated} candidate(s) reproduce it.");

                foreach (var vmByte in survivors[0].Keys)
                {
                    var values = survivors.Select(a => a[vmByte]).Distinct().ToList();
                    if (values.Count != 1)
                    {
                        contested.Add(vmByte);
                        continue;
                    }

                    if (proven.TryGetValue(vmByte, out var existing) && existing != values[0])
                    {
                        // Two methods disagreeing means the premise is wrong somewhere;
                        // neither value is applied.
                        ctx.Options.Logger.Warning(
                            $"Return-value oracle: vm 0x{vmByte:X2} is {existing} for one method and {values[0]} for another.");
                        contested.Add(vmByte);
                        continue;
                    }

                    proven[vmByte] = values[0];
                }
            }

            var applied = 0;
            foreach (var pair in proven.OrderBy(p => p.Key))
            {
                if (contested.Contains(pair.Key) || !ShouldRemap(ctx, pair.Key, pair.Value))
                    continue;
                ApplyProvenMapping(ctx, pair.Key, pair.Value);
                ctx.Options.Logger.Warning($"Return-value oracle: vm 0x{pair.Key:X2} -> {pair.Value}.");
                applied++;
            }

            return applied;
        }

        // Only evidence that stands on its own -- what the protected assembly was
        // observed to do, or what the operator asserted -- is fed back as fact.
        private static Dictionary<int, HashSet<VMOpCode>> CollectMeasuredBytes(DevirtualizationCtx ctx)
        {
            var measured = new Dictionary<int, HashSet<VMOpCode>>();
            if (ctx.OpcodeConfidence == null)
                return measured;

            foreach (var pair in ctx.OpcodeConfidence)
            {
                var source = pair.Value?.Source;
                if (source != EvidenceSource &&
                    source != OpcodeMapping.RuntimeFieldTruthSource &&
                    source != "env-override")
                {
                    continue;
                }

                measured[pair.Key] = new HashSet<VMOpCode> { pair.Value.OpCode };
            }

            return measured;
        }

        private static bool IsEnabled(string variable)
        {
            var value = Environment.GetEnvironmentVariable(variable);
            return !string.IsNullOrWhiteSpace(value) &&
                   (value == "1" || value.Equals("true", StringComparison.OrdinalIgnoreCase));
        }

        private static bool ShouldRemap(DevirtualizationCtx ctx, int vmByte, VMOpCode opCode)
        {
            if (!ctx.PatternMatcher.IsOpCodeValueKnown(vmByte))
                return true;

            var current = ctx.PatternMatcher.GetOpCodeValue(vmByte);
            if (current == opCode)
                return false;

            // Ldtoken and Ldc_I4 share a shape and an operand, and the lowerer picks
            // between them per instruction. Keeping the Ldtoken mapping to preserve
            // that per-site choice was tried and is worse: with the measured bytes in
            // place the writer could no longer build a body for method_23 at all, so
            // the measurement wins here and the ldtoken sites are a known cost
            // (recorded in NOTLAR.md).
            return true;
        }


        // The VM methods are already disassembled by the time this runs, so the
        // instructions carrying the byte are corrected alongside the table -- the
        // table alone would leave the bodies describing the old opcode.
        private static void ApplyProvenMapping(DevirtualizationCtx ctx, int vmByte, VMOpCode opCode)
        {
            if (opCode == VMOpCode.Nop)
                ctx.PatternMatcher.MarkKnownNoOpValue(vmByte);
            else
                ctx.PatternMatcher.SetOpCodeValue(opCode, vmByte);

            ctx.OpcodeConfidence ??= new Dictionary<int, OpcodeMappingConfidence>();
            ctx.OpcodeConfidence[vmByte] = new OpcodeMappingConfidence(opCode, 1.0, EvidenceSource);
            ctx.AnchoredOpcodes.Add(vmByte);

            foreach (var method in ctx.VirtualizedMethods)
            {
                var instructions = method?.MethodBody?.Instructions;
                if (instructions == null)
                    continue;
                foreach (var instruction in instructions)
                {
                    if (instruction == null || instruction.VmByte != vmByte)
                        continue;
                    instruction.OpCode = opCode;
                    instruction.IsResolved = true;
                }
            }
        }

        // Worth measuring only where measuring is possible: the method has to return
        // something, take no arguments, and be small enough that its candidate set was
        // enumerated exhaustively.
        private static IEnumerable<VMMethod> SelectOracleMethods(DevirtualizationCtx ctx)
        {
            foreach (var method in ctx.VirtualizedMethods.OrderBy(m => m?.MethodBody?.Instructions?.Count ?? int.MaxValue))
            {
                var instructions = method?.MethodBody?.Instructions;
                if (instructions == null || instructions.Count == 0 || instructions.Count > MaxOracleInstructions)
                    continue;

                var parent = method.Parent;
                var signature = parent?.Signature;
                if (signature == null || signature.ParameterTypes.Count > 0)
                    continue;
                if (string.Equals(signature.ReturnType?.FullName, "System.Void", StringComparison.Ordinal))
                    continue;
                if (parent.MetadataToken.ToInt32() == 0)
                    continue;

                yield return method;
            }
        }

        private static List<OracleOutcome> RunOracle(
            DevirtualizationCtx ctx,
            string originalPath,
            List<(VMMethod Method, List<IReadOnlyDictionary<int, VMOpCode>> Assignments)> plans,
            int round)
        {
            var basePath = Path.ChangeExtension(originalPath, null);
            var suffix = round > 1 ? "-" + round : string.Empty;
            var planPath = basePath + "-return-oracle-plan" + suffix + ".json";
            var outPath = basePath + "-return-oracle" + suffix + ".json";

            try
            {
                File.WriteAllText(planPath, BuildPlanJson(plans));
            }
            catch (Exception ex)
            {
                ctx.Options.Logger.Warning("Return-value oracle: plan could not be written: " + ex.Message);
                return null;
            }

            if (!RunnerInvoker.Invoke(
                    "--eval-vm-candidates",
                    originalPath,
                    outPath,
                    "ReturnOracle",
                    _ => { },
                    line => ctx.Options.Logger.Warning(line),
                    new[] { planPath }))
            {
                return null;
            }

            if (!File.Exists(outPath))
                return null;

            try
            {
                var file = JsonSerializer.Deserialize<OracleFile>(
                    File.ReadAllText(outPath),
                    new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
                return file?.Methods;
            }
            catch (Exception ex)
            {
                ctx.Options.Logger.Warning("Return-value oracle: result could not be read: " + ex.Message);
                return null;
            }
        }

        private static string BuildPlanJson(
            List<(VMMethod Method, List<IReadOnlyDictionary<int, VMOpCode>> Assignments)> plans)
        {
            var methods = new List<object>();
            foreach (var (method, assignments) in plans)
            {
                var instructions = method.MethodBody.Instructions.Select(i => new
                {
                    VmByte = i.VmByte,
                    Operand = i.Operand is int value ? value : 0,
                    HasOperand = i.Operand is int
                }).ToList();

                var candidates = assignments
                    .Select(a => a.ToDictionary(p => $"0x{p.Key:X2}", p => p.Value.ToString()))
                    .ToList();

                methods.Add(new
                {
                    MethodKey = method.MethodKey,
                    MethodToken = method.Parent.MetadataToken.ToInt32(),
                    Instructions = instructions,
                    LocalTypeTokens = new List<int>(),
                    Candidates = candidates
                });
            }

            return JsonSerializer.Serialize(new { Methods = methods },
                new JsonSerializerOptions { WriteIndented = true });
        }
    }
}
