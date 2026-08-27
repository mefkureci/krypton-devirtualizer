using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using AsmResolver.DotNet;
using Krypton.Core;
using Krypton.Core.Architecture;

namespace Krypton.Pipeline.Stages
{
    internal static class SoundOpcodeInventory
    {
        public static string Write(DevirtualizationCtx ctx, SoundOpcodeFixpointResult fixpoint)
        {
            if (ctx?.VirtualizedMethods == null || fixpoint?.Outcome == null)
                return null;

            var outcome = fixpoint.Outcome;
            var rows = outcome.Candidates.Keys.OrderBy(b => b)
                .Select(b => BuildRow(ctx, fixpoint, b))
                .ToList();
            var exact = new HashSet<int>(outcome.Anchors.Keys);
            var tracked = ctx.VirtualizedMethods.Where(m => m?.MethodBody?.Instructions != null).ToList();
            var fullyCovered = tracked.Count(m => m.MethodBody.Instructions.All(i => exact.Contains(i.VmByte)));

            var sb = new StringBuilder();
            sb.AppendLine("Krypton sound VM opcode inventory");
            sb.AppendLine("=================================");
            sb.AppendLine("Ranking is scheduling information only. It never creates or selects a mapping.");
            sb.AppendLine($"Input: {ctx.Options.FilePath}");
            sb.AppendLine($"Observed bytes: {rows.Count}");
            sb.AppendLine($"Needed by {tracked.Count} tracked methods: {rows.Count}");
            sb.AppendLine($"EXACT_ANCHORED: {rows.Count(r => r.Status == "EXACT_ANCHORED")}");
            sb.AppendLine($"FAMILY_ANCHORED: {rows.Count(r => r.Status == "FAMILY_ANCHORED")}");
            sb.AppendLine($"UNRESOLVED: {rows.Count(r => r.Status == "UNRESOLVED")}");
            sb.AppendLine($"INCONCLUSIVE: {rows.Count(r => r.Status == "INCONCLUSIVE")}");
            sb.AppendLine($"Rounds to fixpoint: {fixpoint.Rounds}");
            sb.AppendLine($"Tracked methods fully covered by exact anchors: {fullyCovered} / {tracked.Count}");
            sb.AppendLine();

            sb.AppendLine("Top 10 proof opportunities");
            sb.AppendLine("Rank | VM | occurrences | candidates | strongest independent evidence | reason");
            var ranked = rows.Where(r => r.Status != "EXACT_ANCHORED")
                .OrderByDescending(r => r.RankScore)
                .ThenBy(r => r.Candidates.Count)
                .ThenByDescending(r => r.Occurrences)
                .ThenBy(r => r.VmByte)
                .Take(10)
                .ToList();
            for (var i = 0; i < ranked.Count; i++)
            {
                var row = ranked[i];
                sb.AppendLine(
                    $"{i + 1} | 0x{row.VmByte:X2} | {row.Occurrences} | {row.Candidates.Count} | " +
                    $"{row.StrongestEvidence} | {row.RankReason}");
            }
            sb.AppendLine();

            sb.AppendLine("Top unresolved blockers for tracked methods");
            var blockers = rows.Where(r => r.Status != "EXACT_ANCHORED")
                .OrderByDescending(r => r.Occurrences)
                .ThenBy(r => r.Candidates.Count)
                .ThenBy(r => r.VmByte)
                .Take(10)
                .ToList();
            for (var i = 0; i < blockers.Count; i++)
            {
                var row = blockers[i];
                sb.AppendLine(
                    $"{i + 1}. 0x{row.VmByte:X2}: {row.Occurrences} occurrence(s), " +
                    $"{row.Candidates.Count} candidate(s), {row.Status}");
            }
            sb.AppendLine();

            sb.AppendLine("Per-byte inventory");
            foreach (var row in rows)
            {
                sb.AppendLine($"VM byte: 0x{row.VmByte:X2}");
                sb.AppendLine($"  occurrences: {row.Occurrences}");
                sb.AppendLine($"  methods containing it ({row.Methods.Count}): {string.Join(" | ", row.Methods)}");
                sb.AppendLine($"  operand encoding/type: {row.Operand}");
                sb.AppendLine($"  candidate count: {row.Candidates.Count}");
                sb.AppendLine($"  candidate set: {string.Join(", ", row.Candidates)}");
                sb.AppendLine($"  stack effects: {string.Join(", ", row.StackEffects)}");
                sb.AppendLine($"  current status: {row.Status}");
                if (!string.IsNullOrEmpty(row.Family))
                    sb.AppendLine($"  family: {row.Family}");
                sb.AppendLine($"  contexts: {(row.Contexts.Count == 0 ? "<none>" : string.Join(", ", row.Contexts))}");
                if (outcome.Anchors.TryGetValue(row.VmByte, out var anchor))
                {
                    sb.AppendLine($"  exact semantic: {anchor.OpCode}");
                    sb.AppendLine($"  anchor source: {anchor.Source}");
                    foreach (var evidence in anchor.Evidence)
                        sb.AppendLine($"  evidence: {evidence}");
                }
                sb.AppendLine();
            }

            sb.AppendLine("Tracked method coverage");
            foreach (var method in tracked)
            {
                var bytes = method.MethodBody.Instructions.Select(i => i.VmByte).Distinct().OrderBy(b => b).ToList();
                var missing = bytes.Where(b => !exact.Contains(b)).ToList();
                sb.AppendLine(
                    $"{method.Parent?.FullName ?? "<unresolved>"} | " +
                    $"needed={bytes.Count} | exact={bytes.Count - missing.Count} | " +
                    $"covered={(missing.Count == 0 ? "YES" : "NO")} | " +
                    $"missing={(missing.Count == 0 ? "-" : string.Join(",", missing.Select(b => $"0x{b:X2}")))}");
            }

            var directory = Path.GetDirectoryName(ctx.Options.OutPath) ?? Environment.CurrentDirectory;
            var baseName = Path.GetFileNameWithoutExtension(ctx.Options.FilePath);
            var path = Path.Combine(directory, baseName + "-sound-opcode-inventory.txt");
            File.WriteAllText(path, sb.ToString(), Encoding.UTF8);
            return path;
        }

        private static InventoryRow BuildRow(
            DevirtualizationCtx ctx,
            SoundOpcodeFixpointResult fixpoint,
            int vmByte)
        {
            var candidates = fixpoint.Outcome.Candidates[vmByte].OrderBy(v => v.ToString()).ToList();
            var occurrences = 0;
            var methods = new List<string>();
            var contexts = new HashSet<string>(StringComparer.Ordinal);
            var constantPairSites = 0;
            var metadataSites = 0;
            var localSites = 0;
            var branchTargetSites = 0;
            var linearMethods = 0;

            foreach (var method in ctx.VirtualizedMethods)
            {
                var instructions = method?.MethodBody?.Instructions;
                if (instructions == null)
                    continue;
                var hits = instructions.Select((instruction, index) => (instruction, index))
                    .Where(p => p.instruction != null && p.instruction.VmByte == vmByte)
                    .ToList();
                if (hits.Count == 0)
                    continue;

                occurrences += hits.Count;
                methods.Add(method.Parent?.FullName ?? "<unresolved>");
                if (IsStructurallyLinear(method, fixpoint.Outcome.Candidates))
                {
                    contexts.Add("linear/no-branch methods");
                    linearMethods++;
                }
                if (IsModuleInitializerContext(method))
                    contexts.Add("module initializer");
                if (method.MethodBody.ExceptionHandlers.Count > 0)
                    contexts.Add("EH methods");

                foreach (var hit in hits)
                {
                    var operand = hit.instruction.Operand;
                    if (operand is int value)
                    {
                        contexts.Add("constant/int operands");
                        if (value >= 0 && value < (method.MethodBody.Locals?.Count ?? 0))
                        {
                            contexts.Add("typed locals");
                            localSites++;
                        }
                        if (value >= 0 && value < instructions.Count)
                        {
                            contexts.Add("branch-target-shaped operands");
                            branchTargetSites++;
                        }

                        var member = SafeLookup(ctx, value);
                        if (member is IMethodDescriptor)
                        {
                            contexts.Add("call/callvirt arguments");
                            contexts.Add("typed metadata");
                            metadataSites++;
                        }
                        else if (member is IFieldDescriptor)
                        {
                            contexts.Add("field loads/stores");
                            contexts.Add("typed metadata");
                            metadataSites++;
                        }
                        else if (member is ITypeDefOrRef)
                        {
                            contexts.Add("typed metadata");
                            metadataSites++;
                        }
                    }
                    else if (operand is int[])
                    {
                        contexts.Add("branch targets");
                        branchTargetSites++;
                    }

                    if (hit.index == instructions.Count - 1)
                        contexts.Add("return-position");
                    if (IsEhBoundary(method, hit.index))
                        contexts.Add("EH boundaries");
                    if (hit.index >= 2 &&
                        fixpoint.Outcome.Anchors.TryGetValue(instructions[hit.index - 1].VmByte, out var right) &&
                        fixpoint.Outcome.Anchors.TryGetValue(instructions[hit.index - 2].VmByte, out var left) &&
                        right.OpCode == VMOpCode.Ldc_I4 && left.OpCode == VMOpCode.Ldc_I4)
                    {
                        contexts.Add("constant propagation");
                        constantPairSites++;
                    }
                }
            }

            if (fixpoint.Outcome.Anchors.TryGetValue(vmByte, out var exact) &&
                exact.Source == AnchorSource.KnownPlaintext)
                contexts.Add("crypto/known plaintext");

            var status = "UNRESOLVED";
            string family = null;
            if (fixpoint.Outcome.Anchors.ContainsKey(vmByte))
                status = "EXACT_ANCHORED";
            else if (fixpoint.Families.TryGetValue(vmByte, out family))
                status = "FAMILY_ANCHORED";
            else if (candidates.Count <= 1 ||
                     (fixpoint.LastStackResult?.Bytes.TryGetValue(vmByte, out var resolution) == true &&
                      resolution.Status == ResolutionStatus.Inconclusive))
                status = "INCONCLUSIVE";

            ctx.TryGetOperandType(vmByte, out var operandType);
            var isDefined = ctx.Parser?.DefinedOperands != null &&
                            vmByte >= 0 && vmByte < ctx.Parser.DefinedOperands.Length &&
                            ctx.Parser.DefinedOperands[vmByte];
            var row = new InventoryRow
            {
                VmByte = vmByte,
                Occurrences = occurrences,
                Methods = methods.OrderBy(m => m, StringComparer.Ordinal).ToList(),
                Operand = DescribeOperand(operandType) + (isDefined ? " (table-defined)" : " (implicit none)"),
                Candidates = candidates,
                StackEffects = candidates.Select(DescribeEffect).Distinct().OrderBy(s => s).ToList(),
                Status = status,
                Family = family,
                Contexts = contexts.OrderBy(c => c, StringComparer.Ordinal).ToList()
            };

            row.RankScore =
                Math.Max(0, 36 - candidates.Count * 2) +
                Math.Min(20, (int) Math.Round(Math.Log(occurrences + 1, 2) * 3)) +
                Math.Min(12, constantPairSites * 2) +
                Math.Min(12, metadataSites * 2) +
                Math.Min(8, localSites) +
                Math.Min(8, branchTargetSites) +
                Math.Min(8, linearMethods * 2) +
                (contexts.Contains("crypto/known plaintext") ? 20 : 0) +
                (contexts.Contains("module initializer") ? 8 : 0);
            row.StrongestEvidence = Strongest(contexts);
            row.RankReason =
                $"ranking-only: {candidates.Count} candidates, {occurrences} sites, " +
                $"constant-pair={constantPairSites}, metadata={metadataSites}, linear-methods={linearMethods}";
            return row;
        }

        private static object SafeLookup(DevirtualizationCtx ctx, int token)
        {
            try { return ctx.Module.LookupMember(token); }
            catch { return null; }
        }

        private static bool IsModuleInitializerContext(VMMethod method)
        {
            var name = method?.Parent?.Name?.ToString() ?? string.Empty;
            var type = method?.Parent?.DeclaringType?.Name?.ToString() ?? string.Empty;
            return string.Equals(name, ".cctor", StringComparison.Ordinal) ||
                   string.Equals(type, "<Module>", StringComparison.Ordinal) ||
                   type.StartsWith("<Module>", StringComparison.Ordinal);
        }

        private static bool IsStructurallyLinear(
            VMMethod method,
            IDictionary<int, HashSet<VMOpCode>> candidates)
        {
            var instructions = method.MethodBody.Instructions;
            if (method.MethodBody.ExceptionHandlers.Count != 0)
                return false;
            foreach (var instruction in instructions)
            {
                if (instruction?.Operand is int[])
                    return false;
                if (!(instruction?.Operand is int target) || target < 0 || target >= instructions.Count)
                    continue;
                if (candidates.TryGetValue(instruction.VmByte, out var set) && set.Any(IsBranch))
                    return false;
            }
            return true;
        }

        private static bool IsEhBoundary(VMMethod method, int index)
        {
            return method.MethodBody.ExceptionHandlers.Any(e =>
                e.TryStart == index || e.TryEnd == index ||
                e.HandlerStart == index || e.HandlerEnd == index ||
                e.Filter == index);
        }

        private static bool IsBranch(VMOpCode op)
        {
            var flow = VMOpCodeCatalog.Get(op).Flow;
            return flow == VMFlowKind.UnconditionalBranch ||
                   flow == VMFlowKind.ConditionalBranch ||
                   flow == VMFlowKind.Leave ||
                   flow == VMFlowKind.Switch;
        }

        private static string DescribeOperand(byte type)
        {
            return type switch
            {
                0 => "0 / none",
                1 => "1 / encrypted signed integer",
                2 => "2 / Int64 little-endian",
                3 => "3 / Single little-endian",
                4 => "4 / Double little-endian",
                5 => "5 / encrypted target array",
                _ => $"{type} / unknown"
            };
        }

        private static string DescribeEffect(VMOpCode op)
        {
            var semantic = VMOpCodeCatalog.Get(op);
            if (semantic.HasFixedStackEffect)
                return $"{semantic.Pop}->{semantic.Push}";

            switch (op)
            {
                case VMOpCode.Nop:
                case VMOpCode.Br:
                case VMOpCode.Leave:
                case VMOpCode.EndFinally:
                    return "0->0";
                case VMOpCode.Ldc_I4:
                case VMOpCode.Ldc_R4:
                case VMOpCode.Ldc_R8:
                case VMOpCode.Ldstr:
                case VMOpCode.Ldnull:
                case VMOpCode.Ldloc:
                case VMOpCode.Ldloca:
                case VMOpCode.Ldarg:
                case VMOpCode.Ldsfld:
                case VMOpCode.Ldtoken:
                    return "0->1";
                case VMOpCode.Pop:
                case VMOpCode.Stloc:
                case VMOpCode.Stsfld:
                case VMOpCode.BrTrue:
                case VMOpCode.BrFalse:
                case VMOpCode.Ret:
                    return "1->0";
                case VMOpCode.Dup:
                    return "1->2";
                case VMOpCode.Ldfld:
                case VMOpCode.Ldlen:
                case VMOpCode.Neg:
                case VMOpCode.Not:
                case VMOpCode.Conv_I4:
                case VMOpCode.Conv_I8:
                case VMOpCode.Conv_U1:
                case VMOpCode.Newarr:
                case VMOpCode.Box:
                case VMOpCode.Unbox_Any:
                case VMOpCode.Ldobj:
                    return "1->1";
                case VMOpCode.Stfld:
                case VMOpCode.Stobj:
                    return "2->0";
                case VMOpCode.Add:
                case VMOpCode.Sub:
                case VMOpCode.Xor:
                case VMOpCode.Shl:
                case VMOpCode.Shr:
                case VMOpCode.Ceq:
                case VMOpCode.Ldelem_Ref:
                case VMOpCode.Ldelem_U1:
                case VMOpCode.Ldelema:
                    return "2->1";
                case VMOpCode.Stelem_Ref:
                case VMOpCode.Stelem_I1:
                    return "3->0";
                case VMOpCode.BrLessThan:
                case VMOpCode.BrGreaterThan:
                case VMOpCode.BrLessOrEqual:
                case VMOpCode.BrGreaterOrEqual:
                case VMOpCode.BrEqual:
                case VMOpCode.BrNotEqual:
                    return "2->0";
                case VMOpCode.Call:
                case VMOpCode.Callvirt:
                case VMOpCode.Newobj:
                    return "signature-dependent";
                case VMOpCode.Switch:
                    return "1->0";
                case VMOpCode.Constrained:
                    return "prefix/0->0";
                default:
                    return "unknown";
            }
        }

        private static string Strongest(ISet<string> contexts)
        {
            var order = new[]
            {
                "crypto/known plaintext", "typed metadata", "module initializer",
                "constant propagation", "EH boundaries", "typed locals",
                "branch targets", "branch-target-shaped operands", "linear/no-branch methods",
                "constant/int operands"
            };
            return order.FirstOrDefault(contexts.Contains) ?? "stack/operand-shape only";
        }

        private sealed class InventoryRow
        {
            public int VmByte { get; set; }
            public int Occurrences { get; set; }
            public IList<string> Methods { get; set; }
            public string Operand { get; set; }
            public IList<VMOpCode> Candidates { get; set; }
            public IList<string> StackEffects { get; set; }
            public string Status { get; set; }
            public string Family { get; set; }
            public IList<string> Contexts { get; set; }
            public int RankScore { get; set; }
            public string StrongestEvidence { get; set; }
            public string RankReason { get; set; }
        }
    }
}
