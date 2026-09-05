using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Krypton.Core;
using Krypton.Core.Architecture;

namespace Krypton.Pipeline.Stages
{
    internal sealed class JointSolverResult
    {
        public IList<string> TargetMethods { get; } = new List<string>();
        public IList<int> Variables { get; } = new List<int>();
        public IDictionary<int, VMOpCode> Fixed { get; } = new Dictionary<int, VMOpCode>();
        public long Explored { get; set; }
        public long Pruned { get; set; }
        public long Feasible { get; set; }
        public bool Exhaustive { get; set; }
        public string StopReason { get; set; } = "completed";
        public IDictionary<int, HashSet<VMOpCode>> FeasibleValues { get; } =
            new Dictionary<int, HashSet<VMOpCode>>();
        public IDictionary<int, VMOpCode> Proven { get; } = new Dictionary<int, VMOpCode>();
        public IList<int> Divergent { get; } = new List<int>();

        // The surviving assignments themselves, not just their union. Static rules
        // cannot separate two opcodes that are both valid IL; running them can, and
        // running them needs the whole assignment.
        public IList<IReadOnlyDictionary<int, VMOpCode>> FeasibleAssignments { get; } =
            new List<IReadOnlyDictionary<int, VMOpCode>>();
    }

    // Closing sprint: instead of resolving the whole opcode table, solve only the
    // bytes the five target methods actually need, and solve them against all five
    // methods at once. A byte keeps every value that appears in at least one
    // assignment making every target method simultaneously consistent; a byte is
    // proven only when exactly one value survives across the whole search.
    //
    // Nothing here scores, votes or prefers. If two assignments both satisfy every
    // constraint, the difference is reported rather than resolved.
    internal static class TargetedJointSolver
    {
        private const long MaxNodes = 40_000_000L;
        private const int MaxRetainedAssignments = 512;
        private const long MaxFeasible = 50_000L;

        // Targets are named before renaming has run, so the obfuscated method names are
        // usually unusable (control characters). "key:<MethodKey>" addresses a method by
        // its VM record, and a bare fragment also matches the declaring type, which is how
        // a caller picks "everything on this form" without knowing a single method name.
        private static bool Matches(VMMethod method, string fragment)
        {
            if (fragment.StartsWith("key:", StringComparison.OrdinalIgnoreCase))
            {
                return int.TryParse(fragment.Substring(4), out var key) && method.MethodKey == key;
            }

            var fullName = method.Parent?.FullName ?? string.Empty;
            return fullName.IndexOf("::" + fragment + "(", StringComparison.Ordinal) >= 0 ||
                   fullName.IndexOf(fragment, StringComparison.Ordinal) >= 0;
        }

        public static JointSolverResult Solve(
            DevirtualizationCtx ctx,
            IDictionary<int, HashSet<VMOpCode>> candidates,
            IReadOnlyCollection<string> targetFragments,
            long nodeBudget = MaxNodes)
        {
            var result = new JointSolverResult();
            if (ctx?.VirtualizedMethods == null)
                return result;

            var methods = ctx.VirtualizedMethods
                .Where(m => m?.MethodBody?.Instructions != null &&
                            m.MethodBody.Instructions.Count > 0 &&
                            targetFragments.Any(f => Matches(m, f)))
                .ToList();

            foreach (var m in methods)
                result.TargetMethods.Add($"{m.Parent?.Name ?? "key:" + m.MethodKey} ({m.MethodBody.Instructions.Count} vm)");

            if (methods.Count == 0)
            {
                result.StopReason = "no target method matched";
                return result;
            }

            // Only bytes these methods actually use matter.
            var needed = new HashSet<int>();
            foreach (var m in methods)
                foreach (var ins in m.MethodBody.Instructions)
                    if (ins != null)
                        needed.Add(ins.VmByte);

            var domains = new Dictionary<int, List<VMOpCode>>();
            foreach (var b in needed)
            {
                if (!candidates.TryGetValue(b, out var set) || set.Count == 0)
                {
                    result.StopReason = $"vm 0x{b:X2} has an empty candidate set";
                    return result;
                }

                // Per-method operand validity is far tighter than the global filter.
                var usable = set.Where(op => methods.All(m =>
                    !m.MethodBody.Instructions.Any(i => i != null && i.VmByte == b) ||
                    GlobalStackConstraintSolver.IsUsableInMethod(ctx, m, b, op))).ToList();

                if (usable.Count == 0)
                {
                    result.StopReason = $"vm 0x{b:X2} has no candidate usable in the target methods";
                    return result;
                }

                if (usable.Count == 1)
                    result.Fixed[b] = usable[0];
                else
                    domains[b] = usable;
            }

            // Most-constrained first: fewest candidates, then most target methods hit.
            var order = domains.Keys
                .OrderBy(b => domains[b].Count)
                .ThenByDescending(b => methods.Count(m =>
                    m.MethodBody.Instructions.Any(i => i != null && i.VmByte == b)))
                .ToList();
            foreach (var b in order)
                result.Variables.Add(b);
            foreach (var b in needed)
                result.FeasibleValues[b] = new HashSet<VMOpCode>();

            var assignment = new Dictionary<int, VMOpCode>(result.Fixed);
            long explored = 0, pruned = 0, feasible = 0;
            var capped = false;

            bool AllConsistent(bool complete)
            {
                foreach (var m in methods)
                {
                    if (!GlobalStackConstraintSolver.IsStackConsistent(
                            ctx, m, assignment, complete, out _, out _,
                            requireFullReachability: complete))
                    {
                        return false;
                    }

                    // Depth alone cannot separate two opcodes of the same shape.
                    // Metadata types can, and they are as independent of the
                    // opcode table as the depths are.
                    if (!TypedStackConstraint.IsTypeConsistent(ctx, m, assignment, out _, out _))
                        return false;
                }

                return true;
            }

            void Recurse(int depth)
            {
                if (capped)
                    return;
                if (explored >= nodeBudget || feasible >= MaxFeasible)
                {
                    capped = true;
                    return;
                }

                if (depth == order.Count)
                {
                    explored++;
                    if (!AllConsistent(complete: true))
                        return;

                    feasible++;
                    foreach (var pair in assignment)
                        result.FeasibleValues[pair.Key].Add(pair.Value);
                    if (result.FeasibleAssignments.Count < MaxRetainedAssignments)
                        result.FeasibleAssignments.Add(new Dictionary<int, VMOpCode>(assignment));
                    return;
                }

                var vmByte = order[depth];
                foreach (var candidate in domains[vmByte])
                {
                    if (capped)
                        return;

                    explored++;
                    assignment[vmByte] = candidate;
                    if (AllConsistent(complete: false))
                        Recurse(depth + 1);
                    else
                        pruned++;
                    assignment.Remove(vmByte);
                }
            }

            if (!AllConsistent(complete: false))
            {
                result.StopReason = "the fixed anchors alone already contradict the target methods";
                return result;
            }

            Recurse(0);

            result.Explored = explored;
            result.Pruned = pruned;
            result.Feasible = feasible;
            result.Exhaustive = !capped;
            if (capped)
                result.StopReason = "node or solution cap reached - INCONCLUSIVE";

            foreach (var pair in result.Fixed)
                result.FeasibleValues[pair.Key].Add(pair.Value);

            if (result.Exhaustive && feasible > 0)
            {
                foreach (var pair in result.FeasibleValues)
                {
                    if (pair.Value.Count == 1)
                        result.Proven[pair.Key] = pair.Value.First();
                    else if (pair.Value.Count > 1)
                        result.Divergent.Add(pair.Key);
                }
            }

            return result;
        }

        public static string Format(JointSolverResult r)
        {
            var sb = new StringBuilder();
            sb.AppendLine("Targeted joint solve (5 methods, minimal byte set)");
            foreach (var m in r.TargetMethods)
                sb.AppendLine($"  target             : {m}");
            sb.AppendLine($"  fixed by anchors   : {r.Fixed.Count}");
            sb.AppendLine($"  free variables     : {r.Variables.Count} " +
                          $"({string.Join(", ", r.Variables.Select(b => $"0x{b:X2}"))})");
            sb.AppendLine($"  assignments explored: {r.Explored}");
            sb.AppendLine($"  assignments pruned  : {r.Pruned}");
            sb.AppendLine($"  complete feasible   : {r.Feasible}");
            sb.AppendLine($"  exhaustive          : {(r.Exhaustive ? "YES" : "NO")}");
            sb.AppendLine($"  stop reason         : {r.StopReason}");

            if (r.Proven.Count > 0)
            {
                sb.AppendLine("  GLOBALLY_PROVEN:");
                foreach (var pair in r.Proven.OrderBy(p => p.Key))
                    sb.AppendLine($"    vm 0x{pair.Key:X2} -> {pair.Value}");
            }

            // Even a capped search yields a sound negative: every assignment counted
            // was genuinely feasible, so a byte seen with two different values is
            // definitively undetermined by these constraints. The converse does not
            // hold, so single-valued bytes are reported as unconfirmed.
            var multi = r.FeasibleValues.Where(p => p.Value.Count > 1).OrderByDescending(p => p.Value.Count).ToList();
            var single = r.FeasibleValues.Where(p => p.Value.Count == 1 && !r.Fixed.ContainsKey(p.Key)).ToList();

            if (multi.Count > 0)
            {
                sb.AppendLine($"  DEFINITIVELY AMBIGUOUS ({multi.Count} bytes - two or more feasible values):");
                foreach (var pair in multi)
                {
                    sb.AppendLine($"    vm 0x{pair.Key:X2} ({pair.Value.Count}): " +
                                  string.Join(", ", pair.Value.OrderBy(v => v.ToString())));
                }
            }

            if (single.Count > 0)
            {
                sb.AppendLine($"  single-valued so far ({single.Count} bytes - NOT proven, search was capped):");
                foreach (var pair in single.OrderBy(p => p.Key))
                    sb.AppendLine($"    vm 0x{pair.Key:X2} -> {pair.Value.First()}");
            }

            return sb.ToString().TrimEnd();
        }
    }
}
