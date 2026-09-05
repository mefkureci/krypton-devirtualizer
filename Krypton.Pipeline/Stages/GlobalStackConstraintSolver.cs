using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using AsmResolver.DotNet;
using Krypton.Core;
using Krypton.Core.Architecture;

namespace Krypton.Pipeline.Stages
{
    internal enum ResolutionStatus
    {
        Anchored,
        Unresolved,
        Inconclusive,
        Contradiction
    }

    internal sealed class ByteResolution
    {
        public int VmByte { get; set; }
        public HashSet<VMOpCode> Initial { get; set; } = new HashSet<VMOpCode>();
        public HashSet<VMOpCode> Surviving { get; set; } = new HashSet<VMOpCode>();
        public IList<string> Eliminations { get; } = new List<string>();
        public bool HadExhaustiveCoverage { get; set; }
        public ResolutionStatus Status { get; set; } = ResolutionStatus.Inconclusive;
    }

    internal sealed class MethodSolveReport
    {
        public string Method { get; set; }
        public int Instructions { get; set; }
        public int DistinctBytes { get; set; }
        public long SearchSpace { get; set; }
        public long NodesExplored { get; set; }
        public long BranchesPruned { get; set; }
        public long FeasibleAssignments { get; set; }
        public bool Exhaustive { get; set; }
        public string StopReason { get; set; } = "completed";
        public IDictionary<int, (int before, int after)> CandidateCounts { get; } =
            new Dictionary<int, (int, int)>();
        public IList<int> BecameSingleton { get; } = new List<int>();
    }

    internal sealed class GlobalStackSolverResult
    {
        public IList<MethodSolveReport> Methods { get; } = new List<MethodSolveReport>();
        public IDictionary<int, ByteResolution> Bytes { get; } = new Dictionary<int, ByteResolution>();
        public IList<string> Contradictions { get; } = new List<string>();
    }

    // Stack discipline is enforced by the CLR on every executable method: no
    // underflow, one depth per instruction however it is reached, an empty stack at
    // return, a single exception object entering a catch. Those are facts about the
    // sample rather than products of the opcode table, so they can eliminate
    // candidates without circularity.
    //
    // A whole method is solved at once instead of byte by byte: an assignment
    // survives only if it makes the entire method consistent, and a byte keeps every
    // value that appears in at least one surviving assignment. Two survivors means
    // ambiguous -- "best" is never promoted to "proven".
    //
    // Narrowing is only applied from a method whose search ran to completion. A
    // search that hit a cap proves nothing, because the assignment it never examined
    // might have been the feasible one.
    internal static class GlobalStackConstraintSolver
    {
        private const int MaxInstructions = 128;
        private const long MaxSearchSpace = 500_000_000_000L;
        private const long MaxNodes = 3_000_000L;
        private const int MaxDepth = 64;

        private sealed class SearchState
        {
            public long Nodes;
            public long Pruned;
            public long Feasible;
            public bool CapHit;
        }

        public static GlobalStackSolverResult Solve(
            DevirtualizationCtx ctx,
            IDictionary<int, HashSet<VMOpCode>> candidates)
        {
            var result = new GlobalStackSolverResult();
            if (ctx?.VirtualizedMethods == null)
                return result;

            foreach (var pair in candidates)
            {
                result.Bytes[pair.Key] = new ByteResolution
                {
                    VmByte = pair.Key,
                    Initial = new HashSet<VMOpCode>(pair.Value),
                    Surviving = new HashSet<VMOpCode>(pair.Value)
                };
            }

            // A candidate that contradicts the stack rules on its own needs no
            // search at all: assigning only that byte and finding an underflow, a
            // merge mismatch or a bad return depth is already a proof, and it holds
            // however every other byte turns out. This is independent of whether any
            // later search runs to completion.
            EliminateBySingleAssignment(ctx, result);

            var methods = ctx.VirtualizedMethods
                .Where(m => m?.MethodBody?.Instructions != null &&
                            m.MethodBody.Instructions.Count > 0 &&
                            m.MethodBody.Instructions.Count <= MaxInstructions)
                .OrderBy(m => m.MethodBody.Instructions.Count)
                .ToList();

            foreach (var method in methods)
            {
                var instructions = method.MethodBody.Instructions;
                var report = new MethodSolveReport
                {
                    Method = method.Parent?.Name ?? "<method>",
                    Instructions = instructions.Count
                };
                result.Methods.Add(report);

                var order = new List<int>();
                foreach (var instruction in instructions)
                {
                    if (instruction != null && !order.Contains(instruction.VmByte))
                        order.Add(instruction.VmByte);
                }

                report.DistinctBytes = order.Count;

                var local = new Dictionary<int, List<VMOpCode>>();
                long space = 1;
                var viable = true;
                foreach (var vmByte in order)
                {
                    if (!result.Bytes.TryGetValue(vmByte, out var resolution) || resolution.Surviving.Count == 0)
                    {
                        viable = false;
                        report.StopReason = $"no candidates for vm 0x{vmByte:X2}";
                        break;
                    }

                    var narrowed = resolution.Surviving
                        .Where(op => IsUsableInMethod(ctx, method, vmByte, op))
                        .ToList();
                    if (narrowed.Count == 0)
                    {
                        viable = false;
                        report.StopReason = $"vm 0x{vmByte:X2} has no candidate usable in this method";
                        break;
                    }

                    local[vmByte] = narrowed;
                    report.CandidateCounts[vmByte] = (resolution.Surviving.Count, narrowed.Count);
                    space = space > MaxSearchSpace / Math.Max(1, narrowed.Count)
                        ? long.MaxValue
                        : space * narrowed.Count;
                    if (space >= MaxSearchSpace)
                    {
                        viable = false;
                        report.StopReason = "search space exceeds cap";
                        break;
                    }
                }

                report.SearchSpace = space;
                if (!viable)
                {
                    report.Exhaustive = false;
                    continue;
                }

                var possible = order.ToDictionary(b => b, _ => new HashSet<VMOpCode>());
                var assignment = new Dictionary<int, VMOpCode>();
                var state = new SearchState();

                Search(ctx, method, order, 0, local, assignment, possible, state);

                report.NodesExplored = state.Nodes;
                report.BranchesPruned = state.Pruned;
                report.FeasibleAssignments = state.Feasible;
                report.Exhaustive = !state.CapHit;
                if (state.CapHit)
                    report.StopReason = "node cap reached - INCONCLUSIVE";

                if (!report.Exhaustive)
                    continue;

                if (state.Feasible == 0)
                {
                    // No assignment at all satisfies the stack rules, which means an
                    // earlier filter already discarded the true opcode for some byte.
                    // Narrowing from here would compound that error.
                    report.StopReason = "no feasible assignment - candidate sets already exclude the truth";
                    result.Contradictions.Add(
                        $"method {report.Method}: exhaustive search found no stack-consistent assignment; " +
                        "an upstream filter has removed a correct candidate");
                    continue;
                }

                foreach (var vmByte in order)
                {
                    var resolution = result.Bytes[vmByte];
                    resolution.HadExhaustiveCoverage = true;

                    var before = resolution.Surviving.Count;
                    var eliminated = resolution.Surviving.Where(op => !possible[vmByte].Contains(op)).ToList();
                    foreach (var candidate in eliminated)
                    {
                        resolution.Surviving.Remove(candidate);
                        resolution.Eliminations.Add(BuildElimination(ctx, method, report, vmByte, candidate, state));
                    }

                    if (before > 1 && resolution.Surviving.Count == 1)
                        report.BecameSingleton.Add(vmByte);
                }
            }

            foreach (var resolution in result.Bytes.Values)
            {
                if (resolution.Surviving.Count == 0)
                {
                    resolution.Status = ResolutionStatus.Contradiction;
                    result.Contradictions.Add($"vm 0x{resolution.VmByte:X2}: every candidate was eliminated");
                }
                else if (resolution.Surviving.Count > 1)
                {
                    resolution.Status = ResolutionStatus.Unresolved;
                }
                else if (resolution.HadExhaustiveCoverage && resolution.Initial.Count > 1)
                {
                    resolution.Status = ResolutionStatus.Anchored;
                }
                else
                {
                    // Singleton, but this solver never proved the alternatives away.
                    resolution.Status = ResolutionStatus.Inconclusive;
                }
            }

            return result;
        }

        // A candidate that is impossible on its own gives a pinpointed contradiction;
        // otherwise the proof is the exhausted search itself.
        private static string BuildElimination(
            DevirtualizationCtx ctx,
            VMMethod method,
            MethodSolveReport report,
            int vmByte,
            VMOpCode candidate,
            SearchState state)
        {
            var single = new Dictionary<int, VMOpCode> { { vmByte, candidate } };
            if (!IsStackConsistent(ctx, method, single, complete: false, out var reason, out var index))
            {
                return $"{candidate}: rejected by {report.Method} at VM index {index} - {reason} " +
                       "(independent basis: CLR stack discipline)";
            }

            return $"{candidate}: no stack-consistent assignment exists in {report.Method} " +
                   $"(exhaustive: {state.Nodes} nodes, {state.Feasible} feasible assignments) " +
                   "(independent basis: CLR stack discipline)";
        }

        private static void EliminateBySingleAssignment(
            DevirtualizationCtx ctx,
            GlobalStackSolverResult result)
        {
            var methods = ctx.VirtualizedMethods
                .Where(m => m?.MethodBody?.Instructions != null && m.MethodBody.Instructions.Count > 0)
                .ToList();

            foreach (var resolution in result.Bytes.Values)
            {
                foreach (var candidate in resolution.Surviving.ToList())
                {
                    foreach (var method in methods)
                    {
                        if (!method.MethodBody.Instructions.Any(i => i != null && i.VmByte == resolution.VmByte))
                            continue;

                        var single = new Dictionary<int, VMOpCode> { { resolution.VmByte, candidate } };
                        if (IsStackConsistent(ctx, method, single, complete: false, out var reason, out var index))
                            continue;

                        resolution.Surviving.Remove(candidate);
                        resolution.HadExhaustiveCoverage = true;
                        resolution.Eliminations.Add(
                            $"{candidate}: rejected by {method.Parent?.Name ?? "<method>"} at VM index {index} - {reason} " +
                            "(single-assignment contradiction; independent basis: CLR stack discipline)");
                        break;
                    }
                }
            }
        }

        private static void Search(
            DevirtualizationCtx ctx,
            VMMethod method,
            IReadOnlyList<int> order,
            int index,
            IReadOnlyDictionary<int, List<VMOpCode>> local,
            Dictionary<int, VMOpCode> assignment,
            IDictionary<int, HashSet<VMOpCode>> possible,
            SearchState state)
        {
            if (state.CapHit)
                return;
            if (state.Nodes >= MaxNodes)
            {
                state.CapHit = true;
                return;
            }

            if (index == order.Count)
            {
                state.Nodes++;

                // Once every byte in the method has a value, an assignment that leaves
                // part of the stream unreachable is describing a method the VM never
                // executes; requiring full reachability is what stops a terminal
                // opcode from being an escape hatch for the rest of the search.
                if (!IsStackConsistent(ctx, method, assignment, complete: true, out _, out _,
                        requireFullReachability: true))
                {
                    return;
                }
                if (!TypedStackConstraint.IsTypeConsistent(ctx, method, assignment, out _, out _))
                    return;

                state.Feasible++;
                foreach (var pair in assignment)
                    possible[pair.Key].Add(pair.Value);
                return;
            }

            var vmByte = order[index];
            foreach (var candidate in local[vmByte])
            {
                if (state.CapHit)
                    return;

                state.Nodes++;
                assignment[vmByte] = candidate;

                // Depth and metadata types are independent facts about the same
                // assignment; a candidate has to survive both to stay in the tree.
                if (IsStackConsistent(ctx, method, assignment, complete: false, out _, out _) &&
                    TypedStackConstraint.IsTypeConsistent(ctx, method, assignment, out _, out _))
                {
                    Search(ctx, method, order, index + 1, local, assignment, possible, state);
                }
                else
                {
                    state.Pruned++;
                }
                assignment.Remove(vmByte);
            }
        }

        // Walks the instruction graph under one assignment. An instruction whose byte
        // is not assigned yet stops that path instead of being guessed, so any
        // contradiction reported is one the assignment really causes.
        internal static bool IsStackConsistent(
            DevirtualizationCtx ctx,
            VMMethod method,
            IReadOnlyDictionary<int, VMOpCode> assignment,
            bool complete,
            out string reason,
            out int failureIndex,
            bool requireFullReachability = false)
        {
            reason = null;
            failureIndex = -1;

            var instructions = method.MethodBody.Instructions;
            var depths = new int[instructions.Count];
            for (var i = 0; i < depths.Length; i++)
                depths[i] = int.MinValue;

            var expectedReturn = ResolveExpectedReturn(method);
            var queue = new Queue<(int index, int depth)>();
            queue.Enqueue((0, 0));

            foreach (var handler in method.MethodBody.ExceptionHandlers)
            {
                if (handler == null)
                    continue;
                if (handler.HandlerStart >= 0 && handler.HandlerStart < instructions.Count)
                {
                    var entryDepth = handler.EHType == VMExceptionHandlerType.Finally ||
                                     handler.EHType == VMExceptionHandlerType.Fault
                        ? 0
                        : 1;
                    queue.Enqueue((handler.HandlerStart, entryDepth));
                }

                if (handler.EHType == VMExceptionHandlerType.Filter &&
                    handler.Filter >= 0 && handler.Filter < instructions.Count)
                {
                    queue.Enqueue((handler.Filter, 1));
                }
            }

            while (queue.Count > 0)
            {
                var (index, depth) = queue.Dequeue();
                if (index < 0 || index >= instructions.Count)
                {
                    reason = "control transfer outside the method";
                    failureIndex = index;
                    return false;
                }

                if (depth < 0 || depth > MaxDepth)
                {
                    reason = $"stack depth {depth} out of range";
                    failureIndex = index;
                    return false;
                }

                if (depths[index] != int.MinValue)
                {
                    if (depths[index] != depth)
                    {
                        reason = $"merge stack depth mismatch ({depths[index]} vs {depth})";
                        failureIndex = index;
                        return false;
                    }

                    continue;
                }

                depths[index] = depth;

                var instruction = instructions[index];
                if (instruction == null)
                {
                    reason = "missing instruction";
                    failureIndex = index;
                    return false;
                }

                if (!assignment.TryGetValue(instruction.VmByte, out var opcode))
                    continue;

                if (!TryGetEffect(ctx, opcode, instruction.Operand, out var pop, out var push, out var flow))
                {
                    reason = $"{opcode} cannot be lowered with this operand";
                    failureIndex = index;
                    return false;
                }

                // Endfinally, rethrow and leave are only legal inside the region they
                // belong to. A method with no exception handlers at all cannot carry
                // any of them, which is what keeps a byte from parking on one of these
                // terminators purely to end the walk early.
                if (!IsHandlerContextValid(method, opcode, index))
                {
                    reason = $"{opcode} appears outside the exception region it requires";
                    failureIndex = index;
                    return false;
                }

                if (depth < pop)
                {
                    reason = $"stack underflow: {opcode} pops {pop} at depth {depth}";
                    failureIndex = index;
                    return false;
                }

                var next = depth - pop + push;

                switch (flow)
                {
                    case FlowKind.Return:
                        if (depth != expectedReturn)
                        {
                            reason = $"return with stack depth {depth}, expected {expectedReturn}";
                            failureIndex = index;
                            return false;
                        }

                        break;

                    case FlowKind.EndFinally:
                    case FlowKind.Throw:
                        break;

                    case FlowKind.Leave:
                        if (!TryTarget(instruction.Operand, instructions.Count, out var leaveTarget))
                        {
                            reason = "leave target outside the method";
                            failureIndex = index;
                            return false;
                        }

                        queue.Enqueue((leaveTarget, 0));
                        break;

                    case FlowKind.Unconditional:
                        if (!TryTarget(instruction.Operand, instructions.Count, out var target))
                        {
                            reason = "branch target outside the method";
                            failureIndex = index;
                            return false;
                        }

                        queue.Enqueue((target, next));
                        break;

                    case FlowKind.Conditional:
                        if (!TryTarget(instruction.Operand, instructions.Count, out var conditional))
                        {
                            reason = "branch target outside the method";
                            failureIndex = index;
                            return false;
                        }

                        queue.Enqueue((conditional, next));
                        if (index + 1 >= instructions.Count)
                        {
                            reason = "conditional branch has no fall-through";
                            failureIndex = index;
                            return false;
                        }

                        queue.Enqueue((index + 1, next));
                        break;

                    case FlowKind.Switch:
                    {
                        if (!(instruction.Operand is int[] targets) || targets.Length == 0)
                        {
                            reason = "switch without targets";
                            failureIndex = index;
                            return false;
                        }

                        foreach (var switchTarget in targets)
                        {
                            if (switchTarget < 0 || switchTarget >= instructions.Count)
                            {
                                reason = "switch target outside the method";
                                failureIndex = index;
                                return false;
                            }

                            queue.Enqueue((switchTarget, next));
                        }

                        if (index + 1 < instructions.Count)
                            queue.Enqueue((index + 1, next));
                        break;
                    }

                    default:
                        if (index + 1 < instructions.Count)
                        {
                            queue.Enqueue((index + 1, next));
                        }
                        else if (next != 0)
                        {
                            reason = $"method falls off the end with stack depth {next}";
                            failureIndex = index;
                            return false;
                        }

                        break;
                }
            }

            if (!complete)
                return true;

            // A byte mapped to a terminal opcode makes everything after it
            // unreachable, and unreachable code cannot contradict anything -- so
            // truncating assignments satisfy every check that only inspects what the
            // walk visited. Requiring the whole stream to stay reachable removes that
            // escape, but it is a claim about the sample (that the obfuscator emitted
            // no dead VM code), not a rule of the CLR, so callers opt in per search
            // rather than it holding module-wide.
            if (requireFullReachability)
            {
                for (var i = 0; i < instructions.Count; i++)
                {
                    if (depths[i] != int.MinValue)
                        continue;
                    reason = $"instruction {i} is unreachable under this assignment";
                    failureIndex = i;
                    return false;
                }
            }

            for (var i = 0; i < instructions.Count; i++)
            {
                if (depths[i] == int.MinValue)
                    continue;
                var instruction = instructions[i];
                if (instruction == null || !assignment.TryGetValue(instruction.VmByte, out var opcode))
                    continue;
                if (!TryGetEffect(ctx, opcode, instruction.Operand, out var pop, out var push, out var flow))
                    continue;
                if (flow != FlowKind.Fall || i + 1 < instructions.Count)
                    continue;

                // ECMA-335: the instruction stream must not fall off the end of a
                // method. The last instruction has to transfer control -- ret, throw,
                // br, leave, endfinally -- so a plain instruction sitting there is not
                // a stack-depth question at all, it is an invalid method.
                reason = "the last instruction falls off the end of the method";
                failureIndex = i;
                return false;
            }

            return true;
        }

        // Endfinally must sit in a finally or fault handler, rethrow in a catch or
        // filter handler, and leave in a protected region or a catch-like handler.
        private static bool IsHandlerContextValid(VMMethod method, VMOpCode opcode, int index)
        {
            if (opcode != VMOpCode.EndFinally && opcode != VMOpCode.Rethrow && opcode != VMOpCode.Leave)
                return true;

            var handlers = method?.MethodBody?.ExceptionHandlers;
            if (handlers == null || handlers.Count == 0)
                return false;

            foreach (var handler in handlers)
            {
                if (handler == null)
                    continue;

                var inHandler = index >= handler.HandlerStart && index <= handler.HandlerEnd;
                var inTry = index >= handler.TryStart && index <= handler.TryEnd;

                switch (opcode)
                {
                    case VMOpCode.EndFinally:
                        if (inHandler &&
                            (handler.EHType == VMExceptionHandlerType.Finally ||
                             handler.EHType == VMExceptionHandlerType.Fault))
                        {
                            return true;
                        }

                        break;

                    case VMOpCode.Rethrow:
                        if (inHandler &&
                            (handler.EHType == VMExceptionHandlerType.Catch ||
                             handler.EHType == VMExceptionHandlerType.Filter))
                        {
                            return true;
                        }

                        break;

                    default:
                        if (inTry ||
                            (inHandler && handler.EHType != VMExceptionHandlerType.Finally &&
                             handler.EHType != VMExceptionHandlerType.Fault))
                        {
                            return true;
                        }

                        break;
                }
            }

            return false;
        }

        private static bool TryTarget(object operand, int count, out int target)
        {
            target = -1;
            if (!(operand is int value) || value < 0 || value >= count)
                return false;
            target = value;
            return true;
        }

        private static int ResolveExpectedReturn(VMMethod method)
        {
            var returnType = method?.Parent?.Signature?.ReturnType?.FullName;
            return string.IsNullOrEmpty(returnType) ||
                   string.Equals(returnType, "System.Void", StringComparison.Ordinal)
                ? 0
                : 1;
        }

        internal enum FlowKind
        {
            Fall,
            Unconditional,
            Conditional,
            Switch,
            Return,
            Leave,
            EndFinally,
            Throw
        }

        internal static bool TryGetEffect(
            DevirtualizationCtx ctx,
            VMOpCode opcode,
            object operand,
            out int pop,
            out int push,
            out FlowKind flow)
        {
            pop = 0;
            push = 0;
            flow = FlowKind.Fall;

            if (VMOpCodeCatalog.TryGet(opcode, out var semantic) &&
                semantic.HasFixedStackEffect)
            {
                pop = semantic.Pop;
                push = semantic.Push;
                flow = semantic.Flow switch
                {
                    VMFlowKind.UnconditionalBranch => FlowKind.Unconditional,
                    VMFlowKind.ConditionalBranch => FlowKind.Conditional,
                    VMFlowKind.Switch => FlowKind.Switch,
                    VMFlowKind.Return => FlowKind.Return,
                    VMFlowKind.Leave => FlowKind.Leave,
                    VMFlowKind.EndFinally => FlowKind.EndFinally,
                    VMFlowKind.Throw => FlowKind.Throw,
                    VMFlowKind.Rethrow => FlowKind.Throw,
                    _ => FlowKind.Fall
                };
                return true;
            }

            switch (opcode)
            {
                case VMOpCode.Nop:
                case VMOpCode.Constrained:
                    return true;

                case VMOpCode.Ldc_I4:
                case VMOpCode.Ldc_R4:
                case VMOpCode.Ldc_R8:
                case VMOpCode.Ldstr:
                case VMOpCode.Ldnull:
                case VMOpCode.Ldloc:
                case VMOpCode.Ldloca:
                case VMOpCode.Ldarg:
                case VMOpCode.Ldsfld:
                case VMOpCode.Ldsflda:
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

                case VMOpCode.Dup:
                    pop = 1;
                    push = 2;
                    return true;

                case VMOpCode.Add:
                case VMOpCode.Sub:
                case VMOpCode.Xor:
                case VMOpCode.Shl:
                case VMOpCode.Shr:
                case VMOpCode.Ceq:
                case VMOpCode.Cgt:
                case VMOpCode.Cgt_Un:
                case VMOpCode.Clt:
                case VMOpCode.Clt_Un:
                case VMOpCode.Ldelem_Ref:
                case VMOpCode.Ldelem_U1:
                case VMOpCode.Ldelema:
                    pop = 2;
                    push = 1;
                    return true;

                case VMOpCode.Pop:
                case VMOpCode.Stloc:
                case VMOpCode.Stsfld:
                    pop = 1;
                    return true;

                case VMOpCode.Stfld:
                case VMOpCode.Stobj:
                    pop = 2;
                    return true;

                case VMOpCode.Stelem_Ref:
                case VMOpCode.Stelem_I1:
                    pop = 3;
                    return true;

                case VMOpCode.Br:
                    flow = FlowKind.Unconditional;
                    return true;

                case VMOpCode.BrTrue:
                case VMOpCode.BrFalse:
                    pop = 1;
                    flow = FlowKind.Conditional;
                    return true;

                case VMOpCode.BrLessThan:
                case VMOpCode.BrGreaterThan:
                case VMOpCode.BrLessOrEqual:
                case VMOpCode.BrGreaterOrEqual:
                case VMOpCode.BrEqual:
                case VMOpCode.BrNotEqual:
                    pop = 2;
                    flow = FlowKind.Conditional;
                    return true;

                case VMOpCode.Switch:
                    pop = 1;
                    flow = FlowKind.Switch;
                    return true;

                case VMOpCode.Ret:
                    flow = FlowKind.Return;
                    return true;

                case VMOpCode.Leave:
                    flow = FlowKind.Leave;
                    return true;

                case VMOpCode.EndFinally:
                    flow = FlowKind.EndFinally;
                    return true;

                case VMOpCode.Call:
                case VMOpCode.Callvirt:
                case VMOpCode.Newobj:
                {
                    if (!(operand is int token))
                        return false;
                    IMethodDescriptor descriptor;
                    try
                    {
                        descriptor = ctx.Module.LookupMember(token) as IMethodDescriptor;
                    }
                    catch
                    {
                        return false;
                    }

                    var signature = descriptor?.Signature;
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
                    push = string.Equals(signature.ReturnType?.FullName, "System.Void", StringComparison.Ordinal)
                        ? 0
                        : 1;
                    return true;
                }

                default:
                    return false;
            }
        }

        internal static bool IsUsableInMethod(DevirtualizationCtx ctx, VMMethod method, int vmByte, VMOpCode opcode)
        {
            var instructions = method.MethodBody.Instructions;
            var localCount = method.MethodBody.Locals?.Count ?? 0;
            var argumentCount = (method.Parent?.Signature?.ParameterTypes?.Count ?? 0) +
                                (method.Parent?.IsStatic == false ? 1 : 0);

            foreach (var instruction in instructions)
            {
                if (instruction == null || instruction.VmByte != vmByte)
                    continue;

                if (!TryGetEffect(ctx, opcode, instruction.Operand, out _, out _, out _))
                    return false;

                if (!(instruction.Operand is int value))
                    continue;

                var semantic = VMOpCodeCatalog.Get(opcode);
                if ((semantic.Flow == VMFlowKind.UnconditionalBranch ||
                     semantic.Flow == VMFlowKind.ConditionalBranch ||
                     semantic.Flow == VMFlowKind.Leave) &&
                    (value < 0 || value >= instructions.Count))
                {
                    return false;
                }

                switch (opcode)
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
                        if (value < 0 || value >= instructions.Count)
                            return false;
                        break;
                }
            }

            return true;
        }

        public static string FormatSummary(GlobalStackSolverResult result)
        {
            var sb = new StringBuilder();
            sb.AppendLine("Global stack-constraint solving");

            var exhaustive = result.Methods.Count(m => m.Exhaustive);
            sb.AppendLine($"  methods considered : {result.Methods.Count}");
            sb.AppendLine($"  exhaustive searches: {exhaustive}");
            sb.AppendLine($"  contradictions     : {result.Contradictions.Count}");
            sb.AppendLine();

            foreach (var m in result.Methods)
            {
                sb.AppendLine($"  method {m.Method} ({m.Instructions} instr, {m.DistinctBytes} distinct bytes)");
                sb.AppendLine($"    search space     : {(m.SearchSpace == long.MaxValue ? "overflow" : m.SearchSpace.ToString())}");
                sb.AppendLine($"    nodes explored   : {m.NodesExplored}");
                sb.AppendLine($"    branches pruned  : {m.BranchesPruned}");
                sb.AppendLine($"    feasible found   : {m.FeasibleAssignments}");
                sb.AppendLine($"    exhaustive       : {(m.Exhaustive ? "YES" : "NO - results not used")}");
                sb.AppendLine($"    stop reason      : {m.StopReason}");
                if (m.CandidateCounts.Count > 0)
                {
                    var counts = string.Join(", ", m.CandidateCounts.OrderBy(p => p.Key)
                        .Select(p => $"0x{p.Key:X2} {p.Value.before}->{p.Value.after}"));
                    sb.AppendLine($"    candidates in/out: {counts}");
                }

                if (m.BecameSingleton.Count > 0)
                {
                    sb.AppendLine("    became singleton : " +
                                  string.Join(", ", m.BecameSingleton.Select(b => $"0x{b:X2}")));
                }
            }

            sb.AppendLine();
            foreach (var pair in result.Bytes.OrderBy(p => p.Key))
            {
                var r = pair.Value;
                sb.AppendLine($"  VM 0x{r.VmByte:X2}  [{r.Status.ToString().ToUpperInvariant()}]");
                sb.AppendLine($"    initial   : {r.Initial.Count} candidate(s)");
                sb.AppendLine($"    remaining : {string.Join(", ", r.Surviving.OrderBy(q => q.ToString()))}");
                foreach (var elimination in r.Eliminations)
                    sb.AppendLine($"    eliminated {elimination}");
            }

            foreach (var contradiction in result.Contradictions)
                sb.AppendLine($"  [contradiction] {contradiction}");

            return sb.ToString().TrimEnd();
        }
    }
}
