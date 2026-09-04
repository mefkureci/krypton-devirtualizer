using System;
using System.Collections.Generic;
using Krypton.Core;
using Krypton.Core.Architecture;

namespace Krypton.Pipeline.Stages
{
    public sealed partial class SemanticValidation
    {
        // The semantic retune loops score a candidate mapping by how many CIL issues the
        // recompiled bodies still have. That objective has a degenerate optimum: mapping a
        // byte to a terminal opcode (Ret/Throw/EndFinally) makes everything after it
        // unreachable, the recompiler drops it, and the issue count collapses -- a method
        // "verifies" because almost none of it survived. Reactor tables regularly have
        // several such bytes, so the loops could reach "0 issues" by deleting the program.
        //
        // Counting reachable VM instructions makes the objective honest: instructions lost
        // to a candidate are added back as issues, so truncation can no longer win on score
        // alone while a genuinely better opcode still can.
        internal static int CountReachableVmInstructions(
            DevirtualizationCtx ctx,
            VMMethod method,
            IDictionary<int, VMOpCode> substitutions = null)
        {
            var instructions = method?.MethodBody?.Instructions;
            if (ctx?.PatternMatcher == null || instructions == null || instructions.Count == 0)
                return 0;

            var visited = new bool[instructions.Count];
            var pending = new Stack<int>();

            void Enqueue(int index)
            {
                if (index < 0 || index >= instructions.Count || visited[index])
                    return;
                visited[index] = true;
                pending.Push(index);
            }

            Enqueue(0);
            if (method.MethodBody.ExceptionHandlers != null)
            {
                foreach (var handler in method.MethodBody.ExceptionHandlers)
                {
                    Enqueue(handler.HandlerStart);
                    if (handler.EHType == VMExceptionHandlerType.Filter)
                        Enqueue(handler.Filter);
                }
            }

            var reached = 0;
            while (pending.Count > 0)
            {
                var index = pending.Pop();
                reached++;

                var instruction = instructions[index];
                var fallThrough = index + 1;

                VMOpCode opCode;
                if (substitutions != null && substitutions.TryGetValue(instruction.VmByte, out var substituted))
                    opCode = substituted;
                else if (ctx.PatternMatcher.IsOpCodeValueKnown(instruction.VmByte))
                    opCode = ctx.PatternMatcher.GetOpCodeValue(instruction.VmByte);
                else
                {
                    Enqueue(fallThrough);
                    continue;
                }

                if (!VMOpCodeCatalog.TryGet(opCode, out var descriptor))
                {
                    Enqueue(fallThrough);
                    continue;
                }

                switch (descriptor.Flow)
                {
                    case VMFlowKind.Return:
                    case VMFlowKind.Throw:
                    case VMFlowKind.Rethrow:
                    case VMFlowKind.EndFinally:
                        break;

                    case VMFlowKind.UnconditionalBranch:
                    case VMFlowKind.Leave:
                        if (instruction.Operand is int unconditionalTarget)
                            Enqueue(unconditionalTarget);
                        break;

                    case VMFlowKind.ConditionalBranch:
                        if (instruction.Operand is int conditionalTarget)
                            Enqueue(conditionalTarget);
                        Enqueue(fallThrough);
                        break;

                    case VMFlowKind.Switch:
                        if (instruction.Operand is int[] switchTargets)
                        {
                            foreach (var target in switchTargets)
                                Enqueue(target);
                        }

                        Enqueue(fallThrough);
                        break;

                    default:
                        Enqueue(fallThrough);
                        break;
                }
            }

            return reached;
        }

        internal static int CountReachableVmInstructions(
            DevirtualizationCtx ctx,
            IDictionary<int, VMOpCode> substitutions = null)
        {
            if (ctx?.VirtualizedMethods == null)
                return 0;

            var total = 0;
            foreach (var method in ctx.VirtualizedMethods)
                total += CountReachableVmInstructions(ctx, method, substitutions);

            return total;
        }

        internal static int CountTotalVmInstructions(DevirtualizationCtx ctx)
        {
            if (ctx?.VirtualizedMethods == null)
                return 0;

            var total = 0;
            foreach (var method in ctx.VirtualizedMethods)
                total += method?.MethodBody?.Instructions?.Count ?? 0;

            return total;
        }

        // Scoring a state as "issues + instructions the mapping cannot reach" keeps both
        // directions honest on one absolute scale: truncating a method no longer looks like
        // a fix, and restoring code that a previous truncation hid is allowed to pay for
        // itself with the issues it brings back. Instructions the obfuscator left genuinely
        // dead are unreachable in every state, so they only add a constant.
        internal static int ScoreState(
            DevirtualizationCtx ctx,
            int issues,
            int totalVmInstructions,
            IDictionary<int, VMOpCode> substitutions = null) =>
            issues + Math.Max(0, totalVmInstructions - CountReachableVmInstructions(ctx, substitutions));
    }
}
