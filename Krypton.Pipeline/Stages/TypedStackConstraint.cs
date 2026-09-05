using System;
using System.Collections.Generic;
using AsmResolver.DotNet;
using AsmResolver.DotNet.Signatures.Types;
using Krypton.Core;
using Krypton.Core.Architecture;

namespace Krypton.Pipeline.Stages
{
    // Stack *depth* consistency cannot tell Ldtoken from Newarr: both carry a type
    // token and both leave one value behind. What separates them is the type of
    // that value, and metadata states it without reference to the opcode table --
    // a call signature says its first argument is an Array, so whatever produced
    // that slot cannot have been the instruction that pushes a RuntimeTypeHandle.
    //
    // This walks a method under a candidate assignment with an abstract type on
    // every stack slot and reports a violation only when a slot definitely cannot
    // satisfy the requirement at its consumer. Everything unknown stays permissive:
    // the result is used to refute assignments, so a false refutation would remove
    // the true answer, while a missed one only leaves the search wider.
    internal static class TypedStackConstraint
    {
        // Requirement-only kinds. Classify never produces these, so the shared
        // lattice used by the anchoring engine is untouched.
        private const StackTypeKind AnyNumeric = (StackTypeKind) 100;
        private const StackTypeKind ValueTypeKind = (StackTypeKind) 101;

        private static readonly StackTypeKind[] NoKinds = Array.Empty<StackTypeKind>();

        public static bool IsTypeConsistent(
            DevirtualizationCtx ctx,
            VMMethod method,
            IReadOnlyDictionary<int, VMOpCode> assignment,
            out string reason,
            out int failureIndex)
        {
            reason = null;
            failureIndex = -1;

            var instructions = method?.MethodBody?.Instructions;
            if (ctx?.Module == null || instructions == null || instructions.Count == 0)
                return true;

            var states = new StackTypeKind[instructions.Count][];
            var queue = new Queue<(int index, StackTypeKind[] stack)>();
            queue.Enqueue((0, NoKinds));

            foreach (var handler in method.MethodBody.ExceptionHandlers)
            {
                if (handler == null)
                    continue;
                if (handler.HandlerStart >= 0 && handler.HandlerStart < instructions.Count)
                {
                    var entry = handler.EHType == VMExceptionHandlerType.Finally ||
                                handler.EHType == VMExceptionHandlerType.Fault
                        ? NoKinds
                        : new[] { StackTypeKind.ObjectRef };
                    queue.Enqueue((handler.HandlerStart, entry));
                }

                if (handler.EHType == VMExceptionHandlerType.Filter &&
                    handler.Filter >= 0 && handler.Filter < instructions.Count)
                {
                    queue.Enqueue((handler.Filter, new[] { StackTypeKind.ObjectRef }));
                }
            }

            var budget = Math.Max(64, instructions.Count * 8);
            while (queue.Count > 0)
            {
                if (--budget < 0)
                    return true;

                var (index, incoming) = queue.Dequeue();
                if (index < 0 || index >= instructions.Count)
                    continue;

                var merged = Merge(states[index], incoming, out var changed);
                if (merged == null)
                    return true; // depth disagreement: not this pass's verdict
                if (states[index] != null && !changed)
                    continue;
                states[index] = merged;

                var instruction = instructions[index];
                if (instruction == null ||
                    !assignment.TryGetValue(instruction.VmByte, out var opcode))
                {
                    continue;
                }

                if (!GlobalStackConstraintSolver.TryGetEffect(
                        ctx, opcode, instruction.Operand, out var pop, out var push, out var flow))
                {
                    continue;
                }

                if (pop > merged.Length)
                    return true; // underflow is the depth pass's verdict

                var required = RequiredKinds(ctx, method, opcode, instruction.Operand, pop);
                for (var slot = 0; slot < pop; slot++)
                {
                    // required is bottom-to-top over the popped window.
                    var actual = merged[merged.Length - pop + slot];
                    var want = slot < required.Length ? required[slot] : StackTypeKind.Unknown;
                    if (Satisfies(actual, want))
                        continue;

                    reason = $"{opcode} wants {Describe(want)} in argument slot {slot} but the stack holds {Describe(actual)}";
                    failureIndex = index;
                    return false;
                }

                var top = merged.Length > 0 ? merged[merged.Length - 1] : StackTypeKind.Unknown;
                var produced = ProducedKinds(ctx, method, opcode, instruction.Operand, push, top);

                var next = new StackTypeKind[merged.Length - pop + push];
                Array.Copy(merged, next, merged.Length - pop);
                for (var slot = 0; slot < push; slot++)
                {
                    next[merged.Length - pop + slot] =
                        slot < produced.Length ? produced[slot] : StackTypeKind.Unknown;
                }

                switch (flow)
                {
                    case GlobalStackConstraintSolver.FlowKind.Return:
                    {
                        // The depth pass already knows a non-void method returns one
                        // value; what it never checks is that the value has the
                        // declared type. Ret models no pop, so the check belongs
                        // here rather than in the popped-argument loop.
                        var declared = Refine(method?.Parent?.Signature?.ReturnType);
                        if (declared != StackTypeKind.Unknown && next.Length > 0)
                        {
                            var returned = next[next.Length - 1];
                            if (!Satisfies(returned, declared))
                            {
                                reason = $"the method returns {Describe(declared)} but Ret leaves {Describe(returned)} on the stack";
                                failureIndex = index;
                                return false;
                            }
                        }

                        break;
                    }

                    case GlobalStackConstraintSolver.FlowKind.EndFinally:
                    case GlobalStackConstraintSolver.FlowKind.Throw:
                        break;

                    case GlobalStackConstraintSolver.FlowKind.Leave:
                        if (instruction.Operand is int leaveTarget)
                            queue.Enqueue((leaveTarget, NoKinds));
                        break;

                    case GlobalStackConstraintSolver.FlowKind.Unconditional:
                        if (instruction.Operand is int target)
                            queue.Enqueue((target, next));
                        break;

                    case GlobalStackConstraintSolver.FlowKind.Conditional:
                        if (instruction.Operand is int conditional)
                            queue.Enqueue((conditional, next));
                        if (index + 1 < instructions.Count)
                            queue.Enqueue((index + 1, next));
                        break;

                    case GlobalStackConstraintSolver.FlowKind.Switch:
                        if (instruction.Operand is int[] targets)
                        {
                            foreach (var switchTarget in targets)
                                queue.Enqueue((switchTarget, next));
                        }

                        if (index + 1 < instructions.Count)
                            queue.Enqueue((index + 1, next));
                        break;

                    default:
                        if (index + 1 < instructions.Count)
                            queue.Enqueue((index + 1, next));
                        break;
                }
            }

            return true;
        }

        // Widening merge: a slot that arrives with two different kinds is simply
        // unknown from here on. Returns null when the two paths disagree on depth,
        // which this pass deliberately does not judge.
        private static StackTypeKind[] Merge(StackTypeKind[] existing, StackTypeKind[] incoming, out bool changed)
        {
            changed = false;
            if (existing == null)
            {
                changed = true;
                return incoming;
            }

            if (existing.Length != incoming.Length)
                return null;

            StackTypeKind[] result = null;
            for (var i = 0; i < existing.Length; i++)
            {
                if (existing[i] == incoming[i])
                    continue;
                if (result == null)
                    result = (StackTypeKind[]) existing.Clone();
                result[i] = StackTypeKind.Unknown;
                changed = true;
            }

            return result ?? existing;
        }

        private static bool Satisfies(StackTypeKind actual, StackTypeKind required)
        {
            if (required == StackTypeKind.Unknown || actual == StackTypeKind.Unknown)
                return true;

            // A managed pointer or a native-sized integer is compatible with too
            // many things in verifiable IL to refute anything with.
            if (actual == StackTypeKind.ManagedPointer || required == StackTypeKind.ManagedPointer)
                return true;

            if (required == AnyNumeric)
            {
                return actual == StackTypeKind.Int32 ||
                       actual == StackTypeKind.Int64 ||
                       actual == StackTypeKind.Float;
            }

            if (required == ValueTypeKind)
                return actual == ValueTypeKind;

            if (actual == ValueTypeKind)
                return false;

            if (actual == required)
                return true;

            if (required == StackTypeKind.ObjectRef)
            {
                return actual == StackTypeKind.String ||
                       actual == StackTypeKind.Array ||
                       actual == StackTypeKind.ObjectRef;
            }

            // Array satisfies a System.Array-shaped requirement, which Classify
            // reports as ObjectRef, and both directions of int widening are left
            // to the depth pass rather than refuted here.
            if (required == StackTypeKind.Int32 || required == StackTypeKind.Int64)
                return actual == StackTypeKind.Int32 || actual == StackTypeKind.Int64;

            return false;
        }

        private static string Describe(StackTypeKind kind)
        {
            if (kind == AnyNumeric)
                return "a number";
            if (kind == ValueTypeKind)
                return "a value type";
            return kind.ToString();
        }

        private static StackTypeKind Refine(TypeSignature signature)
        {
            var kind = TypeConstraintAnchoring.Classify(signature);
            if (kind != StackTypeKind.Unknown || signature == null)
                return kind;
            return IsRefutableValueType(signature) ? ValueTypeKind : StackTypeKind.Unknown;
        }

        private static StackTypeKind RefineDescriptor(ITypeDescriptor descriptor)
        {
            if (descriptor == null)
                return StackTypeKind.Unknown;
            var kind = TypeConstraintAnchoring.ClassifyDescriptor(descriptor);
            if (kind != StackTypeKind.Unknown)
                return kind;
            try
            {
                return Refine(descriptor.ToTypeSignature());
            }
            catch
            {
                return StackTypeKind.Unknown;
            }
        }

        // Only structs whose values genuinely cannot stand in for a reference are
        // useful here. The native-integer types are excluded because verifiable IL
        // does let an int32 flow into them.
        private static bool IsRefutableValueType(TypeSignature signature)
        {
            var name = signature.FullName;
            if (string.Equals(name, "System.IntPtr", StringComparison.Ordinal) ||
                string.Equals(name, "System.UIntPtr", StringComparison.Ordinal))
            {
                return false;
            }

            try
            {
                var resolved = signature.Resolve();
                return resolved != null && resolved.IsValueType && !resolved.IsEnum;
            }
            catch
            {
                return false;
            }
        }

        private static StackTypeKind ArgumentKind(VMMethod method, object operand)
        {
            if (!(operand is int index) || method?.Parent == null)
                return StackTypeKind.Unknown;

            var signature = method.Parent.Signature;
            if (signature == null)
                return StackTypeKind.Unknown;

            if (!method.Parent.IsStatic)
            {
                if (index == 0)
                    return RefineDescriptor(method.Parent.DeclaringType);
                index--;
            }

            return index >= 0 && index < signature.ParameterTypes.Count
                ? Refine(signature.ParameterTypes[index])
                : StackTypeKind.Unknown;
        }

        private static StackTypeKind LocalKind(VMMethod method, object operand)
        {
            var locals = method?.MethodBody?.Locals;
            if (!(operand is int index) || locals == null || index < 0 || index >= locals.Count)
                return StackTypeKind.Unknown;
            return RefineDescriptor(locals[index]);
        }

        private static StackTypeKind[] RequiredKinds(
            DevirtualizationCtx ctx,
            VMMethod method,
            VMOpCode opcode,
            object operand,
            int pop)
        {
            if (pop <= 0)
                return NoKinds;

            switch (opcode)
            {
                case VMOpCode.Call:
                case VMOpCode.Callvirt:
                case VMOpCode.Newobj:
                {
                    if (!(TypeConstraintAnchoring.Lookup(ctx, operand as int? ?? 0) is IMethodDescriptor descriptor) ||
                        descriptor.Signature == null)
                    {
                        return NoKinds;
                    }

                    var signature = descriptor.Signature;
                    var kinds = new List<StackTypeKind>();
                    if (opcode != VMOpCode.Newobj && signature.HasThis)
                    {
                        kinds.Add(TypeConstraintAnchoring.IsValueTypeDeclaring(descriptor)
                            ? StackTypeKind.Unknown
                            : StackTypeKind.ObjectRef);
                    }

                    foreach (var parameter in signature.ParameterTypes)
                        kinds.Add(Refine(parameter));
                    return kinds.ToArray();
                }

                case VMOpCode.Stloc:
                    return new[] { LocalKind(method, operand) };
                case VMOpCode.Starg:
                    return new[] { ArgumentKind(method, operand) };

                case VMOpCode.Stsfld:
                    return new[] { FieldKind(ctx, operand) };
                case VMOpCode.Stfld:
                    return new[] { StackTypeKind.Unknown, FieldKind(ctx, operand) };
                case VMOpCode.Ldfld:
                case VMOpCode.Ldflda:
                    return new[] { StackTypeKind.Unknown };

                case VMOpCode.Newarr:
                    return new[] { StackTypeKind.Int32 };
                case VMOpCode.Ldlen:
                    return new[] { StackTypeKind.Array };

                case VMOpCode.Stelem_Ref:
                    return new[] { StackTypeKind.Array, StackTypeKind.Int32, StackTypeKind.ObjectRef };
                case VMOpCode.Stelem_I:
                case VMOpCode.Stelem_I1:
                case VMOpCode.Stelem_I2:
                case VMOpCode.Stelem_I4:
                case VMOpCode.Stelem_I8:
                case VMOpCode.Stelem_R4:
                case VMOpCode.Stelem_R8:
                    return new[] { StackTypeKind.Array, StackTypeKind.Int32, AnyNumeric };
                case VMOpCode.Stelem:
                    return new[] { StackTypeKind.Array, StackTypeKind.Int32, TypeOperandKind(ctx, operand) };

                case VMOpCode.Ldelem:
                case VMOpCode.Ldelema:
                case VMOpCode.Ldelem_Ref:
                case VMOpCode.Ldelem_I:
                case VMOpCode.Ldelem_I1:
                case VMOpCode.Ldelem_I2:
                case VMOpCode.Ldelem_I4:
                case VMOpCode.Ldelem_I8:
                case VMOpCode.Ldelem_U1:
                case VMOpCode.Ldelem_U2:
                case VMOpCode.Ldelem_U4:
                case VMOpCode.Ldelem_R4:
                case VMOpCode.Ldelem_R8:
                    return new[] { StackTypeKind.Array, StackTypeKind.Int32 };

                case VMOpCode.Unbox:
                case VMOpCode.Unbox_Any:
                case VMOpCode.Isinst:
                case VMOpCode.Castclass:
                    return new[] { StackTypeKind.ObjectRef };

                case VMOpCode.Throw:
                    return new[] { StackTypeKind.ObjectRef };

                case VMOpCode.Ret:
                    return new[] { Refine(method?.Parent?.Signature?.ReturnType) };

                case VMOpCode.Switch:
                    return new[] { StackTypeKind.Int32 };

                case VMOpCode.Neg:
                case VMOpCode.Not:
                    return new[] { AnyNumeric };
            }

            if (VMOpCodeCatalog.IsConversion(opcode))
                return new[] { AnyNumeric };

            if (VMOpCodeCatalog.IsArithmetic(opcode))
            {
                return pop >= 2
                    ? new[] { AnyNumeric, AnyNumeric }
                    : new[] { AnyNumeric };
            }

            return NoKinds;
        }

        private static StackTypeKind[] ProducedKinds(
            DevirtualizationCtx ctx,
            VMMethod method,
            VMOpCode opcode,
            object operand,
            int push,
            StackTypeKind top)
        {
            if (push <= 0)
                return NoKinds;

            switch (opcode)
            {
                case VMOpCode.Dup:
                    return new[] { top, top };

                case VMOpCode.Call:
                case VMOpCode.Callvirt:
                {
                    if (TypeConstraintAnchoring.Lookup(ctx, operand as int? ?? 0) is IMethodDescriptor descriptor &&
                        descriptor.Signature != null)
                    {
                        return new[] { Refine(descriptor.Signature.ReturnType) };
                    }

                    return NoKinds;
                }

                case VMOpCode.Newobj:
                {
                    if (TypeConstraintAnchoring.Lookup(ctx, operand as int? ?? 0) is IMethodDescriptor descriptor)
                        return new[] { RefineDescriptor(descriptor.DeclaringType) };
                    return NoKinds;
                }

                case VMOpCode.Ldtoken:
                    // MethodRecompiling lowers an ldtoken whose operand resolves to
                    // nothing as the plain Ldc_I4 constant it really is, so that is
                    // the type this slot actually carries.
                    return new[]
                    {
                        TypeConstraintAnchoring.Lookup(ctx, operand as int? ?? 0) == null
                            ? StackTypeKind.Int32
                            : ValueTypeKind
                    };

                case VMOpCode.Ldarg:
                    return new[] { ArgumentKind(method, operand) };
                case VMOpCode.Ldloc:
                    return new[] { LocalKind(method, operand) };
                case VMOpCode.Ldsfld:
                case VMOpCode.Ldfld:
                    return new[] { FieldKind(ctx, operand) };

                case VMOpCode.Newarr:
                    return new[] { StackTypeKind.Array };

                case VMOpCode.Unbox_Any:
                case VMOpCode.Ldobj:
                case VMOpCode.Isinst:
                case VMOpCode.Castclass:
                case VMOpCode.Ldelem:
                    return new[] { TypeOperandKind(ctx, operand) };

                case VMOpCode.Ldnull:
                    return new[] { StackTypeKind.Unknown };

                // TypedReference and the runtime handles are structs: they satisfy a
                // struct-shaped requirement and nothing else, which is what separates
                // them from the reference-producing opcodes of the same shape.
                case VMOpCode.Mkrefany:
                case VMOpCode.Refanytype:
                    return new[] { ValueTypeKind };
            }

            if (VMOpCodeCatalog.IsArithmetic(opcode))
                return new[] { top == StackTypeKind.Float ? StackTypeKind.Float : StackTypeKind.Unknown };

            var declared = DeclaredProduction(opcode);
            return new[] { declared };
        }

        private static StackTypeKind FieldKind(DevirtualizationCtx ctx, object operand)
        {
            return TypeConstraintAnchoring.Lookup(ctx, operand as int? ?? 0) is IFieldDescriptor field
                ? Refine(field.Signature?.FieldType)
                : StackTypeKind.Unknown;
        }

        private static StackTypeKind TypeOperandKind(DevirtualizationCtx ctx, object operand)
        {
            return TypeConstraintAnchoring.Lookup(ctx, operand as int? ?? 0) is ITypeDescriptor type
                ? RefineDescriptor(type)
                : StackTypeKind.Unknown;
        }

        // Kinds an opcode produces without consulting its operand. Kept separate
        // from the anchoring engine's table because Ldtoken is a value type here
        // and merely unknown there.
        private static StackTypeKind DeclaredProduction(VMOpCode opcode)
        {
            switch (opcode)
            {
                case VMOpCode.Ldstr:
                    return StackTypeKind.String;
                case VMOpCode.Ldc_I4:
                case VMOpCode.Ldlen:
                case VMOpCode.Sizeof:
                case VMOpCode.Ceq:
                case VMOpCode.Cgt:
                case VMOpCode.Cgt_Un:
                case VMOpCode.Clt:
                case VMOpCode.Clt_Un:
                case VMOpCode.Ldelem_I1:
                case VMOpCode.Ldelem_I2:
                case VMOpCode.Ldelem_I4:
                case VMOpCode.Ldelem_U1:
                case VMOpCode.Ldelem_U2:
                case VMOpCode.Ldelem_U4:
                    return StackTypeKind.Int32;
                case VMOpCode.Ldc_I8:
                case VMOpCode.Ldelem_I8:
                    return StackTypeKind.Int64;
                case VMOpCode.Ldc_R4:
                case VMOpCode.Ldc_R8:
                case VMOpCode.Ldelem_R4:
                case VMOpCode.Ldelem_R8:
                    return StackTypeKind.Float;
                case VMOpCode.Ldloca:
                case VMOpCode.Ldarga:
                case VMOpCode.Ldsflda:
                case VMOpCode.Ldflda:
                case VMOpCode.Ldelema:
                case VMOpCode.Unbox:
                case VMOpCode.Localloc:
                case VMOpCode.Refanyval:
                    return StackTypeKind.ManagedPointer;
                case VMOpCode.Box:
                case VMOpCode.Ldelem_Ref:
                    return StackTypeKind.ObjectRef;
            }

            if (VMOpCodeCatalog.IsConversion(opcode))
            {
                var name = opcode.ToString();
                if (name.EndsWith("I8", StringComparison.Ordinal) || name.EndsWith("U8", StringComparison.Ordinal))
                    return StackTypeKind.Int64;
                if (name.EndsWith("R4", StringComparison.Ordinal) ||
                    name.EndsWith("R8", StringComparison.Ordinal) ||
                    name.EndsWith("R_Un", StringComparison.Ordinal))
                {
                    return StackTypeKind.Float;
                }

                if (name.EndsWith("I", StringComparison.Ordinal) ||
                    name.EndsWith("U", StringComparison.Ordinal) ||
                    name.EndsWith("I_Un", StringComparison.Ordinal) ||
                    name.EndsWith("U_Un", StringComparison.Ordinal))
                {
                    return StackTypeKind.Unknown; // native int
                }

                return StackTypeKind.Int32;
            }

            return StackTypeKind.Unknown;
        }
    }
}
