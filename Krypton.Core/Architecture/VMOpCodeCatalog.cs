using System;
using System.Collections.Generic;
using System.Linq;
using AsmResolver.PE.DotNet.Cil;

namespace Krypton.Core.Architecture
{
    [Flags]
    public enum VMOperandEncoding
    {
        None = 1 << 0,
        Int32 = 1 << 1,
        Int64 = 1 << 2,
        Float32 = 1 << 3,
        Float64 = 1 << 4,
        Switch = 1 << 5
    }

    public enum VMMetadataTokenKind { None, Any, String, Method, Field, Type }

    public enum VMFlowKind
    {
        Next,
        UnconditionalBranch,
        ConditionalBranch,
        Switch,
        Return,
        Throw,
        Rethrow,
        Leave,
        EndFinally,
        Prefix
    }

    public sealed class VMOpCodeDescriptor
    {
        internal VMOpCodeDescriptor(
            VMOpCode opCode, CilOpCode cilOpCode, VMOperandEncoding encodings,
            int pop, int push, VMFlowKind flow, VMMetadataTokenKind tokenKind)
        {
            OpCode = opCode;
            CilOpCode = cilOpCode;
            Encodings = encodings;
            Pop = pop;
            Push = push;
            Flow = flow;
            TokenKind = tokenKind;
        }

        public VMOpCode OpCode { get; }
        public CilOpCode CilOpCode { get; }
        public VMOperandEncoding Encodings { get; }
        public int Pop { get; }
        public int Push { get; }
        public VMFlowKind Flow { get; }
        public VMMetadataTokenKind TokenKind { get; }
        public bool HasFixedStackEffect => Pop >= 0 && Push >= 0;
        public bool IsTerminal => Flow == VMFlowKind.Return || Flow == VMFlowKind.Throw ||
                                  Flow == VMFlowKind.Rethrow || Flow == VMFlowKind.EndFinally;

        public bool SupportsOperandType(byte operandType) =>
            operandType <= 5 && (Encodings & (VMOperandEncoding) (1 << operandType)) != 0;
    }

    // Structural source of truth for the six operand encodings carried by this
    // Reactor VM record format. Membership never depends on a concrete VM byte.
    public static class VMOpCodeCatalog
    {
        private const int Variable = -1;
        private static readonly IReadOnlyDictionary<VMOpCode, VMOpCodeDescriptor> Entries = Build();

        public static IReadOnlyCollection<VMOpCode> CandidateUniverse { get; } =
            Array.AsReadOnly(Enum.GetValues(typeof(VMOpCode)).Cast<VMOpCode>()
                .Where(Entries.ContainsKey).ToArray());

        public static VMOpCodeDescriptor Get(VMOpCode opCode) => Entries[opCode];
        public static bool TryGet(VMOpCode opCode, out VMOpCodeDescriptor descriptor) =>
            Entries.TryGetValue(opCode, out descriptor);
        public static IEnumerable<VMOpCode> GetCandidates(byte operandType) =>
            CandidateUniverse.Where(op => Entries[op].SupportsOperandType(operandType));

        public static bool IsConversion(VMOpCode opCode) =>
            opCode.ToString().StartsWith("Conv_", StringComparison.Ordinal);

        public static bool IsArithmetic(VMOpCode opCode)
        {
            var name = opCode.ToString();
            return name == "And" || name == "Or" || name == "Xor" ||
                   name == "Shl" || name.StartsWith("Shr", StringComparison.Ordinal) ||
                   name == "Neg" || name == "Not" ||
                   name.StartsWith("Add", StringComparison.Ordinal) ||
                   name.StartsWith("Sub", StringComparison.Ordinal) ||
                   name.StartsWith("Mul", StringComparison.Ordinal) ||
                   name.StartsWith("Div", StringComparison.Ordinal) ||
                   name.StartsWith("Rem", StringComparison.Ordinal);
        }

        private static IReadOnlyDictionary<VMOpCode, VMOpCodeDescriptor> Build()
        {
            var r = new Dictionary<VMOpCode, VMOpCodeDescriptor>();
            void A(VMOpCode vm, CilOpCode cil, VMOperandEncoding enc, int pop, int push,
                VMFlowKind flow = VMFlowKind.Next, VMMetadataTokenKind token = VMMetadataTokenKind.None) =>
                r.Add(vm, new VMOpCodeDescriptor(vm, cil, enc, pop, push, flow, token));
            void C(VMOpCode vm, CilOpCode cil) => A(vm, cil, VMOperandEncoding.None, 1, 1);

            var n = VMOperandEncoding.None;
            var i = VMOperandEncoding.Int32;
            var type = VMMetadataTokenKind.Type;

            A(VMOpCode.Nop, CilOpCodes.Nop, n, 0, 0);
            A(VMOpCode.Pop, CilOpCodes.Pop, n, 1, 0);
            A(VMOpCode.Dup, CilOpCodes.Dup, n, 1, 2);
            A(VMOpCode.Ldnull, CilOpCodes.Ldnull, n, 0, 1);
            A(VMOpCode.Ldc_I4, CilOpCodes.Ldc_I4, i, 0, 1);
            A(VMOpCode.Ldc_I8, CilOpCodes.Ldc_I8, VMOperandEncoding.Int64, 0, 1);
            A(VMOpCode.Ldc_R4, CilOpCodes.Ldc_R4, VMOperandEncoding.Float32, 0, 1);
            A(VMOpCode.Ldc_R8, CilOpCodes.Ldc_R8, VMOperandEncoding.Float64, 0, 1);
            A(VMOpCode.Ldstr, CilOpCodes.Ldstr, i, 0, 1, token: VMMetadataTokenKind.String);

            A(VMOpCode.Call, CilOpCodes.Call, i, Variable, Variable, token: VMMetadataTokenKind.Method);
            A(VMOpCode.Callvirt, CilOpCodes.Callvirt, i, Variable, Variable, token: VMMetadataTokenKind.Method);
            A(VMOpCode.Newobj, CilOpCodes.Newobj, i, Variable, 1, token: VMMetadataTokenKind.Method);

            A(VMOpCode.Br, CilOpCodes.Br, i, 0, 0, VMFlowKind.UnconditionalBranch);
            A(VMOpCode.BrTrue, CilOpCodes.Brtrue, i, 1, 0, VMFlowKind.ConditionalBranch);
            A(VMOpCode.BrFalse, CilOpCodes.Brfalse, i, 1, 0, VMFlowKind.ConditionalBranch);
            A(VMOpCode.BrLessThan, CilOpCodes.Blt, i, 2, 0, VMFlowKind.ConditionalBranch);
            A(VMOpCode.BrGreaterThan, CilOpCodes.Bgt, i, 2, 0, VMFlowKind.ConditionalBranch);
            A(VMOpCode.BrLessOrEqual, CilOpCodes.Ble, i, 2, 0, VMFlowKind.ConditionalBranch);
            A(VMOpCode.BrGreaterOrEqual, CilOpCodes.Bge, i, 2, 0, VMFlowKind.ConditionalBranch);
            A(VMOpCode.BrEqual, CilOpCodes.Beq, i, 2, 0, VMFlowKind.ConditionalBranch);
            A(VMOpCode.BrNotEqual, CilOpCodes.Bne_Un, i, 2, 0, VMFlowKind.ConditionalBranch);
            A(VMOpCode.BrLessThan_Un, CilOpCodes.Blt_Un, i, 2, 0, VMFlowKind.ConditionalBranch);
            A(VMOpCode.BrGreaterThan_Un, CilOpCodes.Bgt_Un, i, 2, 0, VMFlowKind.ConditionalBranch);
            A(VMOpCode.BrLessOrEqual_Un, CilOpCodes.Ble_Un, i, 2, 0, VMFlowKind.ConditionalBranch);
            A(VMOpCode.BrGreaterOrEqual_Un, CilOpCodes.Bge_Un, i, 2, 0, VMFlowKind.ConditionalBranch);
            A(VMOpCode.Switch, CilOpCodes.Switch, VMOperandEncoding.Switch, 1, 0, VMFlowKind.Switch);
            A(VMOpCode.Leave, CilOpCodes.Leave, n | i, 0, 0, VMFlowKind.Leave);
            A(VMOpCode.Ret, CilOpCodes.Ret, n, Variable, 0, VMFlowKind.Return);
            A(VMOpCode.Throw, CilOpCodes.Throw, n, 1, 0, VMFlowKind.Throw);
            A(VMOpCode.Rethrow, CilOpCodes.Rethrow, n, 0, 0, VMFlowKind.Rethrow);
            A(VMOpCode.EndFinally, CilOpCodes.Endfinally, n, 0, 0, VMFlowKind.EndFinally);

            A(VMOpCode.Ldloc, CilOpCodes.Ldloc, i, 0, 1);
            A(VMOpCode.Ldloca, CilOpCodes.Ldloca, i, 0, 1);
            A(VMOpCode.Stloc, CilOpCodes.Stloc, i, 1, 0);
            A(VMOpCode.Ldarg, CilOpCodes.Ldarg, i, 0, 1);
            A(VMOpCode.Ldarga, CilOpCodes.Ldarga, i, 0, 1);
            A(VMOpCode.Starg, CilOpCodes.Starg, i, 1, 0);

            A(VMOpCode.Ldfld, CilOpCodes.Ldfld, i, 1, 1, token: VMMetadataTokenKind.Field);
            A(VMOpCode.Ldflda, CilOpCodes.Ldflda, i, 1, 1, token: VMMetadataTokenKind.Field);
            A(VMOpCode.Stfld, CilOpCodes.Stfld, i, 2, 0, token: VMMetadataTokenKind.Field);
            A(VMOpCode.Ldsfld, CilOpCodes.Ldsfld, i, 0, 1, token: VMMetadataTokenKind.Field);
            A(VMOpCode.Ldsflda, CilOpCodes.Ldsflda, i, 0, 1, token: VMMetadataTokenKind.Field);
            A(VMOpCode.Stsfld, CilOpCodes.Stsfld, i, 1, 0, token: VMMetadataTokenKind.Field);

            A(VMOpCode.Box, CilOpCodes.Box, i, 1, 1, token: type);
            A(VMOpCode.Unbox, CilOpCodes.Unbox, i, 1, 1, token: type);
            A(VMOpCode.Unbox_Any, CilOpCodes.Unbox_Any, i, 1, 1, token: type);
            A(VMOpCode.Isinst, CilOpCodes.Isinst, i, 1, 1, token: type);
            A(VMOpCode.Castclass, CilOpCodes.Castclass, i, 1, 1, token: type);
            A(VMOpCode.Newarr, CilOpCodes.Newarr, i, 1, 1, token: type);
            A(VMOpCode.Ldtoken, CilOpCodes.Ldtoken, i, 0, 1, token: VMMetadataTokenKind.Any);
            A(VMOpCode.Ldobj, CilOpCodes.Ldobj, i, 1, 1, token: type);
            A(VMOpCode.Stobj, CilOpCodes.Stobj, i, 2, 0, token: type);
            A(VMOpCode.Ldelema, CilOpCodes.Ldelema, i, 2, 1, token: type);

            A(VMOpCode.Ldlen, CilOpCodes.Ldlen, n, 1, 1);
            A(VMOpCode.Ldelem_Ref, CilOpCodes.Ldelem_Ref, n, 2, 1);
            A(VMOpCode.Ldelem_I, CilOpCodes.Ldelem_I, n, 2, 1);
            A(VMOpCode.Ldelem_I1, CilOpCodes.Ldelem_I1, n, 2, 1);
            A(VMOpCode.Ldelem_I2, CilOpCodes.Ldelem_I2, n, 2, 1);
            A(VMOpCode.Ldelem_I4, CilOpCodes.Ldelem_I4, n, 2, 1);
            A(VMOpCode.Ldelem_I8, CilOpCodes.Ldelem_I8, n, 2, 1);
            A(VMOpCode.Ldelem_U1, CilOpCodes.Ldelem_U1, n, 2, 1);
            A(VMOpCode.Ldelem_U2, CilOpCodes.Ldelem_U2, n, 2, 1);
            A(VMOpCode.Ldelem_U4, CilOpCodes.Ldelem_U4, n, 2, 1);
            A(VMOpCode.Ldelem_R4, CilOpCodes.Ldelem_R4, n, 2, 1);
            A(VMOpCode.Ldelem_R8, CilOpCodes.Ldelem_R8, n, 2, 1);
            A(VMOpCode.Ldelem, CilOpCodes.Ldelem, i, 2, 1, token: type);
            A(VMOpCode.Stelem_Ref, CilOpCodes.Stelem_Ref, n, 3, 0);
            A(VMOpCode.Stelem_I1, CilOpCodes.Stelem_I1, n, 3, 0);
            A(VMOpCode.Stelem_I, CilOpCodes.Stelem_I, n, 3, 0);
            A(VMOpCode.Stelem_I2, CilOpCodes.Stelem_I2, n, 3, 0);
            A(VMOpCode.Stelem_I4, CilOpCodes.Stelem_I4, n, 3, 0);
            A(VMOpCode.Stelem_I8, CilOpCodes.Stelem_I8, n, 3, 0);
            A(VMOpCode.Stelem_R4, CilOpCodes.Stelem_R4, n, 3, 0);
            A(VMOpCode.Stelem_R8, CilOpCodes.Stelem_R8, n, 3, 0);
            A(VMOpCode.Stelem, CilOpCodes.Stelem, i, 3, 0, token: type);

            A(VMOpCode.Add, CilOpCodes.Add, n, 2, 1);
            A(VMOpCode.Add_Ovf, CilOpCodes.Add_Ovf, n, 2, 1);
            A(VMOpCode.Add_Ovf_Un, CilOpCodes.Add_Ovf_Un, n, 2, 1);
            A(VMOpCode.Sub, CilOpCodes.Sub, n, 2, 1);
            A(VMOpCode.Sub_Ovf, CilOpCodes.Sub_Ovf, n, 2, 1);
            A(VMOpCode.Sub_Ovf_Un, CilOpCodes.Sub_Ovf_Un, n, 2, 1);
            A(VMOpCode.Mul, CilOpCodes.Mul, n, 2, 1);
            A(VMOpCode.Mul_Ovf, CilOpCodes.Mul_Ovf, n, 2, 1);
            A(VMOpCode.Mul_Ovf_Un, CilOpCodes.Mul_Ovf_Un, n, 2, 1);
            A(VMOpCode.Div, CilOpCodes.Div, n, 2, 1);
            A(VMOpCode.Div_Un, CilOpCodes.Div_Un, n, 2, 1);
            A(VMOpCode.Rem, CilOpCodes.Rem, n, 2, 1);
            A(VMOpCode.Rem_Un, CilOpCodes.Rem_Un, n, 2, 1);
            A(VMOpCode.And, CilOpCodes.And, n, 2, 1);
            A(VMOpCode.Or, CilOpCodes.Or, n, 2, 1);
            A(VMOpCode.Xor, CilOpCodes.Xor, n, 2, 1);
            A(VMOpCode.Shl, CilOpCodes.Shl, n, 2, 1);
            A(VMOpCode.Shr, CilOpCodes.Shr, n, 2, 1);
            A(VMOpCode.Shr_Un, CilOpCodes.Shr_Un, n, 2, 1);
            A(VMOpCode.Neg, CilOpCodes.Neg, n, 1, 1);
            A(VMOpCode.Not, CilOpCodes.Not, n, 1, 1);
            A(VMOpCode.Ceq, CilOpCodes.Ceq, n, 2, 1);

            C(VMOpCode.Conv_I1, CilOpCodes.Conv_I1);
            C(VMOpCode.Conv_I2, CilOpCodes.Conv_I2);
            C(VMOpCode.Conv_I4, CilOpCodes.Conv_I4);
            C(VMOpCode.Conv_I8, CilOpCodes.Conv_I8);
            C(VMOpCode.Conv_U1, CilOpCodes.Conv_U1);
            C(VMOpCode.Conv_U2, CilOpCodes.Conv_U2);
            C(VMOpCode.Conv_U4, CilOpCodes.Conv_U4);
            C(VMOpCode.Conv_U8, CilOpCodes.Conv_U8);
            C(VMOpCode.Conv_I, CilOpCodes.Conv_I);
            C(VMOpCode.Conv_U, CilOpCodes.Conv_U);
            C(VMOpCode.Conv_R4, CilOpCodes.Conv_R4);
            C(VMOpCode.Conv_R8, CilOpCodes.Conv_R8);
            C(VMOpCode.Conv_R_Un, CilOpCodes.Conv_R_Un);
            C(VMOpCode.Conv_Ovf_I1, CilOpCodes.Conv_Ovf_I1);
            C(VMOpCode.Conv_Ovf_I1_Un, CilOpCodes.Conv_Ovf_I1_Un);
            C(VMOpCode.Conv_Ovf_I2, CilOpCodes.Conv_Ovf_I2);
            C(VMOpCode.Conv_Ovf_I2_Un, CilOpCodes.Conv_Ovf_I2_Un);
            C(VMOpCode.Conv_Ovf_I4, CilOpCodes.Conv_Ovf_I4);
            C(VMOpCode.Conv_Ovf_I4_Un, CilOpCodes.Conv_Ovf_I4_Un);
            C(VMOpCode.Conv_Ovf_I8, CilOpCodes.Conv_Ovf_I8);
            C(VMOpCode.Conv_Ovf_I8_Un, CilOpCodes.Conv_Ovf_I8_Un);
            C(VMOpCode.Conv_Ovf_U1, CilOpCodes.Conv_Ovf_U1);
            C(VMOpCode.Conv_Ovf_U1_Un, CilOpCodes.Conv_Ovf_U1_Un);
            C(VMOpCode.Conv_Ovf_U2, CilOpCodes.Conv_Ovf_U2);
            C(VMOpCode.Conv_Ovf_U2_Un, CilOpCodes.Conv_Ovf_U2_Un);
            C(VMOpCode.Conv_Ovf_U4, CilOpCodes.Conv_Ovf_U4);
            C(VMOpCode.Conv_Ovf_U4_Un, CilOpCodes.Conv_Ovf_U4_Un);
            C(VMOpCode.Conv_Ovf_U8, CilOpCodes.Conv_Ovf_U8);
            C(VMOpCode.Conv_Ovf_U8_Un, CilOpCodes.Conv_Ovf_U8_Un);
            C(VMOpCode.Conv_Ovf_I, CilOpCodes.Conv_Ovf_I);
            C(VMOpCode.Conv_Ovf_I_Un, CilOpCodes.Conv_Ovf_I_Un);
            C(VMOpCode.Conv_Ovf_U, CilOpCodes.Conv_Ovf_U);
            C(VMOpCode.Conv_Ovf_U_Un, CilOpCodes.Conv_Ovf_U_Un);
            A(VMOpCode.Constrained, CilOpCodes.Constrained, i, 0, 0, VMFlowKind.Prefix, type);
            A(VMOpCode.Initobj, CilOpCodes.Initobj, i, 1, 0, token: type);
            A(VMOpCode.Cpobj, CilOpCodes.Cpobj, i, 2, 0, token: type);
            A(VMOpCode.Sizeof, CilOpCodes.Sizeof, i, 0, 1, token: type);
            A(VMOpCode.Localloc, CilOpCodes.Localloc, n, 1, 1);
            A(VMOpCode.Mkrefany, CilOpCodes.Mkrefany, i, 1, 1, token: type);
            A(VMOpCode.Refanyval, CilOpCodes.Refanyval, i, 1, 1, token: type);
            A(VMOpCode.Refanytype, CilOpCodes.Refanytype, n, 1, 1);
            if (r.Count != Enum.GetValues(typeof(VMOpCode)).Length)
                throw new InvalidOperationException(nameof(VMOpCodeCatalog));
            return r;
        }
    }
}
