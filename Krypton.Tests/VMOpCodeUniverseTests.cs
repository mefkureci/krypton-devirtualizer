using System;
using System.Linq;
using AsmResolver.PE.DotNet.Cil;
using Krypton.Core.Architecture;
using Krypton.Pipeline.Stages;
using Xunit;

namespace Krypton.Tests
{
    public sealed class VMOpCodeUniverseTests
    {
        [Fact]
        public void Catalog_CoversEveryEnumMember()
        {
            foreach (var opCode in Enum.GetValues<VMOpCode>())
                Assert.True(VMOpCodeCatalog.TryGet(opCode, out _), opCode.ToString());
        }

        [Fact]
        public void Mul_HasBinaryStackEffect_NoOperand_AndEmitterMapping()
        {
            var semantic = VMOpCodeCatalog.Get(VMOpCode.Mul);

            Assert.Equal(2, semantic.Pop);
            Assert.Equal(1, semantic.Push);
            Assert.True(semantic.SupportsOperandType(0));
            Assert.False(semantic.SupportsOperandType(1));
            Assert.Equal(CilOpCodes.Mul, semantic.CilOpCode);
        }

        [Fact]
        public void Throw_PopsException_AndTerminatesControlFlow()
        {
            var semantic = VMOpCodeCatalog.Get(VMOpCode.Throw);

            Assert.Equal(1, semantic.Pop);
            Assert.Equal(0, semantic.Push);
            Assert.True(semantic.IsTerminal);
            Assert.Equal(VMFlowKind.Throw, semantic.Flow);
            Assert.Equal(CilOpCodes.Throw, semantic.CilOpCode);
        }

        [Theory]
        [InlineData(VMOpCode.Conv_U8)]
        [InlineData(VMOpCode.Conv_U4)]
        [InlineData(VMOpCode.Conv_Ovf_I4)]
        public void NewConversions_HaveUnaryStackEffect_AndNoOperand(VMOpCode opCode)
        {
            var semantic = VMOpCodeCatalog.Get(opCode);

            Assert.Equal(1, semantic.Pop);
            Assert.Equal(1, semantic.Push);
            Assert.True(semantic.SupportsOperandType(0));
            Assert.False(semantic.SupportsOperandType(1));
            Assert.True(VMOpCodeCatalog.IsConversion(opCode));
        }

        [Fact]
        public void NewConversions_HaveExactEmitterMappings()
        {
            Assert.Equal(CilOpCodes.Conv_U8, MethodRecompiling.EmitOperandlessInstruction(VMOpCode.Conv_U8).OpCode);
            Assert.Equal(CilOpCodes.Conv_U4, MethodRecompiling.EmitOperandlessInstruction(VMOpCode.Conv_U4).OpCode);
            Assert.Equal(CilOpCodes.Conv_Ovf_I4, MethodRecompiling.EmitOperandlessInstruction(VMOpCode.Conv_Ovf_I4).OpCode);
        }

        [Fact]
        public void Mul_EmitterProducesCilMul()
        {
            Assert.Equal(CilOpCodes.Mul, MethodRecompiling.EmitOperandlessInstruction(VMOpCode.Mul).OpCode);
        }

        [Fact]
        public void Throw_EmitterProducesCilThrow()
        {
            Assert.Equal(CilOpCodes.Throw, MethodRecompiling.EmitOperandlessInstruction(VMOpCode.Throw).OpCode);
        }

        [Theory]
        [InlineData(VMOpCode.Mul)]
        [InlineData(VMOpCode.Throw)]
        [InlineData(VMOpCode.Conv_U8)]
        [InlineData(VMOpCode.Conv_U4)]
        [InlineData(VMOpCode.Conv_Ovf_I4)]
        public void OperandlessCandidates_RoundTripThroughVmInstruction(VMOpCode opCode)
        {
            var candidates = VMOpCodeCatalog.GetCandidates(0).ToArray();
            var instruction = new VMInstruction(opCode);

            Assert.Contains(opCode, candidates);
            Assert.Equal(opCode, instruction.OpCode);
            Assert.True(instruction.IsResolved);
            Assert.Equal(
                VMOpCodeCatalog.Get(opCode).CilOpCode,
                VMOpCodeCatalog.Get(instruction.OpCode).CilOpCode);
        }

        [Fact]
        public void CandidateGeneration_ExposesCompleteRequiredConversionFamilies()
        {
            var candidates = VMOpCodeCatalog.GetCandidates(0).ToArray();

            Assert.Contains(VMOpCode.Conv_I8, candidates);
            Assert.Contains(VMOpCode.Conv_U8, candidates);
            Assert.Contains(VMOpCode.Conv_I4, candidates);
            Assert.Contains(VMOpCode.Conv_U4, candidates);
            Assert.Contains(VMOpCode.Conv_Ovf_I4, candidates);
        }

        [Fact]
        public void Int64RecordForm_RoundTripsAsLdcI8()
        {
            var descriptor = VMOpCodeCatalog.Get(VMOpCode.Ldc_I8);

            Assert.Equal(CilOpCodes.Ldc_I8, descriptor.CilOpCode);
            Assert.Equal(VMOperandEncoding.Int64, descriptor.Encodings);
            Assert.Equal(0, descriptor.Pop);
            Assert.Equal(1, descriptor.Push);
            Assert.Contains(VMOpCode.Ldc_I8, VMOpCodeCatalog.GetCandidates(2));
        }
    }
}
