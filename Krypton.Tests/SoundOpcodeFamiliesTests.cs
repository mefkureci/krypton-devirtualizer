using System.Collections.Generic;
using Krypton.Core.Architecture;
using Krypton.Pipeline.Stages;
using Xunit;

namespace Krypton.Tests
{
    public sealed class SoundOpcodeFamiliesTests
    {
        [Fact]
        public void Classify_RecognizesOnlyCompleteCompatibleCandidateSubsets()
        {
            var candidates = new Dictionary<int, HashSet<VMOpCode>>
            {
                [0x11] = new HashSet<VMOpCode> { VMOpCode.Call, VMOpCode.Callvirt },
                [0x22] = new HashSet<VMOpCode> { VMOpCode.Ldloc, VMOpCode.Ldloca },
                [0x33] = new HashSet<VMOpCode> { VMOpCode.Call, VMOpCode.Ldloc },
                [0x44] = new HashSet<VMOpCode> { VMOpCode.Call }
            };

            var families = SoundOpcodeFamilies.Classify(candidates);

            Assert.Equal("CALL", families[0x11]);
            Assert.Equal("LOCAL_READ", families[0x22]);
            Assert.False(families.ContainsKey(0x33));
            Assert.False(families.ContainsKey(0x44));
        }

        [Fact]
        public void Classify_DoesNotMutateOrCollapseCandidates()
        {
            var callCandidates = new HashSet<VMOpCode>
                { VMOpCode.Call, VMOpCode.Callvirt };
            var candidates = new Dictionary<int, HashSet<VMOpCode>>
                { [0x11] = callCandidates };

            var families = SoundOpcodeFamilies.Classify(candidates);

            Assert.Equal("CALL", families[0x11]);
            Assert.Equal(2, callCandidates.Count);
            Assert.Contains(VMOpCode.Call, callCandidates);
            Assert.Contains(VMOpCode.Callvirt, callCandidates);
        }
    }
}
