using Krypton.Pipeline.Stages;
using Xunit;

namespace Krypton.Tests
{
    public sealed class BoundedStateWorklistTests
    {
        [Fact]
        public void TryEnqueue_DeduplicatesPendingAndProcessedStates()
        {
            var worklist = new BoundedStateWorklist(4, 2);

            Assert.True(worklist.TryEnqueue(1, 7));
            for (var i = 0; i < 10_000; i++)
                Assert.False(worklist.TryEnqueue(1, 7));

            Assert.Equal(1, worklist.Count);
            Assert.True(worklist.TryDequeue(out var index, out var depth));
            Assert.Equal(1, index);
            Assert.Equal(7, depth);
            Assert.False(worklist.TryEnqueue(1, 7));
            Assert.Equal(0, worklist.Count);
        }

        [Fact]
        public void TryEnqueue_BoundsDistinctStatesPerInstruction()
        {
            var worklist = new BoundedStateWorklist(2, 2);

            Assert.True(worklist.TryEnqueue(0, 0));
            Assert.True(worklist.TryEnqueue(0, 1));
            Assert.False(worklist.TryEnqueue(0, 2));
            Assert.True(worklist.TryEnqueue(1, 2));

            Assert.Equal(3, worklist.Count);
            Assert.Equal(2, worklist.GetDiscoveredDepths(0).Count);
            Assert.Single(worklist.GetDiscoveredDepths(1));
        }
    }
}
