using System;
using System.Collections.Generic;

namespace Krypton.Pipeline.Stages
{
    internal sealed class BoundedStateWorklist
    {
        private readonly Queue<(int Index, int Depth)> _queue = new Queue<(int Index, int Depth)>();
        private readonly HashSet<int>[] _discoveredDepths;
        private readonly int _maxStatesPerInstruction;

        public BoundedStateWorklist(int instructionCount, int maxStatesPerInstruction)
        {
            if (instructionCount < 0)
                throw new ArgumentOutOfRangeException(nameof(instructionCount));
            if (maxStatesPerInstruction <= 0)
                throw new ArgumentOutOfRangeException(nameof(maxStatesPerInstruction));

            _maxStatesPerInstruction = maxStatesPerInstruction;
            _discoveredDepths = new HashSet<int>[instructionCount];
            for (var i = 0; i < instructionCount; i++)
                _discoveredDepths[i] = new HashSet<int>();
        }

        public int Count => _queue.Count;

        public IReadOnlyCollection<int> GetDiscoveredDepths(int index)
        {
            if (index < 0 || index >= _discoveredDepths.Length)
                return Array.Empty<int>();
            return _discoveredDepths[index];
        }

        public bool TryEnqueue(int index, int depth)
        {
            if (index < 0 || index >= _discoveredDepths.Length)
                return false;

            var discovered = _discoveredDepths[index];
            if (discovered.Contains(depth) || discovered.Count >= _maxStatesPerInstruction)
                return false;

            discovered.Add(depth);
            _queue.Enqueue((index, depth));
            return true;
        }

        public bool TryDequeue(out int index, out int depth)
        {
            if (_queue.Count == 0)
            {
                index = -1;
                depth = 0;
                return false;
            }

            var state = _queue.Dequeue();
            index = state.Index;
            depth = state.Depth;
            return true;
        }
    }
}
