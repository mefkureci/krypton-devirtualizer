using System;
using System.Collections.Generic;
using System.Collections.Concurrent;
using AsmResolver.DotNet;
using AsmResolver.PE.DotNet.Cil;

namespace Krypton.Core.PatternMatching.Patterns
{
    internal static class InstructionCache
    {
        private static readonly ConcurrentDictionary<MethodDefinition, List<CilInstruction>> _cache 
            = new ConcurrentDictionary<MethodDefinition, List<CilInstruction>>();
        
        public static List<CilInstruction> GetInstructions(MethodDefinition method)
        {
            if (method == null || method.CilMethodBody == null)
                return new List<CilInstruction>();
            
            return _cache.GetOrAdd(method, m => m.CilMethodBody.Instructions);
        }
        
        public static void ClearCache()
        {
            _cache.Clear();
        }
        
        public static void ClearCacheForMethod(MethodDefinition method)
        {
            if (method != null)
                _cache.TryRemove(method, out _);
        }
    }
}
