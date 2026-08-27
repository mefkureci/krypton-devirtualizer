using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;
using System.Security.Cryptography;
using System.Text;
using System.Xml.Linq;
using AsmResolver.DotNet;
using Krypton.Core;
using Krypton.Core.Architecture;

namespace Krypton.Pipeline.Stages
{
    internal sealed class KnownPlaintextAnchor
    {
        public int VmByte { get; set; }
        public VMOpCode OpCode { get; set; }
        public int Sites { get; set; }
        public string Evidence { get; set; }
    }

    // Uses only raw VM bytes/operands, metadata identities and an independently
    // valid RSA XML plaintext. No existing opcode mapping participates.
    internal static class KnownPlaintextCryptoAnchoring
    {
        private static readonly VMOpCode[] BinaryCandidates =
        {
            VMOpCode.Add, VMOpCode.Sub, VMOpCode.Xor, VMOpCode.Shl, VMOpCode.Shr,
            VMOpCode.Ceq
        };

        public static IList<KnownPlaintextAnchor> Solve(
            DevirtualizationCtx ctx,
            IDictionary<int, HashSet<VMOpCode>> candidates)
        {
            var empty = Array.Empty<KnownPlaintextAnchor>();
            if (ctx?.Module == null || ctx.VirtualizedMethods == null || candidates == null)
                return empty;
            var proofs = new Dictionary<int, List<KnownPlaintextAnchor>>();

            var ldcBytes = candidates
                .Where(p => p.Value.SetEquals(new[] { VMOpCode.Ldc_I4 }))
                .Select(p => p.Key)
                .ToHashSet();
            if (ldcBytes.Count == 0)
                return empty;

            foreach (var method in ctx.VirtualizedMethods)
            {
                if (!TryFindCiphertext(ctx, method, out var ciphertext))
                    continue;
                ctx.Options.Logger.Info(
                    $"  [known-plaintext] crypto resource candidate in {method.Parent?.FullName ?? "<unknown>"}: {ciphertext.Length} bytes");
                if (!TryDescribeConstruction(ctx, method, candidates, ldcBytes, out var layout))
                {
                    ctx.Options.Logger.Info("  [known-plaintext] key/IV construction grammar not matched");
                    continue;
                }
                ctx.Options.Logger.Info(
                    $"  [known-plaintext] construction [{layout.Start}..{layout.End}], binary bytes: " +
                    string.Join(", ", layout.BinaryBytes.OrderBy(b => b).Select(b => $"0x{b:X2}")));

                var domains = layout.BinaryBytes.ToDictionary(
                    b => b,
                    b => candidates[b].Where(BinaryCandidates.Contains).ToArray());
                if (domains.Any(p => p.Value.Length == 0))
                    continue;

                var survivors = new List<Dictionary<int, VMOpCode>>();
                Enumerate(domains.Keys.ToArray(), domains, 0, new Dictionary<int, VMOpCode>(), assignment =>
                {
                    if (!TryEvaluate(method.MethodBody.Instructions, layout, assignment, out var key, out var iv))
                        return;
                    if (IsRsaXml(Decrypt(ciphertext, key, iv)))
                        survivors.Add(new Dictionary<int, VMOpCode>(assignment));
                });

                if (survivors.Count == 0)
                {
                    ctx.Options.Logger.Info("  [known-plaintext] no AES/RSA assignment survived");
                    continue;
                }

                var result = new List<KnownPlaintextAnchor>();
                AddStructuralProof(
                    result, method, candidates, layout.NewarrByte, VMOpCode.Newarr,
                    "validated byte[32]/byte[16] construction feeding the RSA key/IV sink");
                AddStructuralProof(
                    result, method, candidates, layout.StoreLocalByte, VMOpCode.Stloc,
                    "validated key/IV array construction stores each newly-created array in a typed VM local");
                AddStructuralProof(
                    result, method, candidates, layout.StoreElementByte, VMOpCode.Stelem_I1,
                    "validated byte[] receiver plus Int32 index/value consumes three stack items at every key/IV write");
                foreach (var vmByte in layout.BinaryBytes)
                {
                    var values = survivors.Select(s => s[vmByte]).Distinct().ToArray();
                    if (values.Length != 1)
                        continue;
                    var sites = method.MethodBody.Instructions.Count(i => i.VmByte == vmByte);
                    result.Add(new KnownPlaintextAnchor
                    {
                        VmByte = vmByte,
                        OpCode = values[0],
                        Sites = sites,
                        Evidence =
                            $"AES-CBC/PKCS7 produced UTF-8 RSAKeyValue with a valid Modulus and Exponent; " +
                            $"{survivors.Count} complete assignment(s), singleton semantic {values[0]}"
                    });
                }
                foreach (var proof in result)
                {
                    if (!proofs.TryGetValue(proof.VmByte, out var list))
                    {
                        list = new List<KnownPlaintextAnchor>();
                        proofs[proof.VmByte] = list;
                    }
                    list.Add(proof);
                }
            }
            return proofs
                .Where(p => p.Value.Select(v => v.OpCode).Distinct().Count() == 1)
                .Select(p => new KnownPlaintextAnchor
                {
                    VmByte = p.Key,
                    OpCode = p.Value[0].OpCode,
                    Sites = p.Value.Sum(v => v.Sites),
                    Evidence =
                        $"{p.Value.Count} independent AES-CBC/PKCS7 contexts produced UTF-8 RSAKeyValue " +
                        $"with valid Modulus/Exponent; singleton semantic {p.Value[0].OpCode} in every context"
                })
                .ToArray();
        }

        private static void AddStructuralProof(
            ICollection<KnownPlaintextAnchor> result,
            VMMethod method,
            IDictionary<int, HashSet<VMOpCode>> candidates,
            int vmByte,
            VMOpCode opCode,
            string grammar)
        {
            if (vmByte < 0 ||
                !candidates.TryGetValue(vmByte, out var set) ||
                !set.Contains(opCode))
                return;
            result.Add(new KnownPlaintextAnchor
            {
                VmByte = vmByte,
                OpCode = opCode,
                Sites = method.MethodBody.Instructions.Count(i => i.VmByte == vmByte),
                Evidence =
                    $"AES-CBC/PKCS7 produced a valid RSAKeyValue after exact raw-VM simulation; {grammar}"
            });
        }

        private sealed class Layout
        {
            public int Start;
            public int End;
            public int LdcByte;
            public int NewarrByte;
            public int LoadLocalByte;
            public int StoreLocalByte;
            public int StoreElementByte;
            public int KeyLocal;
            public int IvLocal;
            public HashSet<int> BinaryBytes = new HashSet<int>();
        }

        private static bool TryDescribeConstruction(
            DevirtualizationCtx ctx,
            VMMethod method,
            IDictionary<int, HashSet<VMOpCode>> candidates,
            ISet<int> ldcBytes,
            out Layout layout)
        {
            layout = null;
            var ins = method?.MethodBody?.Instructions;
            if (ins == null)
                return false;

            for (var start = 0; start + 3 < ins.Count; start++)
            {
                if (!IsLdc(ins[start], ldcBytes, 32) ||
                    !IsByteTypeToken(ctx, ins[start + 1].Operand) ||
                    !(ins[start + 2].Operand is int keyTemp))
                    continue;

                var newarrByte = ins[start + 1].VmByte;
                var storeLocalByte = ins[start + 2].VmByte;
                if (!Contains(candidates, newarrByte, VMOpCode.Newarr) ||
                    !Contains(candidates, storeLocalByte, VMOpCode.Stloc))
                    continue;

                var loadLocalByte = ins[start + 3].VmByte;
                if (!Contains(candidates, loadLocalByte, VMOpCode.Ldloc))
                    continue;

                var ivStart = -1;
                var ivTemp = -1;
                for (var i = start + 3; i + 2 < ins.Count; i++)
                {
                    if (IsLdc(ins[i], ldcBytes, 16) &&
                        ins[i + 1].VmByte == newarrByte &&
                        ins[i + 2].VmByte == storeLocalByte &&
                        ins[i + 2].Operand is int candidateIv)
                    {
                        ivStart = i;
                        ivTemp = candidateIv;
                        break;
                    }
                }
                if (ivStart < 0)
                    continue;

                if (!TryFindArrayTerminal(ins, start + 3, ivStart, loadLocalByte, storeLocalByte,
                        keyTemp, candidates, ldcBytes, out var keyEnd, out var keyLocal, out var keyStelem) ||
                    !TryFindArrayTerminal(ins, ivStart + 3, ins.Count, loadLocalByte, storeLocalByte,
                        ivTemp, candidates, ldcBytes, out var ivEnd, out var ivLocal, out var ivStelem) ||
                    keyStelem != ivStelem ||
                    !Contains(candidates, keyStelem, VMOpCode.Stelem_I1))
                    continue;

                var binaryBytes = new HashSet<int>();
                for (var i = start; i <= ivEnd; i++)
                {
                    var vmByte = ins[i].VmByte;
                    if (ldcBytes.Contains(vmByte) ||
                        vmByte == newarrByte || vmByte == loadLocalByte ||
                        vmByte == storeLocalByte || vmByte == keyStelem)
                        continue;
                    if (ins[i].Operand != null || !candidates.TryGetValue(vmByte, out var set))
                        continue;
                    if (set.Any(BinaryCandidates.Contains))
                        binaryBytes.Add(vmByte);
                }
                if (binaryBytes.Count == 0)
                    continue;

                layout = new Layout
                {
                    Start = start,
                    End = ivEnd,
                    LdcByte = ins[start].VmByte,
                    NewarrByte = newarrByte,
                    LoadLocalByte = loadLocalByte,
                    StoreLocalByte = storeLocalByte,
                    StoreElementByte = keyStelem,
                    KeyLocal = keyLocal,
                    IvLocal = ivLocal,
                    BinaryBytes = binaryBytes
                };
                return true;
            }
            return false;
        }

        private static bool TryFindArrayTerminal(
            IList<VMInstruction> ins,
            int start,
            int limit,
            int loadLocalByte,
            int storeLocalByte,
            int tempLocal,
            IDictionary<int, HashSet<VMOpCode>> candidates,
            ISet<int> ldcBytes,
            out int end,
            out int finalLocal,
            out int stelemByte)
        {
            end = finalLocal = stelemByte = -1;
            var endings = new List<int>();
            for (var i = start; i + 1 < limit; i++)
            {
                if (ins[i].VmByte != loadLocalByte || !Equals(ins[i].Operand, tempLocal))
                    continue;
                if (ins[i + 1].VmByte == storeLocalByte && ins[i + 1].Operand is int target)
                {
                    end = i + 1;
                    finalLocal = target;
                    break;
                }
                if (!IsLdc(ins[i + 1], ldcBytes, Convert.ToInt32(ins[i + 1].Operand)))
                    continue;
                var depth = 2; // byte[] receiver and Int32 index.
                for (var j = i + 2; j < limit; j++)
                {
                    var current = ins[j];
                    if (ldcBytes.Contains(current.VmByte) || current.VmByte == loadLocalByte)
                    {
                        depth++;
                        continue;
                    }
                    if (current.VmByte == storeLocalByte)
                    {
                        depth--;
                        continue;
                    }
                    if (current.Operand != null ||
                        !candidates.TryGetValue(current.VmByte, out var set))
                        break;
                    if (depth == 3 && set.Contains(VMOpCode.Stelem_I1))
                    {
                        endings.Add(current.VmByte);
                        break;
                    }
                    if (depth >= 2 && set.Any(BinaryCandidates.Contains))
                    {
                        depth--;
                        continue;
                    }
                    break;
                }
            }
            if (end < 0 || endings.Count == 0 || endings.Distinct().Count() != 1)
                return false;
            stelemByte = endings[0];
            return true;
        }

        private static bool TryEvaluate(
            IList<VMInstruction> ins,
            Layout layout,
            IDictionary<int, VMOpCode> assignment,
            out byte[] key,
            out byte[] iv)
        {
            key = iv = null;
            var stack = new Stack<object>();
            var locals = new Dictionary<int, object>();
            try
            {
                for (var i = layout.Start; i <= layout.End; i++)
                {
                    var x = ins[i];
                    if (x.VmByte == layout.LdcByte)
                        stack.Push(Convert.ToInt32(x.Operand));
                    else if (x.VmByte == layout.NewarrByte)
                        stack.Push(new byte[(int) stack.Pop()]);
                    else if (x.VmByte == layout.StoreLocalByte)
                        locals[Convert.ToInt32(x.Operand)] = stack.Pop();
                    else if (x.VmByte == layout.LoadLocalByte)
                        stack.Push(locals[Convert.ToInt32(x.Operand)]);
                    else if (x.VmByte == layout.StoreElementByte)
                    {
                        var value = (int) stack.Pop();
                        var index = (int) stack.Pop();
                        var array = (byte[]) stack.Pop();
                        array[index] = unchecked((byte) value);
                    }
                    else if (assignment.TryGetValue(x.VmByte, out var op))
                    {
                        var right = (int) stack.Pop();
                        var left = (int) stack.Pop();
                        stack.Push(Evaluate(op, left, right));
                    }
                    else
                        return false;
                }
                key = locals[layout.KeyLocal] as byte[];
                iv = locals[layout.IvLocal] as byte[];
                return key?.Length == 32 && iv?.Length == 16 && stack.Count == 0;
            }
            catch
            {
                return false;
            }
        }

        internal static int Evaluate(VMOpCode op, int left, int right)
        {
            return op switch
            {
                VMOpCode.Add => unchecked(left + right),
                VMOpCode.Sub => unchecked(left - right),
                VMOpCode.Xor => left ^ right,
                VMOpCode.Shl => left << (right & 31),
                VMOpCode.Shr => left >> (right & 31),
                VMOpCode.Ceq => left == right ? 1 : 0,
                _ => throw new ArgumentOutOfRangeException(nameof(op))
            };
        }

        internal static bool IsRsaXml(byte[] plaintext)
        {
            if (plaintext == null)
                return false;
            try
            {
                var text = new UTF8Encoding(false, true).GetString(plaintext);
                var root = XDocument.Parse(text, LoadOptions.None).Root;
                if (root?.Name.LocalName != "RSAKeyValue")
                    return false;
                var modulus = Convert.FromBase64String(root.Element("Modulus")?.Value ?? "");
                var exponentBytes = Convert.FromBase64String(root.Element("Exponent")?.Value ?? "");
                if (!new[] { 64, 128, 256, 384, 512 }.Contains(modulus.Length) ||
                    exponentBytes.Length == 0 || exponentBytes.Length > 4)
                    return false;
                var exponent = 0;
                foreach (var b in exponentBytes)
                    exponent = (exponent << 8) | b;
                return exponent >= 3 && (exponent & 1) == 1;
            }
            catch
            {
                return false;
            }
        }

        internal static byte[] Decrypt(byte[] ciphertext, byte[] key, byte[] iv)
        {
            try
            {
                using var aes = Aes.Create();
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;
                aes.Key = key;
                aes.IV = iv;
                using var transform = aes.CreateDecryptor();
                return transform.TransformFinalBlock(ciphertext, 0, ciphertext.Length);
            }
            catch
            {
                return null;
            }
        }

        private static bool TryFindCiphertext(DevirtualizationCtx ctx, VMMethod method, out byte[] data)
        {
            data = null;
            var names = ctx.Module.Resources.OfType<AsmResolver.DotNet.ManifestResource>()
                .Where(r => r.IsEmbedded)
                .ToDictionary(r => r.Name?.ToString() ?? string.Empty, r => r, StringComparer.Ordinal);
            if (names.Count == 0)
                return false;
            foreach (var instruction in method.MethodBody.Instructions)
            {
                if (!(instruction.Operand is int offset))
                    continue;
                var text = TryResolveUserString(ctx.Options.FilePath, offset);
                if (text == null || !names.TryGetValue(text, out var resource))
                    continue;
                var bytes = resource.GetData();
                if (bytes != null && bytes.Length > 0 && bytes.Length % 16 == 0)
                {
                    data = bytes;
                    return true;
                }
            }
            return false;
        }

        internal static string TryResolveUserString(string file, int tokenOrOffset)
        {
            try
            {
                var offset = tokenOrOffset;
                var table = unchecked((uint) tokenOrOffset) & 0xFF000000u;
                if (table == 0x70000000u)
                    offset = tokenOrOffset & 0x00FFFFFF;
                else if (table != 0 || offset <= 0)
                    return null;

                using var stream = File.OpenRead(file);
                using var pe = new PEReader(stream);
                return pe.GetMetadataReader().GetUserString(MetadataTokens.UserStringHandle(offset));
            }
            catch
            {
                return null;
            }
        }

        private static bool IsByteTypeToken(DevirtualizationCtx ctx, object operand)
        {
            if (!(operand is int token))
                return false;
            try
            {
                return (ctx.Module.LookupMember(token) as ITypeDescriptor)?.FullName == "System.Byte";
            }
            catch
            {
                return false;
            }
        }

        private static bool IsLdc(VMInstruction instruction, ISet<int> bytes, int value) =>
            instruction != null && bytes.Contains(instruction.VmByte) &&
            instruction.Operand is int actual && actual == value;

        private static bool Contains(
            IDictionary<int, HashSet<VMOpCode>> candidates,
            int vmByte,
            VMOpCode op) =>
            candidates.TryGetValue(vmByte, out var set) && set.Contains(op);

        private static void Enumerate(
            int[] bytes,
            IDictionary<int, VMOpCode[]> domains,
            int index,
            Dictionary<int, VMOpCode> assignment,
            Action<Dictionary<int, VMOpCode>> visit)
        {
            if (index == bytes.Length)
            {
                visit(assignment);
                return;
            }
            var vmByte = bytes[index];
            foreach (var op in domains[vmByte])
            {
                assignment[vmByte] = op;
                Enumerate(bytes, domains, index + 1, assignment, visit);
            }
            assignment.Remove(vmByte);
        }
    }
}
