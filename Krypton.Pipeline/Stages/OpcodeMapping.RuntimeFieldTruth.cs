using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using AsmResolver.DotNet;
using AsmResolver.DotNet.Signatures;
using Krypton.Core;
using Krypton.Core.Architecture;

namespace Krypton.Pipeline.Stages
{
    public partial class OpcodeMapping
    {
        // Evidence source name. It contains "override" on purpose: the semantic validator
        // treats such mappings as established and will not retune them, which matters here
        // because an imbalanced stack otherwise tempts it to demote an arithmetic byte to Nop.
        internal const string RuntimeFieldTruthSource = "runtime-truth-override";

        private const int MaxSolverOpBytes = 12;
        private const long MaxSolverCombinations = 8_000_000;
        private const int MinSolverGroups = 8;

        private static readonly VMOpCode[] BinaryArithmeticCandidates =
        {
            VMOpCode.Add, VMOpCode.Sub, VMOpCode.Mul, VMOpCode.And,
            VMOpCode.Or, VMOpCode.Xor, VMOpCode.Shl, VMOpCode.Shr
        };

        private static readonly VMOpCode[] UnaryArithmeticCandidates =
        {
            VMOpCode.Neg, VMOpCode.Not
        };

        private sealed class FieldInitGroup
        {
            public readonly List<(bool IsConstant, int Value)> Sequence = new List<(bool, int)>();
            public uint FieldToken;
        }

        // NET Reactor initializes its runtime helper type by storing a few hundred obfuscated
        // int constants into instance fields. Statistical byte->opcode inference has almost
        // nothing to go on there: the arithmetic bytes carry no operands and no distinguishing
        // neighbours, so they all collapse onto whichever arithmetic opcode voted highest, and
        // the field-store byte looks exactly like a field load.
        //
        // Those same fields have observable runtime values, and Krypton.Runner can read them
        // out of the still-protected assembly. That turns guessing into solving: an assignment
        // of opcodes to bytes is correct only if it reproduces every observed field value. A
        // unique such assignment is proof, not a vote.
        private void SolveOpcodesFromRuntimeFieldValues(DevirtualizationCtx ctx)
        {
            if (IsEnvironmentEnabled("KRYPTON_DISABLE_RUNTIME_FIELD_TRUTH_SOLVER"))
                return;
            if (ctx?.Parser?.Reader == null || ctx.PatternMatcher == null || ctx.Module == null)
                return;

            var originalPath = ctx.Options?.FilePath;
            if (string.IsNullOrWhiteSpace(originalPath) || !File.Exists(originalPath))
                return;

            var groups = CollectFieldInitGroups(ctx, out var storeByte);
            if (groups.Count < MinSolverGroups)
                return;

            var opBytes = groups
                .SelectMany(g => g.Sequence.Where(e => !e.IsConstant).Select(e => e.Value))
                .Distinct()
                .OrderBy(b => b)
                .ToList();

            if (opBytes.Count == 0 || opBytes.Count > MaxSolverOpBytes)
                return;

            var truth = ReadRuntimeIntFields(ctx, originalPath);
            if (truth.Count == 0)
                return;

            groups = groups.Where(g => truth.ContainsKey(g.FieldToken)).ToList();
            if (groups.Count < MinSolverGroups)
                return;

            // Phase 1: stack arity. Each group is "load instance; evaluate expression; store
            // field", so the expression must leave exactly one value behind.
            var arities = SolveArities(groups, opBytes);
            if (arities == null)
            {
                ctx.Options.Logger.Info(
                    "Runtime-field solver: no consistent stack arity for the field initializer; leaving mapping untouched.");
                return;
            }

            // Phase 2: which arithmetic opcode each byte actually is, decided by whether the
            // whole initializer reproduces the values the protected binary really produces.
            var semantics = SolveSemantics(ctx, groups, opBytes, arities, truth);
            if (semantics == null)
                return;

            var applied = 0;
            if (storeByte >= 0 && ShouldRemap(ctx, storeByte, VMOpCode.Stfld))
            {
                ApplyMapping(ctx, storeByte, VMOpCode.Stfld, 1.0, RuntimeFieldTruthSource);
                ctx.Options.Logger.Warning($"Runtime-field solver: vm 0x{storeByte:X2} -> Stfld.");
                applied++;
            }

            foreach (var pair in semantics)
            {
                if (!ShouldRemap(ctx, pair.Key, pair.Value))
                    continue;
                ApplyMapping(ctx, pair.Key, pair.Value, 1.0, RuntimeFieldTruthSource);
                ctx.Options.Logger.Warning($"Runtime-field solver: vm 0x{pair.Key:X2} -> {pair.Value}.");
                applied++;
            }

            if (applied > 0)
            {
                ctx.Options.Logger.Success(
                    $"Runtime-field solver: proved {applied} opcode(s) against {groups.Count} observed field value(s).");
            }
        }

        private bool ShouldRemap(DevirtualizationCtx ctx, int vmByte, VMOpCode opCode)
        {
            if (!IsOperandTypeCompatible(opCode, ctx.Parser.Operands[vmByte]))
                return false;
            if (!ctx.PatternMatcher.IsOpCodeValueKnown(vmByte))
                return true;
            return ctx.PatternMatcher.GetOpCodeValue(vmByte) != opCode;
        }

        // Walks the VM stream looking for the "store a computed constant into an int field of a
        // freshly built helper instance" shape, repeated over many fields of one type.
        private List<FieldInitGroup> CollectFieldInitGroups(DevirtualizationCtx ctx, out int storeByte)
        {
            storeByte = -1;
            var best = new List<FieldInitGroup>();
            var parser = ctx.Parser;
            var stream = parser.Reader.BaseStream;
            var originalPosition = stream.Position;

            try
            {
                foreach (var methodKey in parser.MethodKeys)
                {
                    stream.Position = methodKey;

                    parser.ReadEncryptedByte();
                    var locals = parser.ReadEncryptedByte();
                    var exceptionHandlers = parser.ReadEncryptedByte();
                    var instructionCount = parser.ReadEncryptedByte();
                    for (var i = 0; i < locals; i++)
                        parser.ReadEncryptedByte();
                    for (var i = 0; i < exceptionHandlers; i++)
                        new VMExceptionHandler().Read(ctx.Module, parser);

                    var entries = new List<(int VmByte, int Operand, bool HasOperand)>(instructionCount);
                    for (var i = 0; i < instructionCount; i++)
                    {
                        var vmByte = parser.Reader.ReadByte();
                        var operandType = vmByte >= 0 && vmByte < parser.Operands.Length
                            ? parser.Operands[vmByte]
                            : (byte) 0;

                        if (operandType == 1)
                        {
                            entries.Add((vmByte, parser.ReadEncryptedByte(), true));
                        }
                        else
                        {
                            SkipOperand(parser, operandType);
                            entries.Add((vmByte, 0, false));
                        }
                    }

                    var found = ExtractGroupsFromMethod(ctx, entries, out var methodStoreByte);
                    if (found.Count > best.Count)
                    {
                        best = found;
                        storeByte = methodStoreByte;
                    }
                }
            }
            catch
            {
                // Best effort: a stream we cannot walk simply yields no groups.
            }
            finally
            {
                stream.Position = originalPosition;
            }

            return best;
        }

        private List<FieldInitGroup> ExtractGroupsFromMethod(
            DevirtualizationCtx ctx,
            List<(int VmByte, int Operand, bool HasOperand)> entries,
            out int storeByte)
        {
            storeByte = -1;
            var groups = new List<FieldInitGroup>();
            FieldInitGroup current = null;

            foreach (var entry in entries)
            {
                var isInstanceLoad = entry.HasOperand &&
                                     ctx.PatternMatcher.IsOpCodeValueKnown(entry.VmByte) &&
                                     ctx.PatternMatcher.GetOpCodeValue(entry.VmByte) == VMOpCode.Ldsfld &&
                                     ResolveField(ctx, entry.Operand) is { } staticField &&
                                     staticField.IsStatic;

                if (isInstanceLoad)
                {
                    current = new FieldInitGroup();
                    continue;
                }

                if (current == null)
                    continue;

                var targetField = entry.HasOperand ? ResolveField(ctx, entry.Operand) : null;
                if (targetField != null && !targetField.IsStatic && IsInt32Field(targetField))
                {
                    if (storeByte >= 0 && storeByte != entry.VmByte)
                    {
                        current = null;
                        continue;
                    }

                    storeByte = entry.VmByte;
                    current.FieldToken = targetField.MetadataToken.ToUInt32();
                    groups.Add(current);
                    current = null;
                    continue;
                }

                if (entry.HasOperand)
                {
                    // A metadata-looking operand that is not a field is a constant push here:
                    // Ldtoken and Ldc_I4 are structurally indistinguishable in this VM.
                    if (targetField != null)
                    {
                        current = null;
                        continue;
                    }

                    current.Sequence.Add((true, entry.Operand));
                    continue;
                }

                if (ctx.PatternMatcher.IsOpCodeValueKnown(entry.VmByte) &&
                    !IsArithmeticOpcode(ctx.PatternMatcher.GetOpCodeValue(entry.VmByte)))
                {
                    current = null;
                    continue;
                }

                current.Sequence.Add((false, entry.VmByte));
            }

            return groups;
        }

        private static bool IsArithmeticOpcode(VMOpCode opCode) =>
            BinaryArithmeticCandidates.Contains(opCode) || UnaryArithmeticCandidates.Contains(opCode);

        private static FieldDefinition ResolveField(DevirtualizationCtx ctx, int token)
        {
            try
            {
                return ctx.Module.LookupMember((uint) token) as FieldDefinition;
            }
            catch
            {
                return null;
            }
        }

        private static bool IsInt32Field(FieldDefinition field) =>
            field.Signature?.FieldType?.ElementType == AsmResolver.PE.DotNet.Metadata.Tables.Rows.ElementType.I4;

        private Dictionary<uint, int> ReadRuntimeIntFields(DevirtualizationCtx ctx, string originalPath)
        {
            var result = new Dictionary<uint, int>();
            var outPath = Path.ChangeExtension(originalPath, null) + "-opcode-truth-fields.json";

            if (!RunnerInvoker.Invoke(
                    "--dump-fields",
                    originalPath,
                    outPath,
                    "FieldTruth",
                    _ => { },
                    line => ctx.Options.Logger.Warning(line)))
            {
                return result;
            }

            try
            {
                using var doc = JsonDocument.Parse(File.ReadAllText(outPath));
                if (!doc.RootElement.TryGetProperty("Fields", out var fields) ||
                    fields.ValueKind != JsonValueKind.Array)
                {
                    return result;
                }

                foreach (var entry in fields.EnumerateArray())
                {
                    if (!entry.TryGetProperty("Token", out var tokenNode) ||
                        !entry.TryGetProperty("Value", out var valueNode))
                    {
                        continue;
                    }

                    var tokenText = tokenNode.GetString();
                    var valueText = valueNode.ValueKind == JsonValueKind.String
                        ? valueNode.GetString()
                        : valueNode.ToString();
                    if (tokenText == null || valueText == null)
                        continue;
                    if (tokenText.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                        tokenText = tokenText.Substring(2);

                    if (uint.TryParse(tokenText, System.Globalization.NumberStyles.HexNumber, null, out var token) &&
                        int.TryParse(valueText, out var value))
                    {
                        result[token] = value;
                    }
                }
            }
            catch (Exception ex)
            {
                ctx.Options.Logger.Warning($"Runtime-field solver: could not read field dump: {ex.Message}");
            }

            return result;
        }

        // Each group must consume its constants down to exactly one value. With unary ops at
        // net 0 and binary ops at net -1 that is a small integer system; a unique solution
        // pins every byte's arity.
        private static Dictionary<int, int> SolveArities(List<FieldInitGroup> groups, List<int> opBytes)
        {
            Dictionary<int, int> found = null;
            var total = 1L << opBytes.Count;

            for (var mask = 0L; mask < total; mask++)
            {
                var arity = new Dictionary<int, int>(opBytes.Count);
                for (var i = 0; i < opBytes.Count; i++)
                    arity[opBytes[i]] = (mask & (1L << i)) != 0 ? 2 : 1;

                var ok = true;
                foreach (var group in groups)
                {
                    var depth = 0;
                    foreach (var (isConstant, value) in group.Sequence)
                    {
                        if (isConstant)
                        {
                            depth++;
                            continue;
                        }

                        depth -= arity[value] - 1;
                        if (depth < 1)
                        {
                            ok = false;
                            break;
                        }
                    }

                    if (!ok || depth != 1)
                    {
                        ok = false;
                        break;
                    }
                }

                if (!ok)
                    continue;
                if (found != null)
                    return null;
                found = arity;
            }

            return found;
        }

        private Dictionary<int, VMOpCode> SolveSemantics(
            DevirtualizationCtx ctx,
            List<FieldInitGroup> groups,
            List<int> opBytes,
            Dictionary<int, int> arities,
            Dictionary<uint, int> truth)
        {
            var choices = opBytes
                .Select(b => arities[b] == 2 ? BinaryArithmeticCandidates : UnaryArithmeticCandidates)
                .ToList();

            var combinations = 1L;
            foreach (var choice in choices)
            {
                combinations *= choice.Length;
                if (combinations > MaxSolverCombinations)
                {
                    ctx.Options.Logger.Info(
                        "Runtime-field solver: candidate space too large; leaving mapping untouched.");
                    return null;
                }
            }

            var indices = new int[opBytes.Count];
            var assignment = new Dictionary<int, VMOpCode>(opBytes.Count);
            Dictionary<int, VMOpCode> solution = null;
            var stack = new int[64];

            for (var n = 0L; n < combinations; n++)
            {
                var rest = n;
                for (var i = 0; i < indices.Length; i++)
                {
                    indices[i] = (int) (rest % choices[i].Length);
                    rest /= choices[i].Length;
                }

                for (var i = 0; i < opBytes.Count; i++)
                    assignment[opBytes[i]] = choices[i][indices[i]];

                var ok = true;
                foreach (var group in groups)
                {
                    if (!TryEvaluateGroup(group, assignment, stack, out var value) ||
                        value != truth[group.FieldToken])
                    {
                        ok = false;
                        break;
                    }
                }

                if (!ok)
                    continue;
                if (solution != null)
                {
                    ctx.Options.Logger.Info(
                        "Runtime-field solver: observed values do not single out one opcode assignment; leaving mapping untouched.");
                    return null;
                }

                solution = new Dictionary<int, VMOpCode>(assignment);
            }

            if (solution == null)
            {
                ctx.Options.Logger.Info(
                    "Runtime-field solver: no opcode assignment reproduces the observed field values; leaving mapping untouched.");
            }

            return solution;
        }

        private static bool TryEvaluateGroup(
            FieldInitGroup group,
            Dictionary<int, VMOpCode> assignment,
            int[] stack,
            out int result)
        {
            result = 0;
            var depth = 0;

            foreach (var (isConstant, value) in group.Sequence)
            {
                if (isConstant)
                {
                    if (depth >= stack.Length)
                        return false;
                    stack[depth++] = value;
                    continue;
                }

                var opCode = assignment[value];
                if (UnaryArithmeticCandidates.Contains(opCode))
                {
                    if (depth < 1)
                        return false;
                    stack[depth - 1] = opCode == VMOpCode.Neg ? unchecked(-stack[depth - 1]) : ~stack[depth - 1];
                    continue;
                }

                if (depth < 2)
                    return false;

                var b = stack[--depth];
                var a = stack[depth - 1];
                stack[depth - 1] = opCode switch
                {
                    VMOpCode.Add => unchecked(a + b),
                    VMOpCode.Sub => unchecked(a - b),
                    VMOpCode.Mul => unchecked(a * b),
                    VMOpCode.And => a & b,
                    VMOpCode.Or => a | b,
                    VMOpCode.Xor => a ^ b,
                    VMOpCode.Shl => a << (b & 31),
                    VMOpCode.Shr => a >> (b & 31),
                    _ => 0
                };
            }

            if (depth != 1)
                return false;

            result = stack[0];
            return true;
        }
    }
}
