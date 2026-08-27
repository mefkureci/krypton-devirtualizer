using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using Krypton.Core;
using Krypton.Core.Architecture;

namespace Krypton.Pipeline.Stages
{
    internal sealed class RuntimeAnchorOutcome
    {
        public IList<string> Accepted { get; } = new List<string>();
        public IList<string> Rejected { get; } = new List<string>();
        public IDictionary<int, VMOpCode> Applied { get; } = new Dictionary<int, VMOpCode>();
        public string SourcePath { get; set; }
        public int Lines { get; set; }
    }

    // Runtime observations are independent evidence: they read the interpreter's
    // actual behaviour instead of reading the opcode table. They therefore enter
    // through the same door as metadata signatures rather than through inference.
    //
    // The mechanism here is generic. It takes an external file of observed
    // mappings and admits an entry only when the entry survives every check the
    // pipeline can make on its own: the byte must occur in the payload, the opcode
    // must still be in that byte's candidate set, it must not contradict an
    // existing anchor, and it must not collide with another byte's anchor. Sample
    // facts live in the file; the validation lives here.
    internal static class RuntimeTraceAnchors
    {
        public const string EvidenceSource = "runtime-trace";

        public static string ConfiguredPath()
        {
            var raw = Environment.GetEnvironmentVariable("KRYPTON_RUNTIME_ANCHORS");
            return string.IsNullOrWhiteSpace(raw) ? null : raw.Trim();
        }

        public static RuntimeAnchorOutcome Apply(DevirtualizationCtx ctx, AnchorPropagationResult outcome)
        {
            var result = new RuntimeAnchorOutcome();
            var path = ConfiguredPath();
            if (path == null)
                return result;

            result.SourcePath = path;
            if (!File.Exists(path))
            {
                result.Rejected.Add($"file not found: {path}");
                return result;
            }

            var alreadyAnchored = new Dictionary<VMOpCode, int>();
            foreach (var pair in outcome.Anchors)
                alreadyAnchored[pair.Value.OpCode] = pair.Key;

            foreach (var raw in File.ReadAllLines(path))
            {
                var line = raw;
                var comment = line.IndexOf('#');
                if (comment >= 0)
                    line = line.Substring(0, comment);
                line = line.Trim();
                if (line.Length == 0)
                    continue;

                result.Lines++;
                var parts = line.Split('=');
                if (parts.Length != 2)
                {
                    result.Rejected.Add($"malformed entry '{raw.Trim()}'");
                    continue;
                }

                if (!TryParseByte(parts[0].Trim(), out var vmByte))
                {
                    result.Rejected.Add($"unparsable vm byte in '{raw.Trim()}'");
                    continue;
                }

                var opcodeText = parts[1].Trim();
                if (!Enum.TryParse(opcodeText, false, out VMOpCode opcode))
                {
                    result.Rejected.Add($"unknown opcode '{opcodeText}' for vm 0x{vmByte:X2}");
                    continue;
                }

                if (!outcome.Candidates.TryGetValue(vmByte, out var candidates))
                {
                    result.Rejected.Add($"vm 0x{vmByte:X2} does not occur in this payload");
                    continue;
                }

                if (!candidates.Contains(opcode))
                {
                    result.Rejected.Add(
                        $"vm 0x{vmByte:X2} -> {opcode} contradicts its candidate set " +
                        $"({string.Join(", ", candidates.OrderBy(c => c.ToString()))})");
                    continue;
                }

                if (outcome.Anchors.TryGetValue(vmByte, out var existing) && existing.OpCode != opcode)
                {
                    result.Rejected.Add(
                        $"vm 0x{vmByte:X2} -> {opcode} contradicts existing anchor {existing.OpCode}");
                    continue;
                }

                if (alreadyAnchored.TryGetValue(opcode, out var owner) && owner != vmByte)
                {
                    result.Rejected.Add(
                        $"vm 0x{vmByte:X2} -> {opcode} collides with vm 0x{owner:X2}");
                    continue;
                }

                candidates.Clear();
                candidates.Add(opcode);
                outcome.Candidates[vmByte] = candidates;
                outcome.FamilyResolved.Remove(vmByte);

                if (!outcome.Anchors.ContainsKey(vmByte))
                {
                    var record = new AnchorRecord
                    {
                        VmByte = vmByte,
                        OpCode = opcode,
                        Source = AnchorSource.GlobalStack,
                        SiteCount = outcome.SiteCounts.TryGetValue(vmByte, out var sites) ? sites : 0,
                        Round = 0
                    };
                    record.Evidence.Add(EvidenceSource);
                    outcome.Anchors[vmByte] = record;
                }

                alreadyAnchored[opcode] = vmByte;
                result.Applied[vmByte] = opcode;
                result.Accepted.Add($"vm 0x{vmByte:X2} -> {opcode}");
            }

            foreach (var pair in result.Applied)
                PinMapping(ctx, pair.Key, pair.Value);

            return result;
        }

        private static void PinMapping(DevirtualizationCtx ctx, int vmByte, VMOpCode opcode)
        {
            if (ctx?.PatternMatcher == null)
                return;

            ctx.AnchoredOpcodes.Add(vmByte);
            ctx.PatternMatcher.SetOpCodeValue(opcode, vmByte);
            ctx.OpcodeConfidence ??= new Dictionary<int, OpcodeMappingConfidence>();
            ctx.OpcodeConfidence[vmByte] = new OpcodeMappingConfidence(opcode, 1.0, EvidenceSource);

            if (ctx.VirtualizedMethods == null)
                return;

            foreach (var method in ctx.VirtualizedMethods)
            {
                var instructions = method?.MethodBody?.Instructions;
                if (instructions == null)
                    continue;
                foreach (var instruction in instructions)
                {
                    if (instruction?.VmByte != vmByte)
                        continue;
                    instruction.IsResolved = true;
                    instruction.OpCode = opcode;
                }
            }
        }

        private static bool TryParseByte(string text, out int value)
        {
            value = 0;
            if (string.IsNullOrEmpty(text))
                return false;
            if (text.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                text = text.Substring(2);
            return int.TryParse(text, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out value);
        }

        public static string FormatSummary(RuntimeAnchorOutcome outcome)
        {
            var sb = new StringBuilder();
            sb.AppendLine("Runtime-trace anchors");
            sb.AppendLine($"  fixture            : {outcome.SourcePath ?? "<none configured>"}");
            sb.AppendLine($"  entries read       : {outcome.Lines}");
            sb.AppendLine($"  accepted           : {outcome.Accepted.Count}");
            foreach (var line in outcome.Accepted)
                sb.AppendLine($"    {line}");
            sb.AppendLine($"  rejected           : {outcome.Rejected.Count}");
            foreach (var line in outcome.Rejected)
                sb.AppendLine($"    {line}");
            return sb.ToString().TrimEnd();
        }
    }
}
