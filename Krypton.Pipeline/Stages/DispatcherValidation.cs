using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using AsmResolver.DotNet;
using AsmResolver.DotNet.Code.Cil;
using AsmResolver.PE.DotNet.Cil;

namespace Krypton.Pipeline.Stages
{
    public enum DispatcherValidationResult
    {
        Valid,
        Suspicious,
        Rejected,
        NotFound
    }

    public sealed class DispatcherValidationReport
    {
        public DispatcherValidationResult Result { get; set; } = DispatcherValidationResult.NotFound;
        public string CandidateName { get; set; } = "<none>";
        public int SwitchBranches { get; set; }
        public int ExpectedOpcodes { get; set; }
        public bool BytecodeFetchDetected { get; set; }
        public bool VmStateDetected { get; set; }
        public bool SelectorWrittenByTargets { get; set; }
        public double DominantShapeShare { get; set; }
        public List<string> HardFailures { get; } = new List<string>();
        public List<string> SoftFailures { get; } = new List<string>();

        public bool HandlerEvidenceAllowed =>
            Result == DispatcherValidationResult.Valid ||
            Result == DispatcherValidationResult.Suspicious;

        public string Format()
        {
            var sb = new StringBuilder();
            sb.AppendLine("Dispatcher validation");
            sb.AppendLine($"  candidate                : {CandidateName}");
            sb.AppendLine($"  switch branches          : {SwitchBranches}");
            sb.AppendLine($"  expected VM opcodes      : {ExpectedOpcodes}");
            sb.AppendLine($"  bytecode fetch detected  : {(BytecodeFetchDetected ? "YES" : "NO")}");
            sb.AppendLine($"  VM state model detected  : {(VmStateDetected ? "YES" : "NO")}");
            sb.AppendLine($"  selector written by body : {(SelectorWrittenByTargets ? "YES (flattened CFG)" : "no")}");
            sb.AppendLine($"  dominant block shape     : {DominantShapeShare:P0}");
            foreach (var failure in HardFailures)
                sb.AppendLine($"  [hard] {failure}");
            foreach (var failure in SoftFailures)
                sb.AppendLine($"  [soft] {failure}");
            sb.Append($"  RESULT                   : {Result.ToString().ToUpperInvariant()}");
            return sb.ToString();
        }
    }

    // A large switch is not evidence of a VM interpreter: control-flow flattening
    // produces the same shape. Accepting a flattened application method as the
    // opcode dispatcher turns every handler-derived inference into high-confidence
    // noise, which is worse than having no handler evidence at all.
    internal static class DispatcherValidator
    {
        public static DispatcherValidationReport Validate(
            MethodDefinition method,
            CilInstruction switchInstruction,
            int expectedOpcodeCount)
        {
            var report = new DispatcherValidationReport
            {
                ExpectedOpcodes = expectedOpcodeCount
            };

            var instructions = method?.CilMethodBody?.Instructions;
            if (instructions == null || switchInstruction == null ||
                !(switchInstruction.Operand is IList<ICilLabel> labels))
            {
                return report;
            }

            report.CandidateName = method.FullName;
            report.SwitchBranches = labels.Count;

            var indexByInstruction = new Dictionary<CilInstruction, int>(instructions.Count);
            for (var i = 0; i < instructions.Count; i++)
            {
                if (!indexByInstruction.ContainsKey(instructions[i]))
                    indexByInstruction[instructions[i]] = i;
            }

            AnalyzeStateAccess(instructions, report);
            AnalyzeSelector(instructions, indexByInstruction, switchInstruction, labels, report);
            AnalyzeBlockUniformity(instructions, indexByInstruction, labels, report);
            Decide(report);
            return report;
        }

        // A real interpreter fetches its bytecode: it reads elements at a computed
        // position, or pulls them from a stream. Data-construction code writes
        // elements at literal positions and reads almost nothing back.
        private static void AnalyzeStateAccess(IList<CilInstruction> instructions, DispatcherValidationReport report)
        {
            var variableIndexLoads = 0;
            var elementStores = 0;
            var streamReads = 0;
            var pointerAdvances = 0;

            for (var i = 0; i < instructions.Count; i++)
            {
                var instruction = instructions[i];
                var code = instruction.OpCode.Code;

                if (IsElementLoad(code))
                {
                    var previous = i > 0 ? instructions[i - 1] : null;
                    if (previous != null && !IsIntegerConstant(previous.OpCode.Code))
                        variableIndexLoads++;
                }
                else if (IsElementStore(code))
                {
                    elementStores++;
                }

                if (instruction.Operand is IMethodDescriptor descriptor)
                {
                    var name = descriptor.Name?.ToString() ?? string.Empty;
                    if (name.StartsWith("Read", StringComparison.Ordinal) ||
                        string.Equals(name, "get_Position", StringComparison.Ordinal))
                    {
                        streamReads++;
                    }
                }

                // ldloc X ; ldc.i4 k ; add ; stloc X -- an advancing cursor.
                if (i + 3 < instructions.Count &&
                    TryGetLocalIndex(instruction, out var loaded, load: true) &&
                    IsIntegerConstant(instructions[i + 1].OpCode.Code) &&
                    instructions[i + 2].OpCode.Code == CilCode.Add &&
                    TryGetLocalIndex(instructions[i + 3], out var stored, load: false) &&
                    loaded == stored)
                {
                    pointerAdvances++;
                }
            }

            report.BytecodeFetchDetected = variableIndexLoads >= 4 || streamReads >= 4;
            report.VmStateDetected = (variableIndexLoads >= 4 && elementStores >= 4) ||
                                     (pointerAdvances >= 2 && variableIndexLoads >= 2);
        }

        // In an interpreter the selector comes from the fetched bytecode. In a
        // flattened method the targets themselves assign the next state, so the
        // selector is written all over the body.
        private static void AnalyzeSelector(
            IList<CilInstruction> instructions,
            IReadOnlyDictionary<CilInstruction, int> indexByInstruction,
            CilInstruction switchInstruction,
            IList<ICilLabel> labels,
            DispatcherValidationReport report)
        {
            if (!indexByInstruction.TryGetValue(switchInstruction, out var switchIndex) || switchIndex == 0)
                return;
            if (!TryGetLocalIndex(instructions[switchIndex - 1], out var selector, load: true))
                return;

            var selectorWrites = 0;
            foreach (var instruction in instructions)
            {
                if (TryGetLocalIndex(instruction, out var stored, load: false) && stored == selector)
                    selectorWrites++;
            }

            report.SelectorWrittenByTargets = selectorWrites >= Math.Max(8, labels.Count / 4);
        }

        // Distinct opcodes do distinct things. If nearly every branch funnels back
        // to one instruction, the branches are states, not handlers.
        private static void AnalyzeBlockUniformity(
            IList<CilInstruction> instructions,
            IReadOnlyDictionary<CilInstruction, int> indexByInstruction,
            IList<ICilLabel> labels,
            DispatcherValidationReport report)
        {
            var destinations = new Dictionary<int, int>();
            var sampled = 0;

            foreach (var label in labels)
            {
                if (!(label is CilInstructionLabel instructionLabel) ||
                    instructionLabel.Instruction == null ||
                    !indexByInstruction.TryGetValue(instructionLabel.Instruction, out var start))
                {
                    continue;
                }

                sampled++;
                for (var i = start; i < instructions.Count && i < start + 32; i++)
                {
                    var instruction = instructions[i];
                    if (instruction.OpCode.Code != CilCode.Br && instruction.OpCode.Code != CilCode.Br_S)
                        continue;
                    if (!(instruction.Operand is CilInstructionLabel target) ||
                        target.Instruction == null ||
                        !indexByInstruction.TryGetValue(target.Instruction, out var destination))
                    {
                        break;
                    }

                    destinations.TryGetValue(destination, out var count);
                    destinations[destination] = count + 1;
                    break;
                }
            }

            if (sampled == 0 || destinations.Count == 0)
                return;

            report.DominantShapeShare = (double) destinations.Values.Max() / sampled;
        }

        private static void Decide(DispatcherValidationReport report)
        {
            if (report.SwitchBranches == 0)
            {
                report.Result = DispatcherValidationResult.NotFound;
                return;
            }

            if (!report.BytecodeFetchDetected)
                report.HardFailures.Add("no bytecode fetch: nothing reads elements at a computed position");
            if (!report.VmStateDetected)
                report.HardFailures.Add("no persistent VM state model read and written by position");
            if (report.SelectorWrittenByTargets)
                report.HardFailures.Add("switch selector is assigned by its own targets (flattened control flow)");
            if (report.DominantShapeShare >= 0.5)
                report.HardFailures.Add($"{report.DominantShapeShare:P0} of branches funnel back to a single instruction");

            if (report.ExpectedOpcodes > 0 && report.SwitchBranches > report.ExpectedOpcodes * 3)
            {
                report.SoftFailures.Add(
                    $"branch count {report.SwitchBranches} far exceeds observed opcode count {report.ExpectedOpcodes}");
            }

            if (report.HardFailures.Count >= 2)
                report.Result = DispatcherValidationResult.Rejected;
            else if (report.HardFailures.Count == 1 || report.SoftFailures.Count > 0)
                report.Result = DispatcherValidationResult.Suspicious;
            else
                report.Result = DispatcherValidationResult.Valid;
        }

        private static bool IsElementLoad(CilCode code)
        {
            switch (code)
            {
                case CilCode.Ldelem:
                case CilCode.Ldelem_I:
                case CilCode.Ldelem_I1:
                case CilCode.Ldelem_I2:
                case CilCode.Ldelem_I4:
                case CilCode.Ldelem_I8:
                case CilCode.Ldelem_R4:
                case CilCode.Ldelem_R8:
                case CilCode.Ldelem_Ref:
                case CilCode.Ldelem_U1:
                case CilCode.Ldelem_U2:
                case CilCode.Ldelem_U4:
                    return true;
                default:
                    return false;
            }
        }

        private static bool IsElementStore(CilCode code)
        {
            switch (code)
            {
                case CilCode.Stelem:
                case CilCode.Stelem_I:
                case CilCode.Stelem_I1:
                case CilCode.Stelem_I2:
                case CilCode.Stelem_I4:
                case CilCode.Stelem_I8:
                case CilCode.Stelem_R4:
                case CilCode.Stelem_R8:
                case CilCode.Stelem_Ref:
                    return true;
                default:
                    return false;
            }
        }

        private static bool IsIntegerConstant(CilCode code)
        {
            switch (code)
            {
                case CilCode.Ldc_I4:
                case CilCode.Ldc_I4_S:
                case CilCode.Ldc_I4_M1:
                case CilCode.Ldc_I4_0:
                case CilCode.Ldc_I4_1:
                case CilCode.Ldc_I4_2:
                case CilCode.Ldc_I4_3:
                case CilCode.Ldc_I4_4:
                case CilCode.Ldc_I4_5:
                case CilCode.Ldc_I4_6:
                case CilCode.Ldc_I4_7:
                case CilCode.Ldc_I4_8:
                    return true;
                default:
                    return false;
            }
        }

        private static bool TryGetLocalIndex(CilInstruction instruction, out int localIndex, bool load)
        {
            localIndex = -1;
            if (instruction == null)
                return false;

            switch (instruction.OpCode.Code)
            {
                case CilCode.Ldloc_0: localIndex = 0; return load;
                case CilCode.Ldloc_1: localIndex = 1; return load;
                case CilCode.Ldloc_2: localIndex = 2; return load;
                case CilCode.Ldloc_3: localIndex = 3; return load;
                case CilCode.Stloc_0: localIndex = 0; return !load;
                case CilCode.Stloc_1: localIndex = 1; return !load;
                case CilCode.Stloc_2: localIndex = 2; return !load;
                case CilCode.Stloc_3: localIndex = 3; return !load;
                case CilCode.Ldloc:
                case CilCode.Ldloc_S:
                    if (!load)
                        return false;
                    break;
                case CilCode.Stloc:
                case CilCode.Stloc_S:
                    if (load)
                        return false;
                    break;
                default:
                    return false;
            }

            if (instruction.Operand is CilLocalVariable local)
            {
                localIndex = local.Index;
                return true;
            }

            return false;
        }
    }
}
