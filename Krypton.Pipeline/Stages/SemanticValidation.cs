using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;
using System.Text;
using AsmResolver.DotNet;
using Krypton.Core;
using Krypton.Core.Architecture;

namespace Krypton.Pipeline.Stages
{
    public sealed partial class SemanticValidation : IStage, IVmSemanticValidator
    {
        public string Name => nameof(SemanticValidation);

        public void Run(DevirtualizationCtx ctx)
        {
            Validate(ctx);
        }

        public void Validate(DevirtualizationCtx ctx)
        {
            if (ctx?.VirtualizedMethods == null || ctx.PatternMatcher == null || ctx.GetOperandTypes().Length == 0)
                return;

            var profile = BuildEffectiveProfile(ctx);
            if (!profile.Enabled)
                return;

            // Measured evidence first: what the protected assembly actually returns
            // settles bytes that no static rule can, and everything below reasons
            // about a table that is already correct where it could be measured.
            ReturnValueOracle.Apply(ctx);

            // Metadata signatures and payload operand encoding are the only evidence
            // here that does not depend on the opcode table, so what they prove is
            // pinned before any inference runs and is never revisited afterwards.
            if (IsEnvironmentEnabled("KRYPTON_TYPE_CONSTRAINTS"))
            {
                var typeOutcome = TypeConstraintAnchoring.Propagate(ctx);
                foreach (var line in TypeConstraintAnchoring.FormatSummary(typeOutcome).Split('\n'))
                    ctx.Options.Logger.Info(line.TrimEnd());

                ReportTypeCheckerDisagreements(ctx);

                // Runtime observations belong here: they read the interpreter's actual
                // behaviour rather than the opcode table, so they are pinned alongside
                // the metadata anchors and before any search runs. Entries that
                // contradict what is already proven are rejected, not merged.
                if (RuntimeTraceAnchors.ConfiguredPath() != null)
                {
                    var runtimeAnchors = RuntimeTraceAnchors.Apply(ctx, typeOutcome);
                    foreach (var line in RuntimeTraceAnchors.FormatSummary(runtimeAnchors).Split('\n'))
                        ctx.Options.Logger.Info(line.TrimEnd());
                }

                if (IsEnvironmentEnabled("KRYPTON_INVENTORY_ONLY"))
                {
                    var inventorySnapshot = new SoundOpcodeFixpointResult
                    {
                        Outcome = typeOutcome,
                        Families = SoundOpcodeFamilies.Classify(typeOutcome.Candidates),
                        Rounds = 0
                    };
                    var inventoryPath = SoundOpcodeInventory.Write(ctx, inventorySnapshot);
                    if (!string.IsNullOrWhiteSpace(inventoryPath))
                        ctx.Options.Logger.Info($"  sound opcode inventory: {inventoryPath}");
                    return;
                }

                if (IsEnvironmentEnabled("KRYPTON_GLOBAL_STACK_SOLVER"))
                {
                    var solved = GlobalStackConstraintSolver.Solve(ctx, typeOutcome.Candidates);
                    foreach (var line in GlobalStackConstraintSolver.FormatSummary(solved).Split('\n'))
                        ctx.Options.Logger.Info(line.TrimEnd());

                    var anchoredCount = 0;
                    var unresolvedCount = 0;
                    var inconclusiveCount = 0;

                    foreach (var resolution in solved.Bytes.Values)
                    {
                        switch (resolution.Status)
                        {
                            case ResolutionStatus.Anchored:
                                anchoredCount++;
                                break;
                            case ResolutionStatus.Unresolved:
                                unresolvedCount++;
                                continue;
                            default:
                                inconclusiveCount++;
                                continue;
                        }

                        // An existing metadata anchor is independent evidence; a
                        // disagreement is a bug to surface, never something to
                        // silently overwrite.
                        if (typeOutcome.Anchors.TryGetValue(resolution.VmByte, out var existing))
                        {
                            if (existing.OpCode != resolution.Surviving.First())
                            {
                                ctx.Options.Logger.Warning(
                                    $"INCONSISTENCY: vm 0x{resolution.VmByte:X2} is anchored to {existing.OpCode} by metadata " +
                                    $"but stack constraints prove {resolution.Surviving.First()}; keeping the metadata anchor.");
                            }

                            continue;
                        }

                        var record = new AnchorRecord
                        {
                            VmByte = resolution.VmByte,
                            OpCode = resolution.Surviving.First(),
                            Source = AnchorSource.CallArgument,
                            SiteCount = 0,
                            Round = 0
                        };
                        record.Evidence.Add(
                            "GlobalStackFeasibility: exhaustive whole-method search left exactly one assignment");
                        foreach (var elimination in resolution.Eliminations)
                            record.Evidence.Add(elimination);
                        typeOutcome.Anchors[resolution.VmByte] = record;
                    }

                    foreach (var anchor in typeOutcome.Anchors.Values)
                    {
                        if (!typeOutcome.Candidates.TryGetValue(anchor.VmByte, out var set))
                            continue;
                        set.Clear();
                        set.Add(anchor.OpCode);
                    }

                    var knownPlaintext = KnownPlaintextCryptoAnchoring.Solve(ctx, typeOutcome.Candidates);
                    foreach (var known in knownPlaintext)
                    {
                        typeOutcome.Candidates[known.VmByte].Clear();
                        typeOutcome.Candidates[known.VmByte].Add(known.OpCode);
                        var record = new AnchorRecord
                        {
                            VmByte = known.VmByte,
                            OpCode = known.OpCode,
                            Source = AnchorSource.KnownPlaintext,
                            SiteCount = known.Sites,
                            Round = 0
                        };
                        record.Evidence.Add(known.Evidence);
                        typeOutcome.Anchors[known.VmByte] = record;
                        ctx.Options.Logger.Info(
                            $"  [known-plaintext] vm 0x{known.VmByte:X2} -> {known.OpCode}: {known.Evidence}");
                    }

                    if (knownPlaintext.Count > 0)
                    {
                        var cascade = GlobalStackConstraintSolver.Solve(ctx, typeOutcome.Candidates);
                        var cascadeGains = 0;
                        foreach (var resolution in cascade.Bytes.Values)
                        {
                            if (resolution.Status != ResolutionStatus.Anchored ||
                                typeOutcome.Anchors.ContainsKey(resolution.VmByte))
                                continue;
                            var record = new AnchorRecord
                            {
                                VmByte = resolution.VmByte,
                                OpCode = resolution.Surviving.First(),
                                Source = AnchorSource.KnownPlaintext,
                                SiteCount = 0,
                                Round = 1
                            };
                            record.Evidence.Add(
                                "Cascade after known-plaintext anchors: exhaustive whole-method stack search left one assignment");
                            foreach (var elimination in resolution.Eliminations)
                                record.Evidence.Add(elimination);
                            typeOutcome.Anchors[resolution.VmByte] = record;
                            cascadeGains++;
                        }
                        ctx.Options.Logger.Info(
                            $"  known-plaintext cascade: +{cascadeGains} anchor(s); total={typeOutcome.Anchors.Count}");
                    }

                    var fixpoint = SoundOpcodeFixpoint.Run(ctx, typeOutcome);
                    typeOutcome = fixpoint.Outcome;

                    var inventoryPath = SoundOpcodeInventory.Write(ctx, fixpoint);
                    if (!string.IsNullOrWhiteSpace(inventoryPath))
                        ctx.Options.Logger.Info($"  sound opcode inventory: {inventoryPath}");

                    ctx.Options.Logger.Info(
                        $"  resolution states: ANCHORED={anchoredCount} UNRESOLVED={unresolvedCount} INCONCLUSIVE={inconclusiveCount}");
                }

                if (IsEnvironmentEnabled("KRYPTON_JOINT_TARGET_SOLVE"))
                {
                    var jointTargets = (Environment.GetEnvironmentVariable("KRYPTON_JOINT_TARGET_METHODS") ?? string.Empty)
                        .Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries)
                        .Select(n => n.Trim())
                        .Where(n => n.Length > 0)
                        .ToArray();

                    if (jointTargets.Length > 0)
                    {
                        var joint = TargetedJointSolver.Solve(ctx, typeOutcome.Candidates, jointTargets);

                        foreach (var line in TargetedJointSolver.Format(joint).Split('\n'))
                            ctx.Options.Logger.Info(line.TrimEnd());

                        foreach (var pair in joint.Proven)
                        {
                            if (typeOutcome.Candidates.TryGetValue(pair.Key, out var set) && set.Count > 1)
                            {
                                set.Clear();
                                set.Add(pair.Value);
                            }

                            if (!typeOutcome.Anchors.ContainsKey(pair.Key))
                            {
                                var rec = new AnchorRecord
                                {
                                    VmByte = pair.Key,
                                    OpCode = pair.Value,
                                    Source = AnchorSource.CallArgument,
                                    SiteCount = 0,
                                    Round = 0
                                };
                                rec.Evidence.Add(
                                    "GLOBALLY_PROVEN: unique assignment across the target methods " +
                                    "under stack, CFG, EH, operand and type constraints");
                                typeOutcome.Anchors[pair.Key] = rec;
                            }
                        }
                    }
                }

                if (IsEnvironmentEnabled("KRYPTON_APPLY_TYPE_ANCHORS"))
                    ApplyTypeAnchors(ctx, typeOutcome);
            }

            var verifiableIlMode = IsVerifiableIlModeEnabled();

            var cilEvaluationCache = new Dictionary<string, SemanticEvaluationResult>(StringComparer.Ordinal);
            var lowerer = new MethodRecompiling();
            var originalStates = new Dictionary<int, OpcodeMappingSnapshot>();
            var structuralBootstrapChanges = RetuneStructurallyObviousMappings(ctx, originalStates);
            var instanceConsumerBootstrapChanges = RetuneInstanceConsumerSourceBytes(ctx, originalStates);
            var initialBaseline = EvaluateMethods(ctx, profile, null);
            var initialCilBaseline = EvaluateCilMethods(ctx, lowerer, cilEvaluationCache);
            if (initialBaseline.TotalViolations <= 0)
            {
                if (initialCilBaseline.TotalViolations <= 0)
                {
                    if (instanceConsumerBootstrapChanges > 0)
                    {
                        ctx.Options.Logger.Info(
                            $"Semantic validation applied {instanceConsumerBootstrapChanges} instance-consumer bootstrap mapping(s) with clean baseline.");
                    }
                    else if (structuralBootstrapChanges > 0)
                    {
                        ctx.Options.Logger.Info(
                            $"Semantic validation applied {structuralBootstrapChanges} structural bootstrap mapping(s) with clean baseline.");
                    }
                    else
                    {
                        ctx.Options.Logger.Info("Semantic validation passed baseline checks.");
                    }
                    return;
                }
            }
            if (!profile.AllowRemap)
            {
                ctx.Options.Logger.Warning(
                    $"Semantic validation found vm issues={initialBaseline.TotalViolations}, cil issues={initialCilBaseline.TotalViolations}, but remapping is disabled by semantic settings.");
                return;
            }

            // Structural and instance-consumer bootstrap mappings define the baseline
            // evaluated above.  A later exploratory rollback must restore that baseline,
            // not the pre-bootstrap mappings that were already proven substantially worse.
            originalStates.Clear();

            var beforeViolations = initialBaseline.TotalViolations;
            var beforeCilIssues = initialCilBaseline.TotalViolations;
            var appliedChanges = 0;

            for (var pass = 0; pass < 8; pass++)
            {
                var baseline = EvaluateMethods(ctx, profile, null);
                if (baseline.TotalViolations <= 0)
                    break;
                var baselineCil = verifiableIlMode
                    ? EvaluateCilMethods(ctx, lowerer, cilEvaluationCache)
                    : null;
                var totalVmInstructions = CountTotalVmInstructions(ctx);
                var baselineCilScore = verifiableIlMode
                    ? ScoreState(ctx, baselineCil.TotalViolations, totalVmInstructions)
                    : 0;

                // The VM violation walk stops at unreachable code just like the recompiler
                // does, so a byte remapped to a terminal opcode scores well by hiding the
                // rest of the method. Score reachability alongside violations here too.
                var baselineVmScore = ScoreState(ctx, baseline.TotalViolations, totalVmInstructions);

                var candidates = CollectCandidateVmBytes(ctx, profile, baseline);
                SemanticCandidateAdjustment bestAdjustment = null;
                var bestCilImprovement = int.MinValue;

                foreach (var vmByte in candidates)
                {
                    if (!ctx.PatternMatcher.IsOpCodeValueKnown(vmByte))
                        continue;

                    var current = ctx.PatternMatcher.GetOpCodeValue(vmByte);
                    var baselineViolations = baseline.ViolationsByVmByte.TryGetValue(vmByte, out var baseViol) ? baseViol : 0;
                    var suspicious = IsSuspiciousLowFrequencyStackByte(ctx, vmByte, current);
                    if (baselineViolations <= 0 && !suspicious)
                        continue;

                    if (!ShouldTouchMapping(ctx, profile, vmByte, current, baselineViolations, suspicious))
                        continue;

                    foreach (var candidate in BuildCandidates(ctx, vmByte).Distinct())
                    {
                        if (candidate == current)
                            continue;
                        if (!AreCandidateOperandsSemanticallyCompatible(ctx, vmByte, candidate))
                            continue;

                        var substitution = new Dictionary<int, VMOpCode> { { vmByte, candidate } };
                        var eval = EvaluateMethods(ctx, profile, substitution);
                        var evalScore = ScoreState(ctx, eval.TotalViolations, totalVmInstructions, substitution);
                        var improvement = baselineVmScore - evalScore;
                        var minimumImprovement = suspicious ? 1 : profile.MinimumViolationImprovement;
                        if (improvement < minimumImprovement)
                            continue;
                        var candidateCilViolations = -1;
                        var candidateCilImprovement = 0;
                        if (verifiableIlMode)
                        {
                            var snapshot = CaptureMappingState(ctx, vmByte);
                            ApplyChanges(
                                ctx,
                                new Dictionary<int, VMOpCode?> { { vmByte, candidate } },
                                logChanges: false);
                            var candidateCil = EvaluateCilMethods(ctx, lowerer, cilEvaluationCache);
                            candidateCilViolations = ScoreState(ctx, candidateCil.TotalViolations, totalVmInstructions);
                            RestoreMappingState(ctx, snapshot);

                            candidateCilImprovement = baselineCilScore - candidateCilViolations;
                            if (candidateCilImprovement <= 0)
                                continue;
                        }

                        var candidateViolations = eval.ViolationsByVmByte.TryGetValue(vmByte, out var candViol)
                            ? candViol
                            : 0;

                        var isBetter = bestAdjustment == null;
                        if (!isBetter)
                        {
                            if (verifiableIlMode)
                            {
                                if (candidateCilImprovement > bestCilImprovement)
                                {
                                    isBetter = true;
                                }
                                else if (candidateCilImprovement == bestCilImprovement)
                                {
                                    if (improvement > bestAdjustment.TotalImprovement)
                                    {
                                        isBetter = true;
                                    }
                                    else if (improvement == bestAdjustment.TotalImprovement &&
                                             candidateViolations < bestAdjustment.DirectViolations)
                                    {
                                        isBetter = true;
                                    }
                                }
                            }
                            else if (improvement > bestAdjustment.TotalImprovement ||
                                     (improvement == bestAdjustment.TotalImprovement &&
                                      candidateViolations < bestAdjustment.DirectViolations))
                            {
                                isBetter = true;
                            }
                        }

                        if (isBetter)
                        {
                            bestAdjustment = new SemanticCandidateAdjustment(
                                vmByte,
                                current,
                                candidate,
                                baseline.TotalViolations,
                                eval.TotalViolations,
                                candidateViolations,
                                baselineCil?.TotalViolations ?? -1,
                                candidateCilViolations);
                            bestCilImprovement = candidateCilImprovement;
                        }
                    }
                }

                if (bestAdjustment == null)
                    break;

                if (!originalStates.ContainsKey(bestAdjustment.VmByte))
                    originalStates[bestAdjustment.VmByte] = CaptureMappingState(ctx, bestAdjustment.VmByte);
                ApplyChanges(
                    ctx,
                    new Dictionary<int, VMOpCode?> { { bestAdjustment.VmByte, bestAdjustment.NewOpcode } });
                appliedChanges++;
            }

            var cilAppliedChanges = 0;
            for (var pass = 0; pass < 8; pass++)
            {
                var baselineCil = EvaluateCilMethods(ctx, lowerer, cilEvaluationCache);
                if (baselineCil.TotalViolations <= 0)
                    break;

                var baselineVm = EvaluateMethods(ctx, profile, null);
                var baselineEntryUnderflows = CountReachableEntryUnderflowMethods(ctx);
                var totalVmInstructions = CountTotalVmInstructions(ctx);
                var baselineScore = ScoreState(ctx, baselineCil.TotalViolations, totalVmInstructions);
                var knownFrequency = BuildKnownFrequency(ctx);
                SemanticCandidateAdjustment bestAdjustment = null;
                var bestVmViolations = int.MaxValue;
                var bestEntryUnderflows = int.MaxValue;
                var allowedVmRegression = baselineCil.TotalViolations >= 10000
                    ? 32
                    : baselineCil.TotalViolations >= 1000
                        ? 24
                        : baselineCil.TotalViolations >= 200
                            ? 12
                            : 4;
                var allowedEntryUnderflowIncrease = 1;

                foreach (var pair in baselineCil.ViolationsByVmByte.OrderByDescending(p => p.Value).Take(16))
                {
                    var vmByte = pair.Key;
                    if (!ctx.PatternMatcher.IsOpCodeValueKnown(vmByte))
                        continue;
                    if (!ShouldTouchCilMapping(ctx, vmByte))
                        continue;

                    var current = ctx.PatternMatcher.GetOpCodeValue(vmByte);
                    var snapshot = CaptureMappingState(ctx, vmByte);
                    foreach (var candidate in BuildCilCandidates(ctx, vmByte, current, knownFrequency).Distinct())
                    {
                        if (candidate == current)
                            continue;
                        if (!AreCandidateOperandsSemanticallyCompatible(ctx, vmByte, candidate))
                            continue;

                        ApplyChanges(ctx, new Dictionary<int, VMOpCode?> { { vmByte, candidate } }, logChanges: false);
                        var candidateCil = EvaluateCilMethods(ctx, lowerer, cilEvaluationCache);
                        var candidateVm = EvaluateMethods(ctx, profile, null);
                        var candidateScore = ScoreState(ctx, candidateCil.TotalViolations, totalVmInstructions);
                        RestoreMappingState(ctx, snapshot);

                        var improvement = baselineScore - candidateScore;
                        if (improvement <= 0)
                            continue;

                        if (candidateVm.TotalViolations > baselineVm.TotalViolations + allowedVmRegression)
                            continue;

                        var candidateEntryUnderflows = baselineEntryUnderflows;
                        if (baselineEntryUnderflows > 0)
                        {
                            candidateEntryUnderflows = CountReachableEntryUnderflowMethods(ctx);
                            if (candidateEntryUnderflows > baselineEntryUnderflows + allowedEntryUnderflowIncrease)
                                continue;
                        }

                        if (bestAdjustment == null ||
                            candidateEntryUnderflows < bestEntryUnderflows ||
                            (candidateEntryUnderflows == bestEntryUnderflows &&
                             (candidateScore < bestAdjustment.CandidateViolations ||
                              (candidateScore == bestAdjustment.CandidateViolations &&
                               candidateVm.TotalViolations < bestVmViolations))))
                        {
                            bestAdjustment = new SemanticCandidateAdjustment(
                                vmByte,
                                current,
                                candidate,
                                baselineScore,
                                candidateScore,
                                pair.Value);
                            bestVmViolations = candidateVm.TotalViolations;
                            bestEntryUnderflows = candidateEntryUnderflows;
                        }
                    }
                }

                if (bestAdjustment == null)
                    break;

                if (!originalStates.ContainsKey(bestAdjustment.VmByte))
                    originalStates[bestAdjustment.VmByte] = CaptureMappingState(ctx, bestAdjustment.VmByte);
                ApplyChanges(
                    ctx,
                    new Dictionary<int, VMOpCode?> { { bestAdjustment.VmByte, bestAdjustment.NewOpcode } });
                if (baselineEntryUnderflows > 0 && bestEntryUnderflows < baselineEntryUnderflows)
                {
                    ctx.Options.Logger.Info(
                        $"Semantic CIL retune reduced entry-underflow methods: {baselineEntryUnderflows} -> {bestEntryUnderflows} via vm 0x{bestAdjustment.VmByte:X2} -> {bestAdjustment.NewOpcode}.");
                }
                cilAppliedChanges++;
            }

            var entryRetuneChanges = 0;
            for (var pass = 0; pass < 6; pass++)
            {
                var baselineEntryUnderflows = CountReachableEntryUnderflowMethods(ctx);
                if (baselineEntryUnderflows <= 0)
                    break;

                var baselineCil = EvaluateCilMethods(ctx, lowerer, cilEvaluationCache);
                var baselineVm = EvaluateMethods(ctx, profile, null);
                var totalVmInstructions = CountTotalVmInstructions(ctx);
                // Truncating a method also removes its entry underflow, so this loop needs
                // the same reachability accounting as the ones above.
                var baselineCilScore = ScoreState(ctx, baselineCil.TotalViolations, totalVmInstructions);
                var knownFrequency = BuildKnownFrequency(ctx);
                var candidateVmBytes = CollectEntryUnderflowCandidateVmBytes(ctx, baselineCil, knownFrequency);
                if (candidateVmBytes.Count == 0)
                    break;

                var allowedCilRegression = baselineCil.TotalViolations >= 10000
                    ? 128
                    : baselineCil.TotalViolations >= 1000
                        ? 64
                        : baselineCil.TotalViolations >= 200
                            ? 24
                            : 12;
                var allowedVmRegression = baselineCil.TotalViolations >= 10000
                    ? 48
                    : baselineCil.TotalViolations >= 1000
                        ? 32
                        : baselineCil.TotalViolations >= 200
                            ? 16
                            : 8;

                SemanticCandidateAdjustment bestAdjustment = null;
                var bestEntryUnderflows = baselineEntryUnderflows;
                var bestVmViolations = int.MaxValue;

                foreach (var vmByte in candidateVmBytes)
                {
                    if (!ctx.PatternMatcher.IsOpCodeValueKnown(vmByte))
                        continue;
                    if (!ShouldTouchEntryUnderflowMapping(ctx, vmByte))
                        continue;

                    var current = ctx.PatternMatcher.GetOpCodeValue(vmByte);
                    var snapshot = CaptureMappingState(ctx, vmByte);
                    foreach (var candidate in BuildEntryUnderflowCandidates(ctx, vmByte, current, knownFrequency).Distinct())
                    {
                        if (candidate == current)
                            continue;
                        if (!AreCandidateOperandsSemanticallyCompatible(ctx, vmByte, candidate))
                            continue;

                        ApplyChanges(ctx, new Dictionary<int, VMOpCode?> { { vmByte, candidate } }, logChanges: false);
                        var candidateEntryUnderflows = CountReachableEntryUnderflowMethods(ctx);
                        var candidateCil = EvaluateCilMethods(ctx, lowerer, cilEvaluationCache);
                        var candidateVm = EvaluateMethods(ctx, profile, null);
                        var candidateCilScore = ScoreState(ctx, candidateCil.TotalViolations, totalVmInstructions);
                        RestoreMappingState(ctx, snapshot);

                        if (candidateEntryUnderflows >= baselineEntryUnderflows)
                            continue;
                        if (candidateCilScore > baselineCilScore + allowedCilRegression)
                            continue;
                        if (candidateVm.TotalViolations > baselineVm.TotalViolations + allowedVmRegression)
                            continue;

                        if (bestAdjustment == null ||
                            candidateEntryUnderflows < bestEntryUnderflows ||
                            (candidateEntryUnderflows == bestEntryUnderflows &&
                             (candidateCil.TotalViolations < bestAdjustment.CandidateViolations ||
                              (candidateCil.TotalViolations == bestAdjustment.CandidateViolations &&
                               candidateVm.TotalViolations < bestVmViolations))))
                        {
                            bestAdjustment = new SemanticCandidateAdjustment(
                                vmByte,
                                current,
                                candidate,
                                baselineCil.TotalViolations,
                                candidateCil.TotalViolations,
                                baselineEntryUnderflows - candidateEntryUnderflows);
                            bestEntryUnderflows = candidateEntryUnderflows;
                            bestVmViolations = candidateVm.TotalViolations;
                        }
                    }
                }

                if (bestAdjustment == null)
                    break;

                if (!originalStates.ContainsKey(bestAdjustment.VmByte))
                    originalStates[bestAdjustment.VmByte] = CaptureMappingState(ctx, bestAdjustment.VmByte);
                ApplyChanges(
                    ctx,
                    new Dictionary<int, VMOpCode?> { { bestAdjustment.VmByte, bestAdjustment.NewOpcode } });
                ctx.Options.Logger.Info(
                    $"Semantic entry-underflow retune reduced methods: {baselineEntryUnderflows} -> {bestEntryUnderflows} via vm 0x{bestAdjustment.VmByte:X2} -> {bestAdjustment.NewOpcode}.");
                entryRetuneChanges++;
            }

            instanceConsumerBootstrapChanges += RetuneInstanceConsumerSourceBytes(
                ctx,
                originalStates);

            var switchSelectorChanges = RetuneSwitchSelectorBytes(
                ctx,
                lowerer,
                cilEvaluationCache,
                profile,
                originalStates);

            var after = EvaluateMethods(ctx, profile, null);
            var afterCil = EvaluateCilMethods(ctx, lowerer, cilEvaluationCache);
            if (afterCil.TotalViolations > beforeCilIssues && originalStates.Count > 0)
            {
                foreach (var snapshot in originalStates.Values)
                    RestoreMappingState(ctx, snapshot);

                var revertedVm = EvaluateMethods(ctx, profile, null);
                var revertedCil = EvaluateCilMethods(ctx, lowerer, cilEvaluationCache);
                ctx.Options.Logger.Warning(
                    $"Semantic validation rollback: reverted {originalStates.Count} mapping adjustment(s) because CIL issues regressed ({beforeCilIssues} -> {afterCil.TotalViolations}); final vm issues={revertedVm.TotalViolations}, cil issues={revertedCil.TotalViolations}.");
                return;
            }
            if (appliedChanges == 0 &&
                cilAppliedChanges == 0 &&
                entryRetuneChanges == 0 &&
                structuralBootstrapChanges == 0 &&
                instanceConsumerBootstrapChanges == 0 &&
                switchSelectorChanges == 0)
            {
                ctx.Options.Logger.Warning(
                    $"Semantic validation found vm issues={initialBaseline.TotalViolations}, cil issues={initialCilBaseline.TotalViolations}, but no safe mapping adjustment passed thresholds.");
                return;
            }

            ctx.Options.Logger.Warning(
                $"Semantic validation adjusted {appliedChanges + cilAppliedChanges + entryRetuneChanges + structuralBootstrapChanges + instanceConsumerBootstrapChanges + switchSelectorChanges} vm-byte mapping(s): vm violations {beforeViolations} -> {after.TotalViolations}, cil issues {beforeCilIssues} -> {afterCil.TotalViolations}.");
        }

        private void ApplyTypeAnchors(DevirtualizationCtx ctx, AnchorPropagationResult outcome)
        {
            var corrected = 0;
            foreach (var record in outcome.Anchors.Values.OrderBy(r => r.VmByte))
            {
                var vmByte = record.VmByte;
                var anchor = record.OpCode;
                ctx.AnchoredOpcodes.Add(vmByte);

                if (ctx.PatternMatcher.IsOpCodeValueKnown(vmByte) &&
                    ctx.PatternMatcher.GetOpCodeValue(vmByte) == anchor)
                {
                    continue;
                }

                ctx.PatternMatcher.SetOpCodeValue(anchor, vmByte);
                ctx.OpcodeConfidence ??= new Dictionary<int, OpcodeMappingConfidence>();
                ctx.OpcodeConfidence[vmByte] = new OpcodeMappingConfidence(anchor, 1.0, "metadata-signature");
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
                        instruction.OpCode = anchor;
                    }
                }

                corrected++;
                ctx.Options.Logger.Info(
                    $"Type anchor: vm 0x{vmByte:X2} -> {anchor} (round {record.Round}, {record.SiteCount} sites, {record.Source}).");
            }

            if (ctx.AnchoredOpcodes.Count > 0)
            {
                ctx.Options.Logger.Success(
                    $"Pinned {ctx.AnchoredOpcodes.Count} metadata-anchored opcode(s); {corrected} corrected an inferred mapping.");
            }
        }

        private bool IsAnchored(DevirtualizationCtx ctx, int vmByte)
        {
            return ctx?.AnchoredOpcodes != null && ctx.AnchoredOpcodes.Contains(vmByte);
        }

        private int RetuneStructurallyObviousMappings(
            DevirtualizationCtx ctx,
            IDictionary<int, OpcodeMappingSnapshot> originalStates)
        {
            if (ctx?.PatternMatcher == null || ctx.VirtualizedMethods == null)
                return 0;

            var applied = 0;
            for (var pass = 0; pass < 3; pass++)
            {
                var changedThisPass = 0;
                foreach (var vmByte in EnumerateObservedVmBytes(ctx))
                {
                    if (!ctx.PatternMatcher.IsOpCodeValueKnown(vmByte))
                        continue;
                    if (IsAnchored(ctx, vmByte))
                        continue;
                    if (IsOverrideMapping(ctx, vmByte))
                        continue;
                    if (!TryInferStructurallyObviousOpcode(ctx, vmByte, out var inferred))
                        continue;

                    var current = ctx.PatternMatcher.GetOpCodeValue(vmByte);
                    if (current == inferred)
                    {
                        MarkStructuralConfidence(ctx, vmByte, inferred);
                        continue;
                    }
                    if (IsTrustedHandlerFieldMapping(ctx, vmByte, current, inferred))
                        continue;
                    if (!IsOperandTypeCompatible(ctx, vmByte, inferred))
                        continue;
                    if (!AreCandidateOperandsSemanticallyCompatible(ctx, vmByte, inferred))
                        continue;

                    if (!originalStates.ContainsKey(vmByte))
                        originalStates[vmByte] = CaptureMappingState(ctx, vmByte);

                    ApplyStructuralChange(ctx, vmByte, inferred);
                    changedThisPass++;
                    applied++;
                }

                if (changedThisPass == 0)
                    break;
            }

            return applied;
        }

        private bool IsTrustedHandlerFieldMapping(
            DevirtualizationCtx ctx,
            int vmByte,
            VMOpCode current,
            VMOpCode inferred)
        {
            if (!IsFieldAccessOpcode(current) || !IsFieldAccessOpcode(inferred))
                return false;
            return ctx.OpcodeConfidence != null &&
                   ctx.OpcodeConfidence.TryGetValue(vmByte, out var confidence) &&
                   confidence.Confidence >= 0.9 &&
                   (confidence.Source ?? string.Empty).IndexOf(
                       "handler-pattern",
                       StringComparison.OrdinalIgnoreCase) >= 0;
        }

        private bool IsFieldAccessOpcode(VMOpCode opcode)
        {
            return opcode == VMOpCode.Ldfld ||
                   opcode == VMOpCode.Ldsfld ||
                   opcode == VMOpCode.Ldflda ||
                   opcode == VMOpCode.Ldsflda ||
                   opcode == VMOpCode.Stfld ||
                   opcode == VMOpCode.Stsfld;
        }

        private IEnumerable<int> EnumerateObservedVmBytes(DevirtualizationCtx ctx)
        {
            var seen = new HashSet<int>();
            foreach (var method in ctx.VirtualizedMethods)
            {
                var instructions = method?.MethodBody?.Instructions;
                if (instructions == null)
                    continue;
                foreach (var instruction in instructions)
                {
                    if (instruction == null)
                        continue;
                    if (seen.Add(instruction.VmByte))
                        yield return instruction.VmByte;
                }
            }
        }

        private bool IsSmallStructuralMethod(VMMethod method)
        {
            var count = method?.MethodBody?.Instructions?.Count ?? 0;
            return count > 0 && count <= 128;
        }

        private bool IsOverrideMapping(DevirtualizationCtx ctx, int vmByte)
        {
            return ctx.OpcodeConfidence != null &&
                   ctx.OpcodeConfidence.TryGetValue(vmByte, out var confidence) &&
                   (confidence.Source ?? string.Empty).IndexOf("override", StringComparison.OrdinalIgnoreCase) >= 0;
        }

        private void ApplyStructuralChange(DevirtualizationCtx ctx, int vmByte, VMOpCode opcode)
        {
            // structural-usage is derived: it resolves neighbours through the very
            // table it is about to write to.
            if (OpcodeMapping.IsSoundModeEnabled())
                return;

            ctx.PatternMatcher.SetOpCodeValue(opcode, vmByte);
            MarkStructuralConfidence(ctx, vmByte, opcode);

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

            ctx.Options.Logger.Info($"Semantic structural bootstrap: vm 0x{vmByte:X2} -> {opcode}.");
        }

        private void MarkStructuralConfidence(DevirtualizationCtx ctx, int vmByte, VMOpCode opcode)
        {
            ctx.OpcodeConfidence ??= new Dictionary<int, OpcodeMappingConfidence>();
            ctx.OpcodeConfidence[vmByte] = new OpcodeMappingConfidence(opcode, 0.99, "structural-usage");
        }

        private bool TryInferStructurallyObviousOpcode(
            DevirtualizationCtx ctx,
            int vmByte,
            out VMOpCode opcode)
        {
            opcode = VMOpCode.Nop;

            if (TryInferMetadataOperandOpcode(ctx, vmByte, out opcode))
                return true;
            if (TryInferIntegerConstantOpcode(ctx, vmByte, out opcode))
                return true;
            if (TryInferIndexOperandOpcode(ctx, vmByte, out opcode))
                return true;
            if (TryInferExceptionRegionOpcode(ctx, vmByte, out opcode))
                return true;
            if (TryInferArrayAndStackOpcode(ctx, vmByte, out opcode))
                return true;

            return false;
        }

        private bool TryInferMetadataOperandOpcode(DevirtualizationCtx ctx, int vmByte, out VMOpCode opcode)
        {
            opcode = VMOpCode.Nop;
            if (!ctx.TryGetOperandType(vmByte, out var operandType) || operandType != 1)
                return false;

            var stats = CollectOperandKindStats(ctx, vmByte);
            if (stats.Total == 0)
                return false;

            if (stats.MethodTokens == stats.Total)
            {
                opcode = stats.ConstructorMethods == stats.Total ? VMOpCode.Newobj : VMOpCode.Call;
                return true;
            }

            if (stats.FieldTokens == stats.Total)
            {
                if (stats.PrivateImplementationFields == stats.Total)
                {
                    opcode = VMOpCode.Ldtoken;
                    return true;
                }

                opcode = stats.InstanceFields > stats.StaticFields ? VMOpCode.Ldfld : VMOpCode.Ldsfld;
                return true;
            }

            if (stats.TypeTokens == stats.Total)
            {
                if (TryInferTypeTokenContextOpcode(ctx, vmByte, out opcode))
                    return true;
                if (LooksLikeNewarrUsage(ctx, vmByte))
                {
                    opcode = VMOpCode.Newarr;
                    return true;
                }
            }

            if (stats.UserStrings == stats.Total && !LooksLikeBranchOperandByte(ctx, vmByte))
            {
                opcode = VMOpCode.Ldstr;
                return true;
            }

            return false;
        }

        private bool TryInferTypeTokenContextOpcode(DevirtualizationCtx ctx, int vmByte, out VMOpCode opcode)
        {
            opcode = VMOpCode.Nop;
            var total = 0;
            var ldtoken = 0;
            var box = 0;
            var constrained = 0;

            foreach (var method in ctx.VirtualizedMethods)
            {
                var instructions = method?.MethodBody?.Instructions;
                if (instructions == null)
                    continue;

                for (var i = 0; i + 1 < instructions.Count; i++)
                {
                    var instruction = instructions[i];
                    if (instruction?.VmByte != vmByte || !(instruction.Operand is int))
                        continue;

                    total++;
                    if (!(instructions[i + 1]?.Operand is int methodToken))
                        continue;

                    IMethodDescriptor descriptor;
                    try
                    {
                        descriptor = ctx.Module.LookupMember(methodToken) as IMethodDescriptor;
                    }
                    catch
                    {
                        continue;
                    }

                    try
                    {
                        var fullName = descriptor?.FullName ?? string.Empty;
                        if (fullName.IndexOf("System.Type::GetTypeFromHandle", StringComparison.Ordinal) >= 0)
                        {
                            ldtoken++;
                            continue;
                        }

                        var signature = descriptor?.Signature ?? descriptor?.Resolve()?.Signature;
                        if (signature == null)
                            continue;
                        if (signature.HasThis && signature.ParameterTypes.Count == 0)
                        {
                            constrained++;
                            continue;
                        }
                        if (signature.ParameterTypes.Count > 0 &&
                            string.Equals(
                                signature.ParameterTypes[signature.ParameterTypes.Count - 1]?.FullName,
                                "System.Object",
                                StringComparison.Ordinal))
                        {
                            box++;
                        }
                    }
                    catch
                    {
                        // Malformed or non-method member references are not context evidence.
                    }
                }
            }

            if (total == 0)
                return false;
            if (ldtoken == total)
                opcode = VMOpCode.Ldtoken;
            else if (box == total)
                opcode = VMOpCode.Box;
            else if (constrained == total)
                opcode = VMOpCode.Constrained;
            else
                return false;
            return true;
        }

        private bool TryInferIntegerConstantOpcode(DevirtualizationCtx ctx, int vmByte, out VMOpCode opcode)
        {
            opcode = VMOpCode.Nop;
            if (!ctx.TryGetOperandType(vmByte, out var operandType) || operandType != 1)
                return false;
            if (ctx.PatternMatcher.IsOpCodeValueKnown(vmByte))
            {
                var current = ctx.PatternMatcher.GetOpCodeValue(vmByte);
                if (current != VMOpCode.Ldloc &&
                    current != VMOpCode.Ldloca &&
                    current != VMOpCode.Stloc &&
                    current != VMOpCode.Ldc_I4)
                {
                    return false;
                }
            }

            var total = 0;
            var arithmeticNeighbors = 0;
            var resolvedMetadata = 0;
            var branchTargets = 0;
            var invalidLocalIndices = 0;
            foreach (var method in ctx.VirtualizedMethods)
            {
                var instructions = method?.MethodBody?.Instructions;
                if (instructions == null)
                    continue;

                for (var i = 0; i < instructions.Count; i++)
                {
                    var instruction = instructions[i];
                    if (instruction?.VmByte != vmByte || !(instruction.Operand is int operand))
                        continue;

                    total++;
                    if (operand >= 0 && operand < instructions.Count)
                        branchTargets++;
                    var localCount = method?.MethodBody?.Locals?.Count ?? 0;
                    if (operand < 0 || operand >= localCount)
                        invalidLocalIndices++;
                    try
                    {
                        if (ctx.Module.LookupMember(operand) != null)
                            resolvedMetadata++;
                    }
                    catch
                    {
                        // Non-resolvable metadata-shaped values can be integer immediates.
                    }

                    var previous = i > 0 ? instructions[i - 1] : null;
                    var next = i + 1 < instructions.Count ? instructions[i + 1] : null;
                    if (IsIntegerArithmeticInstruction(ctx, previous) ||
                        IsIntegerArithmeticInstruction(ctx, next))
                    {
                        arithmeticNeighbors++;
                    }
                }
            }

            if (total < 4 || invalidLocalIndices == 0)
                return false;
            if (arithmeticNeighbors >= 8)
            {
                opcode = VMOpCode.Ldc_I4;
                return true;
            }
            if (resolvedMetadata * 2 >= total || branchTargets * 5 >= total * 4)
                return false;
            if (arithmeticNeighbors < 2 && invalidLocalIndices * 2 < total)
                return false;

            opcode = VMOpCode.Ldc_I4;
            return true;
        }

        private bool IsIntegerArithmeticInstruction(DevirtualizationCtx ctx, VMInstruction instruction)
        {
            if (instruction == null || !TryResolveOpcode(ctx, instruction, null, out var opcode))
                return false;

            switch (opcode)
            {
                case VMOpCode.Add:
                case VMOpCode.Sub:
                case VMOpCode.Xor:
                case VMOpCode.Shl:
                case VMOpCode.Shr:
                case VMOpCode.Neg:
                case VMOpCode.Not:
                case VMOpCode.Conv_I4:
                case VMOpCode.Conv_I8:
                case VMOpCode.Conv_U1:
                    return true;
                default:
                    return false;
            }
        }

        private OperandKindStats CollectOperandKindStats(DevirtualizationCtx ctx, int vmByte)
        {
            var stats = new OperandKindStats();
            foreach (var method in ctx.VirtualizedMethods)
            {
                var instructions = method?.MethodBody?.Instructions;
                if (instructions == null)
                    continue;

                foreach (var instruction in instructions)
                {
                    if (instruction?.VmByte != vmByte || !(instruction.Operand is int operand))
                        continue;

                    stats.Total++;
                    if (TryResolveUserString(ctx, operand))
                    {
                        stats.UserStrings++;
                        continue;
                    }

                    try
                    {
                        var member = ctx.Module.LookupMember(operand);
                        switch (member)
                        {
                            case IMethodDescriptor methodDescriptor:
                                stats.MethodTokens++;
                                if (IsConstructorMethod(methodDescriptor))
                                    stats.ConstructorMethods++;
                                break;

                            case IFieldDescriptor fieldDescriptor:
                                stats.FieldTokens++;
                                var resolvedField = fieldDescriptor.Resolve();
                                if (resolvedField?.IsStatic == true)
                                {
                                    stats.StaticFields++;
                                    var declaringName = resolvedField.DeclaringType?.Name?.Value ?? string.Empty;
                                    if (declaringName.IndexOf("PrivateImplementationDetails", StringComparison.OrdinalIgnoreCase) >= 0)
                                        stats.PrivateImplementationFields++;
                                }
                                else
                                {
                                    stats.InstanceFields++;
                                }
                                break;

                            case ITypeDefOrRef _:
                                stats.TypeTokens++;
                                break;
                        }
                    }
                    catch
                    {
                        // Non-token operands are handled by the index/control-flow heuristics.
                    }
                }
            }

            return stats;
        }

        private bool TryInferIndexOperandOpcode(DevirtualizationCtx ctx, int vmByte, out VMOpCode opcode)
        {
            opcode = VMOpCode.Nop;
            if (!ctx.TryGetOperandType(vmByte, out var operandType) || operandType != 1)
                return false;
            if (HasMetadataLikeOperands(ctx, vmByte) || HasLargeImmediateOperands(ctx, vmByte))
                return false;

            var stats = CollectIndexUsageStats(ctx, vmByte);
            if (stats.Total == 0)
                return false;

            if (stats.LocalLike == stats.Total && LooksLikeLocalAddressUsage(ctx, vmByte))
            {
                opcode = VMOpCode.Ldloca;
                return true;
            }

            if (stats.ArgLike == stats.Total && stats.Total >= 2)
            {
                opcode = VMOpCode.Ldarg;
                return true;
            }

            if (stats.LocalLike * 10 >= stats.Total * 7 && stats.Total >= 2)
            {
                if (stats.StoreLike > stats.LoadLike && stats.StoreLike * 10 >= stats.Total * 8)
                {
                    opcode = VMOpCode.Stloc;
                    return true;
                }

                if (stats.LoadLike >= stats.StoreLike || LooksLikeLocalIndexByte(ctx, vmByte))
                {
                    opcode = VMOpCode.Ldloc;
                    return true;
                }
            }

            return false;
        }

        private bool LooksLikeLocalAddressUsage(DevirtualizationCtx ctx, int vmByte)
        {
            var strongEvidence = 0;
            foreach (var method in ctx.VirtualizedMethods)
            {
                var instructions = method?.MethodBody?.Instructions;
                var locals = method?.MethodBody?.Locals;
                if (instructions == null || locals == null)
                    continue;

                for (var i = 0; i + 1 < instructions.Count; i++)
                {
                    var instruction = instructions[i];
                    if (instruction?.VmByte != vmByte ||
                        !(instruction.Operand is int localIndex) ||
                        localIndex < 0 ||
                        localIndex >= locals.Count)
                    {
                        continue;
                    }

                    var next = instructions[i + 1];
                    if (next == null)
                        continue;
                    if (TryInferTypeTokenContextOpcode(ctx, next.VmByte, out var tokenOpcode) &&
                        tokenOpcode == VMOpCode.Constrained)
                    {
                        strongEvidence++;
                        continue;
                    }
                    if (!(next.Operand is int methodToken))
                        continue;

                    try
                    {
                        var descriptor = ctx.Module.LookupMember(methodToken) as IMethodDescriptor;
                        var signature = descriptor?.Signature ?? descriptor?.Resolve()?.Signature;
                        var declaringType = descriptor?.DeclaringType?.Resolve();
                        if (signature?.HasThis == true && declaringType?.IsValueType == true)
                            strongEvidence++;
                    }
                    catch
                    {
                        // Unresolvable call sites do not contribute structural evidence.
                    }
                }
            }

            return strongEvidence >= 2;
        }

        private IndexUsageStats CollectIndexUsageStats(DevirtualizationCtx ctx, int vmByte)
        {
            var stats = new IndexUsageStats();
            foreach (var method in ctx.VirtualizedMethods)
            {
                if (!IsSmallStructuralMethod(method))
                    continue;

                var instructions = method?.MethodBody?.Instructions;
                if (instructions == null)
                    continue;

                var localCount = method?.MethodBody?.Locals?.Count ?? 0;
                var argumentCount = GetMethodArgumentCount(method);
                for (var i = 0; i < instructions.Count; i++)
                {
                    var instruction = instructions[i];
                    if (instruction?.VmByte != vmByte || !(instruction.Operand is int operand))
                        continue;

                    stats.Total++;
                    if (operand >= 0 && operand < localCount)
                        stats.LocalLike++;
                    if (operand >= 0 && operand < argumentCount)
                        stats.ArgLike++;

                    var previous = i > 0 ? instructions[i - 1] : null;
                    var next = i + 1 < instructions.Count ? instructions[i + 1] : null;
                    if (previous != null &&
                        TryResolveOpcode(ctx, previous, null, out var previousOpcode) &&
                        ProducesStackValue(ctx, method, previous, previousOpcode))
                    {
                        stats.StoreLike++;
                    }

                    if (next != null &&
                        TryResolveOpcode(ctx, next, null, out var nextOpcode) &&
                        ConsumesStackValue(ctx, method, next, nextOpcode))
                    {
                        stats.LoadLike++;
                    }
                }
            }

            return stats;
        }

        private bool TryInferExceptionRegionOpcode(DevirtualizationCtx ctx, int vmByte, out VMOpCode opcode)
        {
            opcode = VMOpCode.Nop;
            if (TryInferEndFinallyOpcode(ctx, vmByte))
            {
                opcode = VMOpCode.EndFinally;
                return true;
            }

            if (TryInferLeaveOpcode(ctx, vmByte))
            {
                opcode = VMOpCode.Leave;
                return true;
            }

            if (TryInferConditionalBranchOpcode(ctx, vmByte))
            {
                opcode = VMOpCode.BrFalse;
                return true;
            }

            return false;
        }

        private bool TryInferEndFinallyOpcode(DevirtualizationCtx ctx, int vmByte)
        {
            if (!ctx.TryGetOperandType(vmByte, out var operandType) || operandType != 0)
                return false;

            var total = 0;
            var handlerEndMatches = 0;
            foreach (var method in ctx.VirtualizedMethods)
            {
                if (!IsSmallStructuralMethod(method))
                    continue;

                var handlers = method?.MethodBody?.ExceptionHandlers;
                var instructions = method?.MethodBody?.Instructions;
                if (handlers == null || instructions == null)
                    continue;

                foreach (var instruction in instructions)
                {
                    if (instruction?.VmByte != vmByte)
                        continue;
                    total++;
                    var offset = instruction.Offset;
                    if (handlers.Any(eh =>
                            (eh.EHType == VMExceptionHandlerType.Finally || eh.EHType == VMExceptionHandlerType.Fault) &&
                            eh.HandlerEnd == offset))
                    {
                        handlerEndMatches++;
                    }
                }
            }

            return total > 0 && handlerEndMatches > 0 && handlerEndMatches * 2 >= total;
        }

        private bool TryInferLeaveOpcode(DevirtualizationCtx ctx, int vmByte)
        {
            if (!ctx.TryGetOperandType(vmByte, out var operandType) || operandType != 1)
                return false;

            var total = 0;
            var boundaryLeaves = 0;
            foreach (var method in ctx.VirtualizedMethods)
            {
                if (!IsSmallStructuralMethod(method))
                    continue;

                var handlers = method?.MethodBody?.ExceptionHandlers;
                var instructions = method?.MethodBody?.Instructions;
                if (handlers == null || instructions == null || handlers.Count == 0)
                    continue;

                foreach (var instruction in instructions)
                {
                    if (instruction?.VmByte != vmByte || !(instruction.Operand is int target))
                        continue;

                    total++;
                    var source = instruction.Offset;
                    if (handlers.Any(eh => IsEhBoundaryExit(eh, source, target)))
                        boundaryLeaves++;
                }
            }

            return total > 0 && boundaryLeaves > 0 && boundaryLeaves * 2 >= total;
        }

        private bool IsEhBoundaryExit(VMExceptionHandler eh, int source, int target)
        {
            if (source == eh.TryEnd && !IsInsideRange(target, eh.TryStart, eh.TryEnd))
                return true;
            if (source == eh.HandlerEnd && !IsInsideRange(target, eh.HandlerStart, eh.HandlerEnd))
                return true;
            return false;
        }

        private bool IsInsideRange(int offset, int start, int endInclusive)
        {
            return offset >= start && offset <= endInclusive;
        }

        private bool TryInferConditionalBranchOpcode(DevirtualizationCtx ctx, int vmByte)
        {
            if (!ctx.TryGetOperandType(vmByte, out var operandType) || operandType != 1)
                return false;
            if (LooksLikeLocalIndexByte(ctx, vmByte) || LooksLikeArgumentIndexByte(ctx, vmByte))
                return false;
            if (IsTrustedHandlerPattern(ctx, vmByte))
                return false;

            var total = 0;
            var validTargets = 0;
            var conditionalUses = 0;
            var boundaryLeaves = 0;
            foreach (var method in ctx.VirtualizedMethods)
            {
                if (!IsSmallStructuralMethod(method))
                    continue;

                var instructions = method?.MethodBody?.Instructions;
                if (instructions == null)
                    continue;

                for (var i = 0; i < instructions.Count; i++)
                {
                    var instruction = instructions[i];
                    if (instruction?.VmByte != vmByte || !(instruction.Operand is int target))
                        continue;

                    total++;
                    if (target >= 0 && target < instructions.Count)
                        validTargets++;
                    if (method.MethodBody.ExceptionHandlers.Any(eh => IsEhBoundaryExit(eh, instruction.Offset, target)))
                        boundaryLeaves++;

                    var previous = i > 0 ? instructions[i - 1] : null;
                    if (previous != null &&
                        TryResolveOpcode(ctx, previous, null, out var previousOpcode) &&
                        ProducesStackValue(ctx, method, previous, previousOpcode))
                    {
                        conditionalUses++;
                    }
                }
            }

            if (total == 0 || validTargets * 10 < total * 9)
                return false;
            if (boundaryLeaves * 2 >= total)
                return false;

            return conditionalUses > 0 && conditionalUses * 2 >= total;
        }


        // Detects the operandless VM byte that terminates an "array[index] = value"
        // statement. Reactor's integrity blob is built with hundreds of these in a
        // row, and every existing array detector is scoped to small structural
        // methods, so a byte used only inside a large method is invisible to them.
        // Getting this wrong is unusually destructive: the correct opcode pops 3 and
        // pushes nothing, while the arithmetic opcodes it gets confused with pop 2
        // and push 1, so each occurrence leaks two stack slots.
        private bool LooksLikeArrayStoreUsage(DevirtualizationCtx ctx, int vmByte, out VMOpCode opcode)
        {
            opcode = VMOpCode.Stelem_I1;
            var total = 0;
            var storeLike = 0;
            var referenceValues = 0;

            foreach (var method in ctx.VirtualizedMethods)
            {
                var instructions = method?.MethodBody?.Instructions;
                if (instructions == null)
                    continue;

                var expectedReturn = ResolveExpectedReturnStack(method);
                for (var i = 0; i < instructions.Count; i++)
                {
                    if (instructions[i]?.VmByte != vmByte)
                        continue;

                    total++;
                    if (i < 2)
                        continue;

                    // A store terminates a statement, so whatever follows must begin
                    // a new one rather than consume a produced value.
                    if (i + 1 < instructions.Count &&
                        (!TryResolveOpcode(ctx, instructions[i + 1], null, out var follower) ||
                         !StartsNewStatement(follower)))
                    {
                        continue;
                    }

                    // Walk back to a "load array, push index" pair and require the
                    // window between it and this byte to leave exactly three values.
                    for (var j = i - 2; j >= 0 && j >= i - 10; j--)
                    {
                        if (!TryResolveOpcode(ctx, instructions[j], null, out var arrayLoad) ||
                            !IsArrayReferenceLoad(arrayLoad))
                        {
                            continue;
                        }
                        if (!TryResolveOpcode(ctx, instructions[j + 1], null, out var indexPush) ||
                            indexPush != VMOpCode.Ldc_I4)
                        {
                            continue;
                        }

                        if (!TryMeasureWindowDepth(ctx, method, instructions, j, i, expectedReturn, out var depth))
                            break;
                        if (depth != 3)
                            break;

                        storeLike++;
                        if (TryResolveOpcode(ctx, instructions[i - 1], null, out var valueOpcode) &&
                            IsReferenceProducingOpcode(valueOpcode))
                        {
                            referenceValues++;
                        }
                        break;
                    }
                }
            }

            if (total < 8 || storeLike < 8 || storeLike * 2 < total)
                return false;

            opcode = referenceValues * 2 >= storeLike ? VMOpCode.Stelem_Ref : VMOpCode.Stelem_I1;
            return true;
        }

        private bool TryMeasureWindowDepth(
            DevirtualizationCtx ctx,
            VMMethod method,
            IList<VMInstruction> instructions,
            int start,
            int end,
            int expectedReturn,
            out int depth)
        {
            depth = 0;
            for (var k = start; k < end; k++)
            {
                if (!TryResolveOpcode(ctx, instructions[k], null, out var opcode))
                    return false;
                if (IsControlFlowOpcode(opcode))
                    return false;
                if (!TryGetStackEffect(opcode, instructions[k].Operand, ctx.Module, expectedReturn, out var pop, out var push))
                    return false;

                depth -= pop;
                if (depth < 0)
                    return false;
                depth += push;
                if (depth > 64)
                    return false;
            }

            return true;
        }

        private bool IsArrayReferenceLoad(VMOpCode opcode)
        {
            return opcode == VMOpCode.Ldloc ||
                   opcode == VMOpCode.Ldarg ||
                   opcode == VMOpCode.Ldsfld ||
                   opcode == VMOpCode.Ldfld;
        }

        private bool StartsNewStatement(VMOpCode opcode)
        {
            switch (opcode)
            {
                case VMOpCode.Ldloc:
                case VMOpCode.Ldarg:
                case VMOpCode.Ldc_I4:
                case VMOpCode.Ldsfld:
                case VMOpCode.Ldsflda:
                case VMOpCode.Ldfld:
                case VMOpCode.Ldflda:
                case VMOpCode.Ldstr:
                case VMOpCode.Ldnull:
                case VMOpCode.Ldtoken:
                case VMOpCode.Ldloca:
                case VMOpCode.Newobj:
                case VMOpCode.Call:
                case VMOpCode.Callvirt:
                case VMOpCode.Nop:
                case VMOpCode.Ret:
                case VMOpCode.Leave:
                case VMOpCode.Br:
                case VMOpCode.EndFinally:
                    return true;
                default:
                    return false;
            }
        }

        private bool IsReferenceProducingOpcode(VMOpCode opcode)
        {
            switch (opcode)
            {
                case VMOpCode.Ldstr:
                case VMOpCode.Ldnull:
                case VMOpCode.Newobj:
                case VMOpCode.Newarr:
                case VMOpCode.Box:
                case VMOpCode.Ldelem_Ref:
                    return true;
                default:
                    return false;
            }
        }

        private bool IsControlFlowOpcode(VMOpCode opcode)
        {
            switch (opcode)
            {
                case VMOpCode.Br:
                case VMOpCode.BrTrue:
                case VMOpCode.BrFalse:
                case VMOpCode.BrLessThan:
                case VMOpCode.BrGreaterThan:
                case VMOpCode.BrLessOrEqual:
                case VMOpCode.BrGreaterOrEqual:
                case VMOpCode.BrEqual:
                case VMOpCode.BrNotEqual:
                case VMOpCode.Switch:
                case VMOpCode.Leave:
                case VMOpCode.Ret:
                case VMOpCode.EndFinally:
                    return true;
                default:
                    return false;
            }
        }
        private bool TryInferArrayAndStackOpcode(DevirtualizationCtx ctx, int vmByte, out VMOpCode opcode)
        {
            opcode = VMOpCode.Nop;
            if (!ctx.TryGetOperandType(vmByte, out var operandType) || operandType != 0)
                return false;

            // Runs first: a mis-typed array store corrupts the stack for every
            // instruction after it, so it must win over the weaker shape guesses.
            if (LooksLikeArrayStoreUsage(ctx, vmByte, out var arrayStore))
            {
                opcode = arrayStore;
                return true;
            }

            if (LooksLikeNopAfterVoidCallUsage(ctx, vmByte))
            {
                opcode = VMOpCode.Nop;
                return true;
            }

            if (LooksLikeLdlenUsage(ctx, vmByte))
            {
                opcode = VMOpCode.Ldlen;
                return true;
            }

            if (LooksLikeConvI4AfterLdlenUsage(ctx, vmByte))
            {
                opcode = VMOpCode.Conv_I4;
                return true;
            }

            if (LooksLikeDupUsage(ctx, vmByte))
            {
                opcode = VMOpCode.Dup;
                return true;
            }

            if (ctx.PatternMatcher.GetOpCodeValue(vmByte) == VMOpCode.Dup &&
                !IsTrustedHandlerPattern(ctx, vmByte) &&
                LooksLikePopUsage(ctx, vmByte))
            {
                opcode = VMOpCode.Pop;
                return true;
            }

            if (LooksLikeStelemRefUsage(ctx, vmByte))
            {
                opcode = VMOpCode.Stelem_Ref;
                return true;
            }

            return false;
        }

        private bool LooksLikeNopAfterVoidCallUsage(DevirtualizationCtx ctx, int vmByte)
        {
            var total = 0;
            var afterVoidCall = 0;
            var afterVoidCallWithSuccessor = 0;

            foreach (var method in ctx.VirtualizedMethods)
            {
                var instructions = method?.MethodBody?.Instructions;
                if (instructions == null)
                    continue;

                for (var i = 0; i < instructions.Count; i++)
                {
                    if (instructions[i]?.VmByte != vmByte)
                        continue;

                    total++;
                    if (i == 0)
                        continue;

                    var previous = instructions[i - 1];
                    if (!TryResolveOpcode(ctx, previous, null, out var previousOpcode) ||
                        (previousOpcode != VMOpCode.Call && previousOpcode != VMOpCode.Callvirt))
                    {
                        continue;
                    }

                    if (!TryGetStackEffect(
                            previousOpcode,
                            previous.Operand,
                            ctx.Module,
                            ResolveExpectedReturnStack(method),
                            out _,
                            out var push) ||
                        push != 0)
                    {
                        continue;
                    }

                    afterVoidCall++;
                    if (i + 1 < instructions.Count)
                        afterVoidCallWithSuccessor++;
                }
            }

            // A stack-consuming opcode cannot legally follow a void call when no
            // value is produced. Repeated non-terminal occurrences also rule out
            // ret/endfinally, leaving the VM's operandless no-op as the safe shape.
            return total >= 8 &&
                   afterVoidCall >= 4 &&
                   afterVoidCallWithSuccessor >= 2 &&
                   afterVoidCall * 5 >= total;
        }

        private bool LooksLikePopUsage(DevirtualizationCtx ctx, int vmByte)
        {
            var total = 0;
            var popLike = 0;
            foreach (var method in ctx.VirtualizedMethods)
            {
                if (!IsSmallStructuralMethod(method))
                    continue;

                var instructions = method?.MethodBody?.Instructions;
                if (instructions == null)
                    continue;

                for (var i = 0; i < instructions.Count; i++)
                {
                    if (instructions[i]?.VmByte != vmByte)
                        continue;

                    total++;
                    if (method.MethodBody.ExceptionHandlers.Any(eh =>
                            eh.EHType == VMExceptionHandlerType.Catch &&
                            eh.HandlerStart == instructions[i].Offset))
                    {
                        popLike++;
                        continue;
                    }

                    var previous = i > 0 ? instructions[i - 1] : null;
                    if (previous != null &&
                        TryResolveOpcode(ctx, previous, null, out var previousOpcode) &&
                        ProducesStackValue(ctx, method, previous, previousOpcode))
                    {
                        popLike++;
                    }
                }
            }

            return total > 0 && popLike * 10 >= total * 3;
        }

        private bool LooksLikeDupUsage(DevirtualizationCtx ctx, int vmByte)
        {
            var total = 0;
            var dupLike = 0;
            foreach (var method in ctx.VirtualizedMethods)
            {
                if (!IsSmallStructuralMethod(method))
                    continue;

                var instructions = method?.MethodBody?.Instructions;
                if (instructions == null)
                    continue;

                for (var i = 0; i < instructions.Count; i++)
                {
                    if (instructions[i]?.VmByte != vmByte)
                        continue;

                    total++;
                    var next = i + 1 < instructions.Count ? instructions[i + 1] : null;
                    var nextNext = i + 2 < instructions.Count ? instructions[i + 2] : null;
                    if (next != null &&
                        nextNext != null &&
                        TryResolveOpcode(ctx, next, null, out var nextOpcode) &&
                        TryResolveOpcode(ctx, nextNext, null, out var nextNextOpcode) &&
                        nextOpcode == VMOpCode.Ldc_I4 &&
                        (nextNextOpcode == VMOpCode.Ldstr ||
                         nextNextOpcode == VMOpCode.Ldtoken ||
                         nextNextOpcode == VMOpCode.Ldloc ||
                         nextNextOpcode == VMOpCode.Ldarg))
                    {
                        dupLike++;
                    }
                }
            }

            return total > 0 && dupLike * 2 >= total;
        }

        private bool LooksLikeStelemRefUsage(DevirtualizationCtx ctx, int vmByte)
        {
            var total = 0;
            var stelemLike = 0;
            foreach (var method in ctx.VirtualizedMethods)
            {
                if (!IsSmallStructuralMethod(method))
                    continue;

                var instructions = method?.MethodBody?.Instructions;
                if (instructions == null)
                    continue;

                for (var i = 0; i < instructions.Count; i++)
                {
                    if (instructions[i]?.VmByte != vmByte)
                        continue;

                    total++;
                    var previous = i > 0 ? instructions[i - 1] : null;
                    var next = i + 1 < instructions.Count ? instructions[i + 1] : null;
                    if (previous != null &&
                        TryResolveOpcode(ctx, previous, null, out var previousOpcode) &&
                        (previousOpcode == VMOpCode.Ldstr ||
                         previousOpcode == VMOpCode.Ldloc ||
                        previousOpcode == VMOpCode.Ldarg ||
                        previousOpcode == VMOpCode.Call ||
                        previousOpcode == VMOpCode.Newobj) &&
                        next != null &&
                        TryResolveOpcode(ctx, next, null, out var nextOpcode) &&
                        (nextOpcode == VMOpCode.Dup ||
                         nextOpcode == VMOpCode.Stloc))
                    {
                        stelemLike++;
                    }
                }
            }

            return total > 0 && stelemLike * 2 >= total;
        }

        private bool LooksLikeLdlenUsage(DevirtualizationCtx ctx, int vmByte)
        {
            var total = 0;
            var ldlenLike = 0;
            foreach (var method in ctx.VirtualizedMethods)
            {
                if (!IsSmallStructuralMethod(method))
                    continue;

                var instructions = method?.MethodBody?.Instructions;
                if (instructions == null)
                    continue;

                for (var i = 0; i < instructions.Count; i++)
                {
                    if (instructions[i]?.VmByte != vmByte)
                        continue;

                    total++;
                    var previous = i > 0 ? instructions[i - 1] : null;
                    var next = i + 1 < instructions.Count ? instructions[i + 1] : null;
                    if (previous != null &&
                        next != null &&
                        TryResolveOpcode(ctx, previous, null, out var previousOpcode) &&
                        previousOpcode != VMOpCode.Ldc_I4 &&
                        previousOpcode != VMOpCode.Ldstr &&
                        previousOpcode != VMOpCode.Ldlen &&
                        previousOpcode != VMOpCode.Conv_I4 &&
                        ProducesStackValue(ctx, method, previous, previousOpcode) &&
                        IsLikelyConvI4Follower(ctx, method, instructions, i + 1))
                    {
                        ldlenLike++;
                    }
                }
            }

            return total > 0 && ldlenLike * 2 >= total;
        }

        private bool LooksLikeConvI4AfterLdlenUsage(DevirtualizationCtx ctx, int vmByte)
        {
            var total = 0;
            var convLike = 0;
            foreach (var method in ctx.VirtualizedMethods)
            {
                if (!IsSmallStructuralMethod(method))
                    continue;

                var instructions = method?.MethodBody?.Instructions;
                if (instructions == null)
                    continue;

                for (var i = 0; i < instructions.Count; i++)
                {
                    if (instructions[i]?.VmByte != vmByte)
                        continue;

                    total++;
                    var previous = i > 0 ? instructions[i - 1] : null;
                    if (previous != null &&
                        TryResolveOpcode(ctx, previous, null, out var previousOpcode) &&
                        previousOpcode == VMOpCode.Ldlen)
                    {
                        convLike++;
                    }
                }
            }

            return total > 0 && convLike * 2 >= total;
        }

        private bool IsLikelyConvI4Follower(
            DevirtualizationCtx ctx,
            VMMethod method,
            IList<VMInstruction> instructions,
            int index)
        {
            if (index < 0 || index >= instructions.Count)
                return false;

            if (TryResolveOpcode(ctx, instructions[index], null, out var opcode) &&
                opcode == VMOpCode.Conv_I4)
            {
                return true;
            }

            var next = index + 1 < instructions.Count ? instructions[index + 1] : null;
            if (next == null || !TryResolveOpcode(ctx, next, null, out var nextOpcode))
                return false;

            return nextOpcode == VMOpCode.Ldc_I4 ||
                   nextOpcode == VMOpCode.Sub ||
                   nextOpcode == VMOpCode.Call ||
                   nextOpcode == VMOpCode.Callvirt;
        }

        private bool IsTrustedHandlerPattern(DevirtualizationCtx ctx, int vmByte)
        {
            if (ctx.OpcodeConfidence == null || !ctx.OpcodeConfidence.TryGetValue(vmByte, out var confidence))
                return false;

            var source = confidence.Source ?? string.Empty;
            return confidence.Confidence >= 0.90 &&
                   source.IndexOf("handler-pattern", StringComparison.OrdinalIgnoreCase) >= 0;
        }

        private bool IsStructuralConfidence(OpcodeMappingConfidence confidence)
        {
            var source = confidence?.Source ?? string.Empty;
            return confidence != null &&
                   confidence.Confidence >= 0.98 &&
                   source.IndexOf("structural-usage", StringComparison.OrdinalIgnoreCase) >= 0;
        }

        private bool LooksLikeNewarrUsage(DevirtualizationCtx ctx, int vmByte)
        {
            var total = 0;
            var newarrLike = 0;
            foreach (var method in ctx.VirtualizedMethods)
            {
                if (!IsSmallStructuralMethod(method))
                    continue;

                var instructions = method?.MethodBody?.Instructions;
                if (instructions == null)
                    continue;

                for (var i = 0; i < instructions.Count; i++)
                {
                    if (instructions[i]?.VmByte != vmByte)
                        continue;

                    total++;
                    var previous = i > 0 ? instructions[i - 1] : null;
                    var next = i + 1 < instructions.Count ? instructions[i + 1] : null;
                    if (previous != null &&
                        TryResolveOpcode(ctx, previous, null, out var previousOpcode) &&
                        ProducesStackValue(ctx, method, previous, previousOpcode) &&
                        (next == null ||
                         !TryResolveOpcode(ctx, next, null, out var nextOpcode) ||
                         nextOpcode == VMOpCode.Dup ||
                         nextOpcode == VMOpCode.Stloc))
                    {
                        newarrLike++;
                    }
                }
            }

            return total > 0 && newarrLike * 2 >= total;
        }

        private bool ProducesStackValue(
            DevirtualizationCtx ctx,
            VMMethod method,
            VMInstruction instruction,
            VMOpCode opcode)
        {
            if (!TryGetStackEffect(opcode, instruction?.Operand, ctx.Module, ResolveExpectedReturnStack(method), out _, out var push))
                return false;
            return push > 0;
        }

        private bool ConsumesStackValue(
            DevirtualizationCtx ctx,
            VMMethod method,
            VMInstruction instruction,
            VMOpCode opcode)
        {
            if (!TryGetStackEffect(opcode, instruction?.Operand, ctx.Module, ResolveExpectedReturnStack(method), out var pop, out _))
                return false;
            return pop > 0;
        }

        private int RetuneInstanceConsumerSourceBytes(
            DevirtualizationCtx ctx,
            IDictionary<int, OpcodeMappingSnapshot> originalStates)
        {
            if (ctx?.PatternMatcher == null)
                return 0;

            var applied = 0;
            foreach (var vmByte in CollectInstanceConsumerCandidateVmBytes(ctx))
            {
                if (!ctx.PatternMatcher.IsOpCodeValueKnown(vmByte))
                    continue;
                if (!ctx.TryGetOperandType(vmByte, out var operandType) || operandType != 1)
                    continue;
                if (HasLargeImmediateOperands(ctx, vmByte))
                    continue;
                if (!ShouldTouchCilMapping(ctx, vmByte))
                    continue;

                var current = ctx.PatternMatcher.GetOpCodeValue(vmByte);
                if (current != VMOpCode.Ldc_I4)
                    continue;

                VMOpCode? forced = null;
                if (LooksLikeLocalIndexByte(ctx, vmByte) &&
                    AreCandidateOperandsSemanticallyCompatible(ctx, vmByte, VMOpCode.Ldloc))
                {
                    forced = VMOpCode.Ldloc;
                }
                else if (LooksLikeArgumentIndexByte(ctx, vmByte) &&
                         AreCandidateOperandsSemanticallyCompatible(ctx, vmByte, VMOpCode.Ldarg))
                {
                    forced = VMOpCode.Ldarg;
                }

                if (!forced.HasValue || forced.Value == current)
                    continue;

                if (!originalStates.ContainsKey(vmByte))
                    originalStates[vmByte] = CaptureMappingState(ctx, vmByte);
                ApplyChanges(ctx, new Dictionary<int, VMOpCode?> { { vmByte, forced.Value } });
                ctx.Options.Logger.Info(
                    $"Semantic instance-consumer bootstrap: vm 0x{vmByte:X2} {current} -> {forced.Value}.");
                applied++;
            }

            return applied;
        }

        private IReadOnlyCollection<int> CollectInstanceConsumerCandidateVmBytes(DevirtualizationCtx ctx)
        {
            var result = new List<int>();
            var added = new HashSet<int>();
            if (ctx?.VirtualizedMethods == null)
                return result;

            foreach (var method in ctx.VirtualizedMethods)
            {
                var instructions = method?.MethodBody?.Instructions;
                if (instructions == null || instructions.Count < 2)
                    continue;

                for (var i = 0; i < instructions.Count - 1; i++)
                {
                    var current = instructions[i];
                    var next = instructions[i + 1];
                    if (current == null || next == null)
                        continue;
                    if (!TryResolveOpcode(ctx, next, null, out var nextOpcode) || nextOpcode != VMOpCode.Callvirt)
                        continue;
                    if (!IsNoArgumentCallvirt(ctx, next))
                        continue;

                    if (added.Add(current.VmByte))
                        result.Add(current.VmByte);
                }
            }

            return result;
        }

        private bool IsNoArgumentCallvirt(DevirtualizationCtx ctx, VMInstruction instruction)
        {
            if (!(instruction?.Operand is int token))
                return false;

            try
            {
                var descriptor = ctx?.Module?.LookupMember(token) as IMethodDescriptor;
                var signature = descriptor?.Signature ?? descriptor?.Resolve()?.Signature;
                return signature != null && signature.ParameterTypes.Count == 0;
            }
            catch
            {
                return false;
            }
        }

        private int RetuneSwitchSelectorBytes(
            DevirtualizationCtx ctx,
            MethodRecompiling lowerer,
            IDictionary<string, SemanticEvaluationResult> cilEvaluationCache,
            SemanticValidationProfile profile,
            IDictionary<int, OpcodeMappingSnapshot> originalStates)
        {
            if (ctx?.PatternMatcher == null)
                return 0;

            var applied = 0;
            var selectorVmBytes = CollectSwitchSelectorCandidateVmBytes(ctx);
            foreach (var vmByte in selectorVmBytes)
            {
                if (!ctx.PatternMatcher.IsOpCodeValueKnown(vmByte))
                    continue;

                var current = ctx.PatternMatcher.GetOpCodeValue(vmByte);
                if (IsSwitchSelectorValueProducer(current))
                    continue;

                VMOpCode? forced = null;
                if (LooksLikeLocalIndexByte(ctx, vmByte) &&
                    AreCandidateOperandsSemanticallyCompatible(ctx, vmByte, VMOpCode.Ldloc))
                {
                    forced = VMOpCode.Ldloc;
                }
                else if (LooksLikeArgumentIndexByte(ctx, vmByte) &&
                         AreCandidateOperandsSemanticallyCompatible(ctx, vmByte, VMOpCode.Ldarg))
                {
                    forced = VMOpCode.Ldarg;
                }

                if (!forced.HasValue || forced.Value == current)
                    continue;

                if (!originalStates.ContainsKey(vmByte))
                    originalStates[vmByte] = CaptureMappingState(ctx, vmByte);
                ApplyChanges(ctx, new Dictionary<int, VMOpCode?> { { vmByte, forced.Value } });
                ctx.Options.Logger.Info(
                    $"Semantic switch-selector bootstrap: vm 0x{vmByte:X2} {current} -> {forced.Value}.");
                applied++;
            }

            for (var pass = 0; pass < 4; pass++)
            {
                var baselineCil = EvaluateCilMethods(ctx, lowerer, cilEvaluationCache);
                var baselineVm = EvaluateMethods(ctx, profile, null);
                var baselineUnderflows = CountReachableEntryUnderflowMethods(ctx);
                var candidates = CollectSwitchSelectorCandidateVmBytes(ctx);
                if (candidates.Count == 0)
                    break;

                SemanticCandidateAdjustment best = null;
                var bestVmViolations = int.MaxValue;
                var bestUnderflows = int.MaxValue;
                foreach (var vmByte in candidates)
                {
                    if (!ctx.PatternMatcher.IsOpCodeValueKnown(vmByte))
                        continue;

                    var current = ctx.PatternMatcher.GetOpCodeValue(vmByte);
                    var snapshot = CaptureMappingState(ctx, vmByte);
                    foreach (var candidate in BuildSwitchSelectorCandidates(ctx, vmByte, current))
                    {
                        if (candidate == current)
                            continue;
                        if (!AreCandidateOperandsSemanticallyCompatible(ctx, vmByte, candidate))
                            continue;

                        ApplyChanges(ctx, new Dictionary<int, VMOpCode?> { { vmByte, candidate } }, logChanges: false);
                        var candidateCil = EvaluateCilMethods(ctx, lowerer, cilEvaluationCache);
                        var candidateVm = EvaluateMethods(ctx, profile, null);
                        var candidateUnderflows = CountReachableEntryUnderflowMethods(ctx);
                        RestoreMappingState(ctx, snapshot);

                        if (candidateCil.TotalViolations > baselineCil.TotalViolations + 16)
                            continue;
                        if (candidateVm.TotalViolations > baselineVm.TotalViolations + 16)
                            continue;
                        if (candidateUnderflows > baselineUnderflows + 1)
                            continue;
                        if (candidateCil.TotalViolations >= baselineCil.TotalViolations &&
                            candidateUnderflows >= baselineUnderflows)
                        {
                            continue;
                        }

                        if (best == null ||
                            candidateUnderflows < bestUnderflows ||
                            (candidateUnderflows == bestUnderflows &&
                             (candidateCil.TotalViolations < best.CandidateViolations ||
                              (candidateCil.TotalViolations == best.CandidateViolations &&
                               candidateVm.TotalViolations < bestVmViolations))))
                        {
                            best = new SemanticCandidateAdjustment(
                                vmByte,
                                current,
                                candidate,
                                baselineCil.TotalViolations,
                                candidateCil.TotalViolations,
                                baselineUnderflows - candidateUnderflows);
                            bestVmViolations = candidateVm.TotalViolations;
                            bestUnderflows = candidateUnderflows;
                        }
                    }
                }

                if (best == null)
                    break;

                if (!originalStates.ContainsKey(best.VmByte))
                    originalStates[best.VmByte] = CaptureMappingState(ctx, best.VmByte);
                ApplyChanges(
                    ctx,
                    new Dictionary<int, VMOpCode?> { { best.VmByte, best.NewOpcode } });
                ctx.Options.Logger.Info(
                    $"Semantic switch-selector retune: vm 0x{best.VmByte:X2} {best.OldOpcode} -> {best.NewOpcode} (cil {best.BaselineViolations}->{best.CandidateViolations}, underflow={best.DirectViolations}).");
                applied++;
            }

            return applied;
        }

        private IReadOnlyCollection<int> CollectSwitchSelectorCandidateVmBytes(DevirtualizationCtx ctx)
        {
            var result = new List<int>();
            var added = new HashSet<int>();
            if (ctx?.VirtualizedMethods == null)
                return result;

            foreach (var method in ctx.VirtualizedMethods)
            {
                var instructions = method?.MethodBody?.Instructions;
                if (instructions == null || instructions.Count < 2)
                    continue;

                for (var i = 1; i < instructions.Count; i++)
                {
                    var current = instructions[i];
                    var previous = instructions[i - 1];
                    if (current == null || previous == null)
                        continue;
                    if (!TryResolveOpcode(ctx, current, null, out var currentOpcode) || currentOpcode != VMOpCode.Switch)
                        continue;
                    if (!TryResolveOpcode(ctx, previous, null, out var previousOpcode))
                        continue;
                    if (IsSwitchSelectorValueProducer(previousOpcode))
                        continue;

                    if (added.Add(previous.VmByte))
                        result.Add(previous.VmByte);
                }
            }

            return result;
        }

        private IReadOnlyCollection<VMOpCode> BuildSwitchSelectorCandidates(
            DevirtualizationCtx ctx,
            int vmByte,
            VMOpCode current)
        {
            var candidates = new List<VMOpCode>();
            if (ctx.TryGetOperandType(vmByte, out var operandType))
            {
                if (operandType == 1)
                {
                    if (LooksLikeLocalIndexByte(ctx, vmByte))
                        candidates.Add(VMOpCode.Ldloc);
                    if (LooksLikeArgumentIndexByte(ctx, vmByte))
                        candidates.Add(VMOpCode.Ldarg);
                    candidates.Add(VMOpCode.Ldc_I4);
                    candidates.Add(VMOpCode.Ldloc);
                    candidates.Add(VMOpCode.Ldarg);
                }
                else if (operandType == 0)
                {
                    candidates.Add(VMOpCode.Dup);
                    candidates.Add(VMOpCode.Nop);
                }
            }

            return candidates
                .Where(candidate => candidate != current)
                .Where(candidate => IsOperandTypeCompatible(ctx, vmByte, candidate))
                .Distinct()
                .ToArray();
        }

        private bool IsSwitchSelectorValueProducer(VMOpCode opcode)
        {
            switch (opcode)
            {
                case VMOpCode.Ldarg:
                case VMOpCode.Ldloc:
                case VMOpCode.Ldloca:
                case VMOpCode.Ldc_I4:
                case VMOpCode.Ldc_R4:
                case VMOpCode.Ldc_R8:
                case VMOpCode.Dup:
                case VMOpCode.Conv_I4:
                case VMOpCode.Conv_I8:
                case VMOpCode.Conv_U1:
                    return true;
                default:
                    return false;
            }
        }

        private SemanticValidationProfile BuildEffectiveProfile(DevirtualizationCtx ctx)
        {
            var profile = CloneProfile(new SemanticValidationProfile());

            if (string.Equals(
                    Environment.GetEnvironmentVariable("KRYPTON_DISABLE_SEMANTIC_VALIDATION"),
                    "1",
                    StringComparison.Ordinal))
            {
                profile.Enabled = false;
                return profile;
            }

            if (string.Equals(
                    Environment.GetEnvironmentVariable("KRYPTON_DISABLE_SEMANTIC_REMAP"),
                    "1",
                    StringComparison.Ordinal))
            {
                profile.AllowRemap = false;
            }

            // If many instructions are still unresolved, allow a stronger semantic
            // cleanup pass for low-confidence mappings before recompilation.
            var unresolved = 0;
            var total = 0;
            foreach (var method in ctx.VirtualizedMethods)
            {
                var instructions = method?.MethodBody?.Instructions;
                if (instructions == null)
                    continue;

                total += instructions.Count;
                for (var i = 0; i < instructions.Count; i++)
                {
                    if (!ctx.PatternMatcher.IsOpCodeValueKnown(instructions[i].VmByte))
                        unresolved++;
                }
            }

            if (total > 0 && unresolved >= 64 && unresolved * 5 >= total)
            {
                profile.AllowPruneHandlerPatternMappings = true;
                profile.MinimumViolationImprovement = Math.Min(profile.MinimumViolationImprovement, 1);
                profile.LowConfidenceThreshold = Math.Max(profile.LowConfidenceThreshold, 0.88);
                profile.ViolationRateThreshold = Math.Min(profile.ViolationRateThreshold, 0.2);
            }
            if (IsVerifiableIlModeEnabled())
            {
                // Bias for conservative rewrites that improve structural CIL validity.
                profile.MinimumViolationImprovement = Math.Max(profile.MinimumViolationImprovement, 1);
                profile.AllowPruneHandlerPatternMappings = true;
            }

            return profile;
        }

        private SemanticValidationProfile CloneProfile(SemanticValidationProfile source)
        {
            source ??= new SemanticValidationProfile();
            return new SemanticValidationProfile
            {
                Enabled = source.Enabled,
                MinimumVmByteOccurrences = source.MinimumVmByteOccurrences,
                ViolationRateThreshold = source.ViolationRateThreshold,
                LowConfidenceThreshold = source.LowConfidenceThreshold,
                AllowRemap = source.AllowRemap,
                MinimumViolationImprovement = source.MinimumViolationImprovement,
                AllowPruneHandlerPatternMappings = source.AllowPruneHandlerPatternMappings,
                MaxStackDepth = source.MaxStackDepth,
                MaxStatesPerInstruction = source.MaxStatesPerInstruction
            };
        }

        private IReadOnlyCollection<int> CollectCandidateVmBytes(
            DevirtualizationCtx ctx,
            SemanticValidationProfile profile,
            SemanticEvaluationResult baseline)
        {
            var knownFrequency = BuildKnownFrequency(ctx);
            var result = new List<int>();
            var added = new HashSet<int>();

            foreach (var pair in baseline.ViolationsByVmByte.OrderByDescending(p => p.Value))
            {
                var vmByte = pair.Key;
                var violations = pair.Value;
                if (!knownFrequency.TryGetValue(vmByte, out var occurrences))
                    continue;
                if (occurrences < profile.MinimumVmByteOccurrences)
                    continue;

                var rate = (double) violations / occurrences;
                if (rate < profile.ViolationRateThreshold)
                    continue;

                if (added.Add(vmByte))
                    result.Add(vmByte);
            }

            foreach (var pair in knownFrequency.OrderBy(p => p.Value).ThenBy(p => p.Key))
            {
                var vmByte = pair.Key;
                if (!ctx.PatternMatcher.IsOpCodeValueKnown(vmByte))
                    continue;

                var current = ctx.PatternMatcher.GetOpCodeValue(vmByte);
                if (!IsSuspiciousLowFrequencyStackByte(ctx, vmByte, current))
                    continue;

                if (added.Add(vmByte))
                    result.Add(vmByte);
            }

            return result;
        }

        private Dictionary<int, int> BuildKnownFrequency(DevirtualizationCtx ctx)
        {
            var knownFrequency = new Dictionary<int, int>();
            foreach (var method in ctx.VirtualizedMethods)
            {
                foreach (var instruction in method.MethodBody.Instructions)
                {
                    if (!ctx.PatternMatcher.IsOpCodeValueKnown(instruction.VmByte))
                        continue;
                    if (!knownFrequency.TryGetValue(instruction.VmByte, out var count))
                        count = 0;
                    knownFrequency[instruction.VmByte] = count + 1;
                }
            }

            return knownFrequency;
        }

        private bool ShouldTouchMapping(
            DevirtualizationCtx ctx,
            SemanticValidationProfile profile,
            int vmByte,
            VMOpCode current,
            int baselineViolations,
            bool suspicious)
        {
            if (IsAnchored(ctx, vmByte))
                return false;

            if (suspicious)
                return true;
            if (!IsOperandTypeCompatible(ctx, vmByte, current))
                return true;
            if (!AreCandidateOperandsSemanticallyCompatible(ctx, vmByte, current))
                return true;
            if (ctx.OpcodeConfidence == null || !ctx.OpcodeConfidence.TryGetValue(vmByte, out var confidence))
                return profile.AllowPruneHandlerPatternMappings;

            var source = confidence.Source ?? string.Empty;
            if (source.IndexOf("override", StringComparison.OrdinalIgnoreCase) >= 0)
                return false;
            if (IsStructuralConfidence(confidence))
                return false;
            var looksInference =
                source.IndexOf("inference", StringComparison.OrdinalIgnoreCase) >= 0 ||
                source.IndexOf("neighbor", StringComparison.OrdinalIgnoreCase) >= 0 ||
                source.IndexOf("dominant", StringComparison.OrdinalIgnoreCase) >= 0 ||
                source.IndexOf("last-resort", StringComparison.OrdinalIgnoreCase) >= 0 ||
                source.IndexOf("semantic", StringComparison.OrdinalIgnoreCase) >= 0;
            if (!profile.AllowPruneHandlerPatternMappings &&
                source.IndexOf("handler-pattern", StringComparison.OrdinalIgnoreCase) >= 0 &&
                !looksInference)
            {
                return false;
            }

            if (profile.AllowPruneHandlerPatternMappings && baselineViolations > 0)
                return true;

            return looksInference || confidence.Confidence < profile.LowConfidenceThreshold;
        }

        private bool IsVmDelegateConstructionCall(DevirtualizationCtx ctx, IList<VMInstruction> instructions, int index)
        {
            // Delegate construction virtualizes as an ordinary Call to the target
            // method immediately followed by Newobj on the delegate type. At the
            // VM level that Call never actually invokes anything -- it takes the
            // method's function pointer -- so it must be scored as a push, not
            // against the target method's real (this + args) pop count.
            if (index + 1 >= instructions.Count)
                return false;

            var next = instructions[index + 1];
            if (!TryResolveOpcode(ctx, next, null, out var nextOpcode) || nextOpcode != VMOpCode.Newobj)
                return false;
            if (!(next.Operand is int ctorToken))
                return false;

            try
            {
                if (!(ctx.Module.LookupMember(ctorToken) is IMethodDescriptor ctor) ||
                    !string.Equals(ctor.Name, ".ctor", StringComparison.Ordinal))
                {
                    return false;
                }

                var parameters = ctor.Signature?.ParameterTypes;
                if (parameters == null || parameters.Count != 2)
                    return false;

                return string.Equals(parameters[0].FullName, "System.Object", StringComparison.Ordinal) &&
                       (string.Equals(parameters[1].FullName, "System.IntPtr", StringComparison.Ordinal) ||
                        string.Equals(parameters[1].FullName, "System.UIntPtr", StringComparison.Ordinal));
            }
            catch
            {
                return false;
            }
        }

        public bool HasReachableEntryUnderflow(DevirtualizationCtx ctx, VMMethod method)
        {
            if (ctx?.PatternMatcher == null || ctx.GetOperandTypes().Length == 0 || method?.MethodBody?.Instructions == null)
                return false;

            var instructions = method.MethodBody.Instructions;
            if (instructions.Count == 0)
                return false;

            var profile = BuildEffectiveProfile(ctx);
            var expectedReturn = ResolveExpectedReturnStack(method);
            var worklist = new BoundedStateWorklist(instructions.Count, profile.MaxStatesPerInstruction);
            worklist.TryEnqueue(0, 0);

            while (worklist.TryDequeue(out var index, out var depth))
            {
                var instruction = instructions[index];
                if (!TryResolveOpcode(ctx, instruction, null, out var opcode))
                {
                    worklist.TryEnqueue(index + 1, depth);
                    continue;
                }

                if (!TryGetStackEffect(opcode, instruction.Operand, ctx.Module, expectedReturn, out var pop, out var push))
                {
                    worklist.TryEnqueue(index + 1, depth);
                    continue;
                }

                if (opcode == VMOpCode.Call && IsVmDelegateConstructionCall(ctx, instructions, index))
                {
                    pop = 0;
                    push = 1;
                }

                if (depth < pop)
                {
                    if (string.Equals(
                            Environment.GetEnvironmentVariable("KRYPTON_LOG_ENTRY_UNDERFLOW"),
                            "1",
                            StringComparison.Ordinal))
                    {
                        var methodName = method.Parent?.FullName ?? "<unknown>";
                        ctx.Options.Logger.Info(
                            $"[entry-underflow] method={methodName} index={index} vm=0x{instruction.VmByte:X2} op={opcode} depth={depth} pop={pop} operand={instruction.Operand ?? "<null>"}");
                    }
                    return true;
                }

                var nextDepth = depth - pop + push;
                if (nextDepth > profile.MaxStackDepth)
                    nextDepth = profile.MaxStackDepth;

                var fallThrough = index + 1;
                switch (opcode)
                {
                    case VMOpCode.Br:
                    case VMOpCode.Leave:
                    {
                        if (!TryReadTarget(instruction.Operand, instructions.Count, out var target))
                            continue;
                        worklist.TryEnqueue(target, nextDepth);
                        break;
                    }
                    case VMOpCode.BrTrue:
                    case VMOpCode.BrFalse:
                    case VMOpCode.BrLessThan:
                    case VMOpCode.BrGreaterThan:
                    case VMOpCode.BrLessOrEqual:
                    case VMOpCode.BrGreaterOrEqual:
                    case VMOpCode.BrEqual:
                    case VMOpCode.BrNotEqual:
                    case VMOpCode.BrLessThan_Un:
                    case VMOpCode.BrGreaterThan_Un:
                    case VMOpCode.BrLessOrEqual_Un:
                    case VMOpCode.BrGreaterOrEqual_Un:
                    {
                        if (!TryReadTarget(instruction.Operand, instructions.Count, out var target))
                            continue;
                        worklist.TryEnqueue(target, nextDepth);
                        worklist.TryEnqueue(fallThrough, nextDepth);
                        break;
                    }
                    case VMOpCode.Switch:
                    {
                        if (!(instruction.Operand is int[] targets) || targets.Length == 0)
                            continue;
                        foreach (var target in targets)
                            worklist.TryEnqueue(target, nextDepth);
                        worklist.TryEnqueue(fallThrough, nextDepth);
                        break;
                    }
                    case VMOpCode.Ret:
                    case VMOpCode.EndFinally:
                    case VMOpCode.Throw:
                    case VMOpCode.Rethrow:
                        break;
                    default:
                        worklist.TryEnqueue(fallThrough, nextDepth);
                        break;
                }
            }

            return false;
        }

        private IReadOnlyCollection<VMOpCode> BuildCandidates(DevirtualizationCtx ctx, int vmByte)
        {
            ctx.TryGetOperandType(vmByte, out var operandType);
            return VMOpCodeCatalog.GetCandidates(operandType)
                .Where(candidate => AreCandidateOperandsSemanticallyCompatible(ctx, vmByte, candidate))
                .ToArray();
        }

        private IReadOnlyCollection<VMOpCode> BuildLegacyCandidates(DevirtualizationCtx ctx, int vmByte)
        {
            ctx.TryGetOperandType(vmByte, out var operandType);
            var logCandidates = string.Equals(
                Environment.GetEnvironmentVariable("KRYPTON_LOG_SEMANTIC_CANDIDATES"),
                "1",
                StringComparison.Ordinal);
            switch (operandType)
            {
                case 0:
                    return new[]
                    {
                        VMOpCode.Nop, VMOpCode.Ldnull,
                        VMOpCode.Pop, VMOpCode.Dup, VMOpCode.Conv_I4, VMOpCode.Conv_I8, VMOpCode.Conv_U1,
                        VMOpCode.Not, VMOpCode.Neg, VMOpCode.Add, VMOpCode.Sub, VMOpCode.Xor, VMOpCode.Shl, VMOpCode.Shr
                    };
                case 1:
                    var hasMetadataLike = HasMetadataLikeOperands(ctx, vmByte);
                    var localLike = !hasMetadataLike && LooksLikeLocalIndexByte(ctx, vmByte);
                    var argLike = !hasMetadataLike && !localLike && LooksLikeArgumentIndexByte(ctx, vmByte);
                    var branchLike = !hasMetadataLike && !localLike && !argLike && LooksLikeBranchOperandByte(ctx, vmByte);
                    var hasLargeImmediate = !hasMetadataLike && !branchLike && !localLike && !argLike && HasLargeImmediateOperands(ctx, vmByte);

                    if (logCandidates)
                    {
                        ctx.Options.Logger.Info(
                            $"Semantic candidates for vm 0x{vmByte:X2}: operand={operandType}, meta={hasMetadataLike}, branch={branchLike}, large={hasLargeImmediate}, local={localLike}, arg={argLike}");
                    }

                    if (hasMetadataLike)
                    {
                        return new[]
                        {
                            VMOpCode.Call,
                            VMOpCode.Callvirt,
                            VMOpCode.Newobj,
                            VMOpCode.Ldstr,
                            VMOpCode.Ldfld,
                            VMOpCode.Ldsfld,
                            VMOpCode.Stfld,
                            VMOpCode.Stsfld,
                            VMOpCode.Unbox_Any,
                            VMOpCode.Box,
                            VMOpCode.Constrained,
                            VMOpCode.Newarr,
                            VMOpCode.Ldobj,
                            VMOpCode.Stobj,
                            VMOpCode.Ldtoken,
                            VMOpCode.Ldc_I4
                        };
                    }

                    if (branchLike)
                    {
                        return new[]
                        {
                            VMOpCode.Br, VMOpCode.BrTrue, VMOpCode.BrFalse, VMOpCode.BrLessThan, VMOpCode.Leave,
                            VMOpCode.Ldc_I4
                        };
                    }

                    if (hasLargeImmediate)
                    {
                        return new[]
                        {
                            VMOpCode.Ldc_I4,
                            VMOpCode.Ldobj
                        };
                    }

                    if (localLike)
                    {
                        return new[]
                        {
                            VMOpCode.Ldloc,
                            VMOpCode.Stloc,
                            VMOpCode.Ldc_I4,
                            VMOpCode.Ldobj
                        };
                    }

                    if (argLike)
                    {
                        return new[]
                        {
                            VMOpCode.Ldarg,
                            VMOpCode.Ldc_I4
                        };
                    }

                    return new[]
                    {
                        VMOpCode.Ldc_I4,
                        VMOpCode.Ldobj
                    };
                case 5:
                    return new[] { VMOpCode.Switch };
                default:
                    return Array.Empty<VMOpCode>();
            }
        }

        private void ApplyChanges(DevirtualizationCtx ctx, IDictionary<int, VMOpCode?> changes, bool logChanges = true)
        {
            // semantic-validator-remap is derived: the candidate it installs was
            // chosen by measuring the current table against itself.
            if (OpcodeMapping.IsSoundModeEnabled())
                return;

            foreach (var pair in changes)
            {
                var vmByte = pair.Key;
                if (IsAnchored(ctx, vmByte))
                    continue;
                var newOpCode = pair.Value;
                if (!newOpCode.HasValue)
                {
                    ctx.PatternMatcher.UnsetOpCodeValue(vmByte);
                    ctx.OpcodeConfidence?.Remove(vmByte);
                    if (logChanges)
                        ctx.Options.Logger.Warning($"Semantic validator unmapped vm 0x{vmByte:X2}.");
                    continue;
                }

                ctx.PatternMatcher.SetOpCodeValue(newOpCode.Value, vmByte);
                ctx.OpcodeConfidence ??= new Dictionary<int, OpcodeMappingConfidence>();
                ctx.OpcodeConfidence[vmByte] = new OpcodeMappingConfidence(
                    newOpCode.Value,
                    0.67,
                    "semantic-validator-remap");
                if (logChanges)
                    ctx.Options.Logger.Info($"Semantic validator remapped vm 0x{vmByte:X2} -> {newOpCode.Value}.");
            }

            foreach (var method in ctx.VirtualizedMethods)
            {
                foreach (var instruction in method.MethodBody.Instructions)
                {
                    if (!changes.ContainsKey(instruction.VmByte))
                        continue;
                    instruction.IsResolved = ctx.PatternMatcher.IsOpCodeValueKnown(instruction.VmByte);
                    instruction.OpCode = instruction.IsResolved
                        ? ctx.PatternMatcher.GetOpCodeValue(instruction.VmByte)
                        : VMOpCode.Nop;
                }
            }
        }

        private SemanticEvaluationResult EvaluateMethods(
            DevirtualizationCtx ctx,
            SemanticValidationProfile profile,
            IDictionary<int, VMOpCode> substitutions)
        {
            var result = new SemanticEvaluationResult();
            foreach (var method in ctx.VirtualizedMethods)
            {
                EvaluateMethod(ctx, profile, method, substitutions, result);
            }

            return result;
        }

        private void EvaluateMethod(
            DevirtualizationCtx ctx,
            SemanticValidationProfile profile,
            VMMethod method,
            IDictionary<int, VMOpCode> substitutions,
            SemanticEvaluationResult result)
        {
            var instructions = method.MethodBody.Instructions;
            if (instructions == null || instructions.Count == 0)
                return;

            var expectedReturn = ResolveExpectedReturnStack(method);
            var worklist = new BoundedStateWorklist(instructions.Count, profile.MaxStatesPerInstruction);
            worklist.TryEnqueue(0, 0);

            while (worklist.TryDequeue(out var index, out var depth))
            {
                var instruction = instructions[index];
                if (!TryResolveOpcode(ctx, instruction, substitutions, out var opcode))
                {
                    worklist.TryEnqueue(index + 1, depth);
                    continue;
                }

                if (!TryGetStackEffect(opcode, instruction.Operand, ctx.Module, expectedReturn, out var pop, out var push))
                {
                    worklist.TryEnqueue(index + 1, depth);
                    continue;
                }

                var nextDepth = depth;
                if (nextDepth < pop)
                {
                    RegisterViolation(result, instruction.VmByte);
                    nextDepth = push;
                }
                else
                {
                    nextDepth = nextDepth - pop + push;
                }

                if (nextDepth > profile.MaxStackDepth)
                {
                    RegisterViolation(result, instruction.VmByte);
                    nextDepth = profile.MaxStackDepth;
                }

                var fallThrough = index + 1;
                switch (opcode)
                {
                    case VMOpCode.Br:
                    case VMOpCode.Leave:
                    {
                        if (!TryReadTarget(instruction.Operand, instructions.Count, out var target))
                        {
                            RegisterViolation(result, instruction.VmByte);
                            break;
                        }
                        worklist.TryEnqueue(target, nextDepth);
                        break;
                    }
                    case VMOpCode.BrTrue:
                    case VMOpCode.BrFalse:
                    case VMOpCode.BrLessThan:
                    case VMOpCode.BrGreaterThan:
                    case VMOpCode.BrLessOrEqual:
                    case VMOpCode.BrGreaterOrEqual:
                    case VMOpCode.BrEqual:
                    case VMOpCode.BrNotEqual:
                    case VMOpCode.BrLessThan_Un:
                    case VMOpCode.BrGreaterThan_Un:
                    case VMOpCode.BrLessOrEqual_Un:
                    case VMOpCode.BrGreaterOrEqual_Un:
                    {
                        if (!TryReadTarget(instruction.Operand, instructions.Count, out var target))
                        {
                            RegisterViolation(result, instruction.VmByte);
                            break;
                        }
                        worklist.TryEnqueue(target, nextDepth);
                        worklist.TryEnqueue(fallThrough, nextDepth);
                        break;
                    }
                    case VMOpCode.Switch:
                    {
                        if (!(instruction.Operand is int[] targets) || targets.Length == 0)
                        {
                            RegisterViolation(result, instruction.VmByte);
                            break;
                        }
                        var validTargets = true;
                        foreach (var target in targets)
                        {
                            if (target < 0 || target >= instructions.Count)
                            {
                                validTargets = false;
                                continue;
                            }
                            worklist.TryEnqueue(target, nextDepth);
                        }
                        if (!validTargets)
                            RegisterViolation(result, instruction.VmByte);
                        worklist.TryEnqueue(fallThrough, nextDepth);
                        break;
                    }
                    case VMOpCode.Ret:
                    case VMOpCode.EndFinally:
                    case VMOpCode.Throw:
                    case VMOpCode.Rethrow:
                        break;
                    default:
                        worklist.TryEnqueue(fallThrough, nextDepth);
                        break;
                }
            }
        }

        private bool HasMetadataLikeOperands(DevirtualizationCtx ctx, int vmByte)
        {
            if (ctx?.VirtualizedMethods == null)
                return false;

            foreach (var method in ctx.VirtualizedMethods)
            {
                var instructions = method?.MethodBody?.Instructions;
                if (instructions == null)
                    continue;

                foreach (var instruction in instructions)
                {
                    if (instruction?.VmByte != vmByte)
                        continue;
                    if (!(instruction.Operand is int operand))
                        continue;
                    if (operand > 0 && (((uint) operand) & 0xFF000000u) != 0)
                        return true;
                }
            }

            return false;
        }

        private bool LooksLikeBranchOperandByte(DevirtualizationCtx ctx, int vmByte)
        {
            if (ctx?.VirtualizedMethods == null)
                return false;

            var total = 0;
            var validTargets = 0;
            var maxTarget = int.MinValue;
            var uniqueTargets = new HashSet<int>();
            foreach (var method in ctx.VirtualizedMethods)
            {
                var instructions = method?.MethodBody?.Instructions;
                if (instructions == null)
                    continue;

                foreach (var instruction in instructions)
                {
                    if (instruction?.VmByte != vmByte)
                        continue;
                    if (!(instruction.Operand is int operand))
                        continue;

                    total++;
                    if (operand >= 0 && operand < instructions.Count)
                    {
                        validTargets++;
                        uniqueTargets.Add(operand);
                        if (operand > maxTarget)
                            maxTarget = operand;
                    }
                }
            }

            if (total == 0)
                return false;
            if (validTargets * 10 < total * 9)
                return false;
            if (LooksLikeLocalIndexByte(ctx, vmByte) || LooksLikeArgumentIndexByte(ctx, vmByte))
                return false;

            // Flattened dispatcher branch bytes usually have wider target spread.
            // Reject tiny low-variance index-like shapes.
            if (maxTarget < 32 && uniqueTargets.Count <= 4)
                return false;
            if (maxTarget < 64 && uniqueTargets.Count * 10 < total * 2)
                return false;

            return true;
        }

        private bool HasLargeImmediateOperands(DevirtualizationCtx ctx, int vmByte)
        {
            if (ctx?.VirtualizedMethods == null)
                return false;

            foreach (var method in ctx.VirtualizedMethods)
            {
                var instructions = method?.MethodBody?.Instructions;
                if (instructions == null)
                    continue;

                foreach (var instruction in instructions)
                {
                    if (instruction?.VmByte != vmByte)
                        continue;
                    if (!(instruction.Operand is int operand))
                        continue;
                    if (operand >= 64 || operand <= -64)
                        return true;
                }
            }

            return false;
        }

        private bool LooksLikeLocalIndexByte(DevirtualizationCtx ctx, int vmByte)
        {
            if (ctx?.VirtualizedMethods == null)
                return false;

            var total = 0;
            var localLike = 0;
            foreach (var method in ctx.VirtualizedMethods)
            {
                var instructions = method?.MethodBody?.Instructions;
                if (instructions == null)
                    continue;

                var localCount = method?.MethodBody?.Locals?.Count ?? 0;
                foreach (var instruction in instructions)
                {
                    if (instruction?.VmByte != vmByte)
                        continue;
                    if (!(instruction.Operand is int operand))
                        continue;

                    total++;
                    if (operand >= 0 && operand < localCount)
                        localLike++;
                }
            }

            if (total == 0)
                return false;
            return localLike * 10 >= total * 7;
        }

        private bool LooksLikeArgumentIndexByte(DevirtualizationCtx ctx, int vmByte)
        {
            if (ctx?.VirtualizedMethods == null)
                return false;

            var total = 0;
            var argLike = 0;
            foreach (var method in ctx.VirtualizedMethods)
            {
                var instructions = method?.MethodBody?.Instructions;
                if (instructions == null)
                    continue;

                var argumentCount = method?.Parent?.Signature?.ParameterTypes?.Count ?? 0;
                if (method?.Parent?.IsStatic == false)
                    argumentCount += 1;

                foreach (var instruction in instructions)
                {
                    if (instruction?.VmByte != vmByte)
                        continue;
                    if (!(instruction.Operand is int operand))
                        continue;

                    total++;
                    if (operand >= 0 && operand < argumentCount)
                        argLike++;
                }
            }

            if (total == 0)
                return false;
            return argLike * 10 >= total * 7;
        }

        private bool TryResolveOpcode(
            DevirtualizationCtx ctx,
            VMInstruction instruction,
            IDictionary<int, VMOpCode> substitutions,
            out VMOpCode opcode)
        {
            opcode = VMOpCode.Nop;
            if (substitutions != null && substitutions.TryGetValue(instruction.VmByte, out var substituted))
            {
                opcode = substituted;
                return true;
            }

            if (!ctx.PatternMatcher.IsOpCodeValueKnown(instruction.VmByte))
                return false;

            opcode = ctx.PatternMatcher.GetOpCodeValue(instruction.VmByte);
            return true;
        }

        private bool TryReadTarget(object operand, int instructionCount, out int target)
        {
            target = -1;
            if (!(operand is int branchTarget))
                return false;
            if (branchTarget < 0 || branchTarget >= instructionCount)
                return false;
            target = branchTarget;
            return true;
        }

        private int ResolveExpectedReturnStack(VMMethod method)
        {
            var parent = method?.Parent;
            var signature = parent?.Signature;
            if (signature == null)
                return 0;
            return string.Equals(signature.ReturnType?.FullName, "System.Void", StringComparison.Ordinal) ? 0 : 1;
        }

        private void RegisterViolation(SemanticEvaluationResult result, int vmByte)
        {
            result.TotalViolations++;
            if (!result.ViolationsByVmByte.TryGetValue(vmByte, out var count))
                count = 0;
            result.ViolationsByVmByte[vmByte] = count + 1;
        }

        private bool IsSuspiciousLowFrequencyStackByte(
            DevirtualizationCtx ctx,
            int vmByte,
            VMOpCode current)
        {
            if (ctx?.GetOperandTypes().Length == 0 || ctx.OpcodeConfidence == null)
                return false;
            if (!ctx.TryGetOperandType(vmByte, out var operandType))
                return false;
            if (operandType != 0)
                return false;
            if (!ctx.OpcodeConfidence.TryGetValue(vmByte, out var confidence))
                return false;

            var source = confidence.Source ?? string.Empty;
            if (source.IndexOf("override", StringComparison.OrdinalIgnoreCase) >= 0)
                return false;

            var occurrences = 0;
            foreach (var method in ctx.VirtualizedMethods)
            {
                foreach (var instruction in method.MethodBody.Instructions)
                {
                    if (instruction.VmByte == vmByte)
                        occurrences++;
                }
            }

            if (occurrences <= 0 || occurrences > 6)
                return false;

            if (current == VMOpCode.Nop)
            {
                return source.IndexOf("constraint-mapper", StringComparison.OrdinalIgnoreCase) >= 0 ||
                       source.IndexOf("semantic", StringComparison.OrdinalIgnoreCase) >= 0;
            }

            if (current != VMOpCode.Add &&
                current != VMOpCode.Sub &&
                current != VMOpCode.Xor &&
                current != VMOpCode.Shl &&
                current != VMOpCode.Shr)
            {
                return false;
            }

            return source.IndexOf("handler-pattern", StringComparison.OrdinalIgnoreCase) >= 0 ||
                   source.IndexOf("constraint-mapper", StringComparison.OrdinalIgnoreCase) >= 0;
        }

        private bool IsOperandTypeCompatible(DevirtualizationCtx ctx, int vmByte, VMOpCode opCode)
        {
            if (ctx == null || !ctx.TryGetOperandType(vmByte, out var operandType))
                return true;
            if (VMOpCodeCatalog.TryGet(opCode, out var semantic))
                return semantic.SupportsOperandType(operandType);
            switch (opCode)
            {
                case VMOpCode.Nop:
                case VMOpCode.Add:
                case VMOpCode.Ceq:
                case VMOpCode.Cgt:
                case VMOpCode.Cgt_Un:
                case VMOpCode.Clt:
                case VMOpCode.Clt_Un:
                case VMOpCode.Sub:
                case VMOpCode.Xor:
                case VMOpCode.Shl:
                case VMOpCode.Shr:
                case VMOpCode.Pop:
                case VMOpCode.Dup:
                case VMOpCode.Ret:
                case VMOpCode.Conv_I4:
                case VMOpCode.Conv_I8:
                case VMOpCode.Conv_U1:
                case VMOpCode.Not:
                case VMOpCode.Neg:
                case VMOpCode.Ldlen:
                case VMOpCode.Ldnull:
                case VMOpCode.EndFinally:
                case VMOpCode.Ldelem_Ref:
                case VMOpCode.Ldelem_U1:
                case VMOpCode.Stelem_Ref:
                case VMOpCode.Stelem_I1:
                    return operandType == 0;

                case VMOpCode.Leave:
                    return operandType == 0 || operandType == 1;

                case VMOpCode.Ldarg:
                case VMOpCode.Ldloc:
                case VMOpCode.Ldloca:
                case VMOpCode.Stloc:
                case VMOpCode.Ldc_I4:
                case VMOpCode.Ldstr:
                case VMOpCode.Call:
                case VMOpCode.Callvirt:
                case VMOpCode.Newobj:
                case VMOpCode.Newarr:
                case VMOpCode.Unbox_Any:
                case VMOpCode.Box:
                case VMOpCode.Constrained:
                case VMOpCode.Br:
                case VMOpCode.BrTrue:
                case VMOpCode.BrFalse:
                case VMOpCode.BrLessThan:
                case VMOpCode.BrGreaterThan:
                case VMOpCode.BrLessOrEqual:
                case VMOpCode.BrGreaterOrEqual:
                case VMOpCode.BrEqual:
                case VMOpCode.BrNotEqual:
                case VMOpCode.Ldsfld:
                case VMOpCode.Ldfld:
                case VMOpCode.Stsfld:
                case VMOpCode.Stfld:
                case VMOpCode.Ldelema:
                case VMOpCode.Ldobj:
                case VMOpCode.Stobj:
                    return operandType == 1;

                case VMOpCode.Ldc_R4:
                    return operandType == 3;

                case VMOpCode.Ldc_R8:
                    return operandType == 4;

                case VMOpCode.Switch:
                    return operandType == 5;

                default:
                    return true;
            }
        }

        private bool AreCandidateOperandsSemanticallyCompatible(DevirtualizationCtx ctx, int vmByte, VMOpCode candidate)
        {
            if (ctx?.VirtualizedMethods == null)
                return false;

            var seen = false;
            foreach (var method in ctx.VirtualizedMethods)
            {
                var instructions = method?.MethodBody?.Instructions;
                if (instructions == null)
                    continue;

                foreach (var instruction in instructions)
                {
                    if (instruction == null || instruction.VmByte != vmByte)
                        continue;

                    seen = true;
                    if (!IsOperandSemanticallyCompatible(
                            ctx,
                            candidate,
                            instruction.Operand,
                            instructions.Count,
                            method?.MethodBody?.Locals?.Count ?? 0,
                            GetMethodArgumentCount(method)))
                    {
                        return false;
                    }
                }
            }

            return seen;
        }

        private bool IsOperandSemanticallyCompatible(
            DevirtualizationCtx ctx,
            VMOpCode candidate,
            object operand,
            int instructionCount,
            int localCount,
            int argumentCount)
        {
            var semantic = VMOpCodeCatalog.Get(candidate);
            if (semantic.Flow == VMFlowKind.UnconditionalBranch ||
                semantic.Flow == VMFlowKind.ConditionalBranch)
            {
                if (!(operand is int target) || target < 0 || target >= instructionCount)
                    return false;
            }
            if (semantic.Flow == VMFlowKind.Leave && operand != null &&
                (!(operand is int validatedLeaveTarget) ||
                 validatedLeaveTarget < 0 ||
                 validatedLeaveTarget >= instructionCount))
            {
                return false;
            }

            switch (semantic.TokenKind)
            {
                case VMMetadataTokenKind.Method:
                    if (!TryResolveMethodToken(ctx, operand))
                        return false;
                    break;
                case VMMetadataTokenKind.Field:
                    if (!TryResolveFieldToken(ctx, operand))
                        return false;
                    break;
                case VMMetadataTokenKind.Type:
                    if (!TryResolveTypeToken(ctx, operand))
                        return false;
                    break;
                case VMMetadataTokenKind.String:
                    if (!TryResolveUserString(ctx, operand))
                        return false;
                    break;
                case VMMetadataTokenKind.Any:
                    if (!TryResolveFieldToken(ctx, operand) &&
                        !TryResolveTypeToken(ctx, operand) &&
                        !TryResolveMethodToken(ctx, operand))
                    {
                        return false;
                    }
                    break;
            }

            switch (candidate)
            {
                case VMOpCode.Br:
                case VMOpCode.BrTrue:
                case VMOpCode.BrFalse:
                case VMOpCode.BrLessThan:
                    return operand is int branchTarget &&
                           branchTarget >= 0 &&
                           branchTarget < instructionCount;

                case VMOpCode.Leave:
                    if (operand == null)
                        return true;
                    return operand is int leaveTarget &&
                           leaveTarget >= 0 &&
                           leaveTarget < instructionCount;

                case VMOpCode.Ldloc:
                case VMOpCode.Ldloca:
                case VMOpCode.Stloc:
                    return operand is int localIndex &&
                           localIndex >= 0 &&
                           localIndex < localCount;

                case VMOpCode.Ldarg:
                case VMOpCode.Ldarga:
                case VMOpCode.Starg:
                    return operand is int argIndex &&
                           argIndex >= 0 &&
                           argIndex < argumentCount;

                case VMOpCode.Switch:
                    if (!(operand is int[] targets) || targets.Length == 0)
                        return false;
                    for (var i = 0; i < targets.Length; i++)
                    {
                        if (targets[i] < 0 || targets[i] >= instructionCount)
                            return false;
                    }
                    return true;

                case VMOpCode.Call:
                case VMOpCode.Callvirt:
                    return TryResolveMethodToken(ctx, operand);

                case VMOpCode.Newobj:
                    return TryResolveConstructorToken(ctx, operand);

                case VMOpCode.Ldfld:
                case VMOpCode.Stfld:
                case VMOpCode.Ldsfld:
                case VMOpCode.Stsfld:
                    return TryResolveFieldToken(ctx, operand);

                case VMOpCode.Ldstr:
                    return TryResolveUserString(ctx, operand);

                case VMOpCode.Newarr:
                case VMOpCode.Unbox_Any:
                case VMOpCode.Box:
                case VMOpCode.Constrained:
                case VMOpCode.Ldobj:
                case VMOpCode.Stobj:
                case VMOpCode.Ldelema:
                    return TryResolveTypeToken(ctx, operand);

                case VMOpCode.Ldtoken:
                    return TryResolveFieldToken(ctx, operand) ||
                           TryResolveTypeToken(ctx, operand) ||
                           TryResolveMethodToken(ctx, operand);

                default:
                    return true;
            }
        }

        private bool TryResolveMethodToken(DevirtualizationCtx ctx, object operand)
        {
            if (!(operand is int token))
                return false;

            try
            {
                return ctx?.Module?.LookupMember(token) is IMethodDescriptor;
            }
            catch
            {
                return false;
            }
        }

        private bool TryResolveConstructorToken(DevirtualizationCtx ctx, object operand)
        {
            if (!(operand is int token))
                return false;

            try
            {
                return ctx?.Module?.LookupMember(token) is IMethodDescriptor descriptor &&
                       IsConstructorMethod(descriptor);
            }
            catch
            {
                return false;
            }
        }

        private bool IsConstructorMethod(IMethodDescriptor descriptor)
        {
            if (descriptor == null)
                return false;

            var name = descriptor.Name?.ToString() ?? descriptor.Resolve()?.Name?.ToString();
            return string.Equals(name, ".ctor", StringComparison.Ordinal) ||
                   string.Equals(name, ".cctor", StringComparison.Ordinal);
        }

        private bool TryResolveUserString(DevirtualizationCtx ctx, object operand)
        {
            if (!(operand is int tokenOrOffset))
                return false;

            var offset = tokenOrOffset;
            var table = unchecked((uint) tokenOrOffset) & 0xFF000000u;
            if (table == 0x70000000u)
                offset = tokenOrOffset & 0x00FFFFFF;
            else if (table != 0)
                return false;

            if (offset <= 0)
                return false;

            try
            {
                using var fs = File.OpenRead(ctx.Options.FilePath);
                using var pe = new PEReader(fs);
                var metadata = pe.GetMetadataReader();
                _ = metadata.GetUserString(MetadataTokens.UserStringHandle(offset));
                return true;
            }
            catch
            {
                return false;
            }
        }

        private bool TryResolveFieldToken(DevirtualizationCtx ctx, object operand)
        {
            if (!(operand is int token))
                return false;

            try
            {
                return ctx?.Module?.LookupMember(token) is IFieldDescriptor;
            }
            catch
            {
                return false;
            }
        }

        private bool TryResolveTypeToken(DevirtualizationCtx ctx, object operand)
        {
            if (!(operand is int token))
                return false;

            try
            {
                var member = ctx?.Module?.LookupMember(token);
                return member is ITypeDescriptor;
            }
            catch
            {
                return false;
            }
        }

        private OpcodeMappingSnapshot CaptureMappingState(DevirtualizationCtx ctx, int vmByte)
        {
            var isMapped = ctx.PatternMatcher.IsOpCodeValueKnown(vmByte);
            var mappedOpcode = isMapped ? ctx.PatternMatcher.GetOpCodeValue(vmByte) : VMOpCode.Nop;
            OpcodeMappingConfidence confidence = null;
            if (ctx.OpcodeConfidence != null && ctx.OpcodeConfidence.TryGetValue(vmByte, out var existingConfidence))
            {
                confidence = new OpcodeMappingConfidence(
                    existingConfidence.OpCode,
                    existingConfidence.Confidence,
                    existingConfidence.Source);
            }

            return new OpcodeMappingSnapshot(vmByte, isMapped, mappedOpcode, confidence);
        }

        private void RestoreMappingState(DevirtualizationCtx ctx, OpcodeMappingSnapshot snapshot)
        {
            if (snapshot == null || ctx?.PatternMatcher == null)
                return;

            if (snapshot.IsMapped)
                ctx.PatternMatcher.SetOpCodeValue(snapshot.OpCode, snapshot.VmByte);
            else
                ctx.PatternMatcher.UnsetOpCodeValue(snapshot.VmByte);

            if (snapshot.Confidence == null)
                ctx.OpcodeConfidence?.Remove(snapshot.VmByte);
            else
            {
                ctx.OpcodeConfidence ??= new Dictionary<int, OpcodeMappingConfidence>();
                ctx.OpcodeConfidence[snapshot.VmByte] = snapshot.Confidence;
            }

            foreach (var method in ctx.VirtualizedMethods)
            {
                foreach (var instruction in method.MethodBody.Instructions)
                {
                    if (instruction.VmByte != snapshot.VmByte)
                        continue;
                    instruction.IsResolved = snapshot.IsMapped;
                    instruction.OpCode = snapshot.IsMapped ? snapshot.OpCode : VMOpCode.Nop;
                }
            }
        }

        private bool ShouldTouchCilMapping(DevirtualizationCtx ctx, int vmByte)
        {
            if (IsAnchored(ctx, vmByte))
                return false;

            if (ctx?.PatternMatcher == null || !ctx.PatternMatcher.IsOpCodeValueKnown(vmByte))
                return false;

            var current = ctx.PatternMatcher.GetOpCodeValue(vmByte);
            if (!AreCandidateOperandsSemanticallyCompatible(ctx, vmByte, current))
                return true;
            if (ctx.OpcodeConfidence == null || !ctx.OpcodeConfidence.TryGetValue(vmByte, out var confidence))
                return true;

            var source = confidence.Source ?? string.Empty;
            if (source.IndexOf("override", StringComparison.OrdinalIgnoreCase) >= 0)
                return false;
            if (IsStructuralConfidence(confidence))
                return false;
            if (current == VMOpCode.Pop || current == VMOpCode.Nop || current == VMOpCode.Dup)
                return true;
            var looksInference =
                source.IndexOf("stack-consistency", StringComparison.OrdinalIgnoreCase) >= 0 ||
                source.IndexOf("constraint-mapper", StringComparison.OrdinalIgnoreCase) >= 0 ||
                source.IndexOf("semantic", StringComparison.OrdinalIgnoreCase) >= 0 ||
                source.IndexOf("singleton", StringComparison.OrdinalIgnoreCase) >= 0 ||
                source.IndexOf("windowed", StringComparison.OrdinalIgnoreCase) >= 0 ||
                source.IndexOf("joint-stack", StringComparison.OrdinalIgnoreCase) >= 0 ||
                source.IndexOf("neighbor", StringComparison.OrdinalIgnoreCase) >= 0 ||
                source.IndexOf("dominant", StringComparison.OrdinalIgnoreCase) >= 0 ||
                source.IndexOf("last-resort", StringComparison.OrdinalIgnoreCase) >= 0 ||
                source.IndexOf("branch", StringComparison.OrdinalIgnoreCase) >= 0 ||
                source.IndexOf("aggressive", StringComparison.OrdinalIgnoreCase) >= 0 ||
                source.IndexOf("retune", StringComparison.OrdinalIgnoreCase) >= 0;
            if (source.IndexOf("handler-pattern", StringComparison.OrdinalIgnoreCase) >= 0 && !looksInference)
                return false;
            if (source.IndexOf("stack-consistency", StringComparison.OrdinalIgnoreCase) >= 0 ||
                source.IndexOf("constraint-mapper", StringComparison.OrdinalIgnoreCase) >= 0 ||
                source.IndexOf("semantic", StringComparison.OrdinalIgnoreCase) >= 0 ||
                source.IndexOf("singleton", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                return true;
            }

            return looksInference || confidence.Confidence < 0.98;
        }

        private int GetMethodArgumentCount(VMMethod method)
        {
            var argumentCount = method?.Parent?.Signature?.ParameterTypes?.Count ?? 0;
            if (method?.Parent?.IsStatic == false)
                argumentCount += 1;
            return argumentCount;
        }

        private IReadOnlyCollection<VMOpCode> BuildCilCandidates(
            DevirtualizationCtx ctx,
            int vmByte,
            VMOpCode current,
            IReadOnlyDictionary<int, int> knownFrequency)
        {
            var baseCandidates = BuildCandidates(ctx, vmByte)
                .Where(c => c != current)
                .Distinct()
                .ToList();

            if (knownFrequency != null &&
                knownFrequency.TryGetValue(vmByte, out var frequency) &&
                frequency > 0 &&
                frequency <= 16)
            {
                return baseCandidates;
            }

            if (current == VMOpCode.Pop || current == VMOpCode.Nop || current == VMOpCode.Dup)
                return baseCandidates;

            return baseCandidates.Count > 8
                ? baseCandidates.Take(8).ToArray()
                : baseCandidates.ToArray();
        }

        private IReadOnlyCollection<int> CollectEntryUnderflowCandidateVmBytes(
            DevirtualizationCtx ctx,
            SemanticEvaluationResult baselineCil,
            IReadOnlyDictionary<int, int> knownFrequency)
        {
            var result = new List<int>();
            var added = new HashSet<int>();

            foreach (var pair in baselineCil.ViolationsByVmByte.OrderByDescending(p => p.Value).Take(24))
            {
                if (added.Add(pair.Key))
                    result.Add(pair.Key);
            }

            var branchLikeBytes = BuildBranchLikeVmByteSet(ctx, knownFrequency);
            foreach (var pair in knownFrequency.OrderByDescending(p => p.Value))
            {
                var vmByte = pair.Key;
                if (!ctx.PatternMatcher.IsOpCodeValueKnown(vmByte))
                    continue;
                if (!ctx.TryGetOperandType(vmByte, out var operandType) || operandType != 1)
                    continue;

                var mapped = ctx.PatternMatcher.GetOpCodeValue(vmByte);
                if (!IsBranchLikeOpcode(mapped) && !branchLikeBytes.Contains(vmByte))
                    continue;

                if (added.Add(vmByte))
                    result.Add(vmByte);
            }

            foreach (var method in ctx.VirtualizedMethods)
            {
                if (method?.MethodBody?.Instructions == null || method.MethodBody.Instructions.Count == 0)
                    continue;
                if (!HasReachableEntryUnderflow(ctx, method))
                    continue;

                var instructions = method.MethodBody.Instructions;
                var limit = Math.Min(24, instructions.Count);
                for (var i = 0; i < limit; i++)
                {
                    var vmByte = instructions[i].VmByte;
                    if (!ctx.PatternMatcher.IsOpCodeValueKnown(vmByte))
                        continue;
                    if (!ctx.TryGetOperandType(vmByte, out var operandType))
                        continue;

                    var mapped = ctx.PatternMatcher.GetOpCodeValue(vmByte);
                    var stackConsumingOperandless = operandType == 0 &&
                        TryGetStackEffect(
                            mapped,
                            instructions[i].Operand,
                            ctx.Module,
                            ResolveExpectedReturnStack(method),
                            out var pop,
                            out _) &&
                        pop > 0;
                    var branchCandidate = operandType == 1 &&
                        (IsBranchLikeOpcode(mapped) || branchLikeBytes.Contains(vmByte));
                    if (!stackConsumingOperandless && !branchCandidate)
                        continue;

                    if (added.Add(vmByte))
                        result.Add(vmByte);
                }
            }

            return result;
        }

        private HashSet<int> BuildBranchLikeVmByteSet(
            DevirtualizationCtx ctx,
            IReadOnlyDictionary<int, int> knownFrequency)
        {
            var set = new HashSet<int>();
            foreach (var pair in knownFrequency)
            {
                var vmByte = pair.Key;
                if (!ctx.PatternMatcher.IsOpCodeValueKnown(vmByte))
                    continue;
                if (!ctx.TryGetOperandType(vmByte, out var operandType) || operandType != 1)
                    continue;
                if (LooksLikeBranchOperandByte(ctx, vmByte))
                    set.Add(vmByte);
            }

            return set;
        }

        private bool ShouldTouchEntryUnderflowMapping(DevirtualizationCtx ctx, int vmByte)
        {
            if (IsAnchored(ctx, vmByte))
                return false;

            if (ctx?.PatternMatcher == null || !ctx.PatternMatcher.IsOpCodeValueKnown(vmByte))
                return false;

            if (ctx.OpcodeConfidence != null &&
                ctx.OpcodeConfidence.TryGetValue(vmByte, out var confidence))
            {
                var source = confidence.Source ?? string.Empty;
                if (source.IndexOf("override", StringComparison.OrdinalIgnoreCase) >= 0)
                    return false;
                if (IsStructuralConfidence(confidence))
                    return false;

                // Flattened VM control flow deliberately carries dispatcher state
                // across branches. Entry-only stack analysis cannot model that state
                // and used to "repair" a well-supported conditional branch into
                // Leave merely because Leave pops nothing. Preserve a high-confidence
                // stack-derived branch when its operands consistently point at real
                // instruction targets; later full-body validation can still reject an
                // actually malformed recompiled method.
                var current = ctx.PatternMatcher.GetOpCodeValue(vmByte);
                if (confidence.Confidence >= 0.90 &&
                    source.IndexOf("stack-consistency", StringComparison.OrdinalIgnoreCase) >= 0 &&
                    IsBranchLikeOpcode(current) &&
                    current != VMOpCode.Leave &&
                    LooksLikeBranchOperandByte(ctx, vmByte))
                {
                    return false;
                }
            }

            if (ctx.TryGetOperandType(vmByte, out var stackOperandType) && stackOperandType == 0)
            {
                var current = ctx.PatternMatcher.GetOpCodeValue(vmByte);
                if (TryGetStackEffect(current, null, ctx.Module, 0, out var pop, out _) && pop > 0)
                    return true;
            }

            if (ctx.TryGetOperandType(vmByte, out var operandType) && operandType == 1)
            {
                var current = ctx.PatternMatcher.GetOpCodeValue(vmByte);
                if (IsBranchLikeOpcode(current) || LooksLikeBranchOperandByte(ctx, vmByte))
                    return true;
            }

            return ShouldTouchCilMapping(ctx, vmByte);
        }

        private IReadOnlyCollection<VMOpCode> BuildEntryUnderflowCandidates(
            DevirtualizationCtx ctx,
            int vmByte,
            VMOpCode current,
            IReadOnlyDictionary<int, int> knownFrequency)
        {
            var candidates = new List<VMOpCode>();
            candidates.AddRange(BuildCilCandidates(ctx, vmByte, current, knownFrequency));

            if (ctx.TryGetOperandType(vmByte, out var operandType) && operandType == 1)
            {
                if (IsBranchLikeOpcode(current) || LooksLikeBranchOperandByte(ctx, vmByte))
                {
                    candidates.Add(VMOpCode.Br);
                    candidates.Add(VMOpCode.BrTrue);
                    candidates.Add(VMOpCode.BrFalse);
                    candidates.Add(VMOpCode.BrLessThan);
                    candidates.Add(VMOpCode.Leave);
                    candidates.Add(VMOpCode.Ldc_I4);
                }
            }
            else if (ctx.TryGetOperandType(vmByte, out operandType) && operandType == 0)
            {
                candidates.Add(VMOpCode.Nop);
                candidates.Add(VMOpCode.Ldnull);
                candidates.Add(VMOpCode.Pop);
                candidates.Add(VMOpCode.Dup);
                candidates.Add(VMOpCode.Add);
                candidates.Add(VMOpCode.Sub);
                candidates.Add(VMOpCode.Xor);
                candidates.Add(VMOpCode.Shl);
                candidates.Add(VMOpCode.Shr);
            }

            return candidates
                .Where(candidate => candidate != current)
                .Where(candidate => IsOperandTypeCompatible(ctx, vmByte, candidate))
                .Distinct()
                .ToArray();
        }

        private bool IsBranchLikeOpcode(VMOpCode opCode)
        {
            switch (opCode)
            {
                case VMOpCode.Br:
                case VMOpCode.BrTrue:
                case VMOpCode.BrFalse:
                case VMOpCode.BrLessThan:
                case VMOpCode.Switch:
                case VMOpCode.Leave:
                    return true;
                default:
                    return false;
            }
        }

        private SemanticEvaluationResult EvaluateCilMethods(
            DevirtualizationCtx ctx,
            MethodRecompiling lowerer,
            IDictionary<string, SemanticEvaluationResult> cache)
        {
            var cacheKey = BuildCilEvaluationCacheKey(ctx);
            if (cache != null && cache.TryGetValue(cacheKey, out var cached))
                return cached.Clone();

            var result = new SemanticEvaluationResult();
            var includeDnlibValidation = string.Equals(
                Environment.GetEnvironmentVariable("KRYPTON_ENABLE_DNLIB_SEMANTIC_EVAL"),
                "1",
                StringComparison.Ordinal);
            var dnlibValidationWeight = ReadPositiveIntFromEnvironment(
                "KRYPTON_DNLIB_SEMANTIC_WEIGHT",
                1);
            var recompileFailurePenalty = ReadPositiveIntFromEnvironment(
                "KRYPTON_RECOMPILE_FAILURE_PENALTY",
                5000);
            var logProgress = IsEnvironmentEnabled("KRYPTON_LOG_SEMANTIC_PROGRESS");
            var methodIndex = 0;

            foreach (var method in ctx.VirtualizedMethods)
            {
                methodIndex++;
                if (method?.MethodBody?.Instructions == null || method.MethodBody.Instructions.Count == 0)
                    continue;
                if (method.MethodBody.Instructions.Any(q => !q.IsResolved))
                {
                    RegisterViolation(result, method.MethodBody.Instructions[0].VmByte);
                    continue;
                }

                try
                {
                    if (logProgress)
                    {
                        ctx.Options.Logger.Info(
                            $"[semantic-cil] method {methodIndex}/{ctx.VirtualizedMethods.Count} begin: {method.Parent?.FullName ?? "<unknown>"} (vm={method.MethodBody.Instructions.Count}).");
                    }
                    var artifact = lowerer.RecompileDetailed(ctx, method);
                    if (logProgress)
                    {
                        ctx.Options.Logger.Info(
                            $"[semantic-cil] method {methodIndex}/{ctx.VirtualizedMethods.Count} recompiled: cil={artifact?.Body?.Instructions?.Count ?? 0}.");
                    }
                    var analysis = CilBodyStackAnalyzer.Analyze(ctx, method, artifact);
                    if (logProgress)
                    {
                        ctx.Options.Logger.Info(
                            $"[semantic-cil] method {methodIndex}/{ctx.VirtualizedMethods.Count} analyzed: issues={analysis.TotalIssues}.");
                    }
                    result.TotalViolations += analysis.TotalIssues;
                    foreach (var pair in analysis.IssuesByVmByte)
                    {
                        if (!result.ViolationsByVmByte.TryGetValue(pair.Key, out var count))
                            count = 0;
                        result.ViolationsByVmByte[pair.Key] = count + pair.Value;
                    }

                    AccumulateCilNeighborSuspicion(ctx, artifact, analysis, result);

                    if (includeDnlibValidation && analysis.TotalIssues > 0)
                    {
                        var dnlibAnalysis = DnlibStyleMaxStackAnalyzer.Analyze(null, method, artifact);
                        if (dnlibAnalysis.TotalIssues > 0)
                        {
                            var weightedTotal = dnlibAnalysis.TotalIssues * dnlibValidationWeight;
                            result.TotalViolations += weightedTotal;
                            foreach (var pair in dnlibAnalysis.IssuesByVmByte)
                            {
                                var weightedCount = pair.Value * dnlibValidationWeight;
                                if (!result.ViolationsByVmByte.TryGetValue(pair.Key, out var count))
                                    count = 0;
                                result.ViolationsByVmByte[pair.Key] = count + weightedCount;
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    result.TotalViolations += recompileFailurePenalty;

                    var vmByte = method.MethodBody.Instructions[0].VmByte;
                    if (TryExtractVmByteFromException(ex, out var extractedVmByte))
                        vmByte = extractedVmByte;

                    if (!result.ViolationsByVmByte.TryGetValue(vmByte, out var count))
                        count = 0;
                    result.ViolationsByVmByte[vmByte] = count + recompileFailurePenalty;
                }
            }

            if (cache != null)
                cache[cacheKey] = result.Clone();
            return result;
        }

        private bool TryExtractVmByteFromException(Exception ex, out int vmByte)
        {
            vmByte = 0;
            if (ex == null)
                return false;

            var text = ex.ToString();
            if (string.IsNullOrWhiteSpace(text))
                return false;

            const string marker = "vm:0x";
            var index = text.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
            if (index < 0)
                return false;

            index += marker.Length;
            var end = index;
            while (end < text.Length && end - index < 4 && Uri.IsHexDigit(text[end]))
                end++;

            if (end <= index)
                return false;

            var token = text.Substring(index, end - index);
            return int.TryParse(token, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out vmByte);
        }

        private int ReadPositiveIntFromEnvironment(string variableName, int fallback)
        {
            var raw = Environment.GetEnvironmentVariable(variableName);
            if (string.IsNullOrWhiteSpace(raw))
                return fallback;
            if (!int.TryParse(raw, out var parsed))
                return fallback;
            if (parsed <= 0)
                return fallback;
            return parsed;
        }

        private bool IsVerifiableIlModeEnabled()
        {
            return IsEnvironmentEnabled("KRYPTON_VERIFIABLE_IL_MODE");
        }

        private bool IsEnvironmentEnabled(string variableName)
        {
            var raw = Environment.GetEnvironmentVariable(variableName);
            if (string.IsNullOrWhiteSpace(raw))
                return false;

            return string.Equals(raw, "1", StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(raw, "true", StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(raw, "yes", StringComparison.OrdinalIgnoreCase);
        }

        private int CountReachableEntryUnderflowMethods(DevirtualizationCtx ctx)
        {
            if (ctx?.VirtualizedMethods == null)
                return 0;

            var count = 0;
            foreach (var method in ctx.VirtualizedMethods)
            {
                if (method?.MethodBody?.Instructions == null || method.MethodBody.Instructions.Count == 0)
                    continue;
                if (HasReachableEntryUnderflow(ctx, method))
                    count++;
            }

            return count;
        }

        private void AccumulateCilNeighborSuspicion(
            DevirtualizationCtx ctx,
            RecompiledMethodArtifact artifact,
            CilBodyAnalysisResult analysis,
            SemanticEvaluationResult result)
        {
            if (ctx?.PatternMatcher == null || artifact?.InstructionOrigins == null || analysis?.IssueInstructionIndices == null || result == null)
                return;
            if (analysis.IssueInstructionIndices.Count == 0)
                return;

            var origins = artifact.InstructionOrigins;
            foreach (var issueIndex in analysis.IssueInstructionIndices)
            {
                if (issueIndex < 0 || issueIndex >= origins.Count)
                    continue;

                var seen = new HashSet<int>();
                var start = Math.Max(0, issueIndex - 6);
                for (var i = start; i <= issueIndex; i++)
                {
                    var origin = origins[i];
                    if (origin == null)
                        continue;

                    var vmByte = origin.VmByte;
                    if (vmByte < 0 || !ctx.PatternMatcher.IsOpCodeValueKnown(vmByte))
                        continue;
                    if (!seen.Add(vmByte))
                        continue;

                    var mapped = ctx.PatternMatcher.GetOpCodeValue(vmByte);
                    if (!IsCilIssueNeighborCandidate(mapped))
                        continue;

                    if (!result.ViolationsByVmByte.TryGetValue(vmByte, out var count))
                        count = 0;
                    result.ViolationsByVmByte[vmByte] = count + 1;
                }
            }
        }

        private bool IsCilIssueNeighborCandidate(VMOpCode opCode)
        {
            switch (opCode)
            {
                case VMOpCode.Pop:
                case VMOpCode.Dup:
                case VMOpCode.Nop:
                case VMOpCode.Conv_I4:
                case VMOpCode.Conv_I8:
                case VMOpCode.Conv_U1:
                case VMOpCode.Not:
                case VMOpCode.Neg:
                case VMOpCode.Add:
                case VMOpCode.Ceq:
                case VMOpCode.Cgt:
                case VMOpCode.Cgt_Un:
                case VMOpCode.Clt:
                case VMOpCode.Clt_Un:
                case VMOpCode.Sub:
                case VMOpCode.Xor:
                case VMOpCode.Shl:
                case VMOpCode.Shr:
                case VMOpCode.Br:
                case VMOpCode.BrTrue:
                case VMOpCode.BrFalse:
                case VMOpCode.BrLessThan:
                case VMOpCode.Switch:
                    return true;
                default:
                    return false;
            }
        }

        private string BuildCilEvaluationCacheKey(DevirtualizationCtx ctx)
        {
            var operandTypes = ctx.GetOperandTypes();
            var sb = new StringBuilder(1024);
            sb.Append("m:");
            sb.Append(ctx.VirtualizedMethods?.Count ?? 0);
            sb.Append("|o:");
            sb.Append(operandTypes.Length);
            sb.Append('|');

            for (var vmByte = 0; vmByte < operandTypes.Length; vmByte++)
            {
                if (!ctx.PatternMatcher.IsOpCodeValueKnown(vmByte))
                    continue;

                var opCode = ctx.PatternMatcher.GetOpCodeValue(vmByte);
                sb.Append(vmByte);
                sb.Append(':');
                sb.Append((int) opCode);
                sb.Append(';');
            }

            return sb.ToString();
        }

        private bool TryGetStackEffect(
            VMOpCode opCode,
            object operand,
            AsmResolver.DotNet.ModuleDefinition module,
            int expectedReturnStack,
            out int pop,
            out int push)
        {
            pop = 0;
            push = 0;

            if (VMOpCodeCatalog.TryGet(opCode, out var semantic) &&
                semantic.HasFixedStackEffect)
            {
                pop = semantic.Pop;
                push = semantic.Push;
                return true;
            }

            switch (opCode)
            {
                case VMOpCode.Nop:
                    return true;
                case VMOpCode.Ldarg:
                case VMOpCode.Ldloc:
                case VMOpCode.Ldloca:
                case VMOpCode.Ldc_I4:
                case VMOpCode.Ldc_R4:
                case VMOpCode.Ldc_R8:
                case VMOpCode.Ldstr:
                case VMOpCode.Ldnull:
                case VMOpCode.Ldsfld:
                case VMOpCode.Ldsflda:
                case VMOpCode.Ldtoken:
                    push = 1;
                    return true;
                case VMOpCode.Box:
                    pop = 1;
                    push = 1;
                    return true;
                case VMOpCode.Constrained:
                    return true;
                case VMOpCode.Newobj:
                {
                    if (!(operand is int token))
                        return false;
                    IMethodDescriptor descriptor;
                    try
                    {
                        descriptor = module.LookupMember(token) as IMethodDescriptor;
                    }
                    catch
                    {
                        return false;
                    }

                    var sig = descriptor?.Signature ?? descriptor?.Resolve()?.Signature;
                    if (sig == null || !IsConstructorMethod(descriptor))
                        return false;

                    pop = sig.ParameterTypes.Count;
                    push = 1;
                    return true;
                }
                case VMOpCode.Ldfld:
                case VMOpCode.Ldflda:
                case VMOpCode.Ldlen:
                case VMOpCode.Ldobj:
                case VMOpCode.Unbox_Any:
                case VMOpCode.Isinst:
                case VMOpCode.Castclass:
                    pop = 1;
                    push = 1;
                    return true;
                case VMOpCode.Ldelem_Ref:
                case VMOpCode.Ldelem_U1:
                case VMOpCode.Ldelema:
                    pop = 2;
                    push = 1;
                    return true;
                case VMOpCode.Newarr:
                    pop = 1;
                    push = 1;
                    return true;
                case VMOpCode.Stloc:
                case VMOpCode.Pop:
                    pop = 1;
                    return true;
                case VMOpCode.Dup:
                    pop = 1;
                    push = 2;
                    return true;
                case VMOpCode.Add:
                case VMOpCode.Sub:
                case VMOpCode.Xor:
                case VMOpCode.Shl:
                case VMOpCode.Shr:
                    pop = 2;
                    push = 1;
                    return true;
                case VMOpCode.Neg:
                case VMOpCode.Not:
                case VMOpCode.Conv_I4:
                case VMOpCode.Conv_I8:
                case VMOpCode.Conv_U1:
                    pop = 1;
                    push = 1;
                    return true;
                case VMOpCode.Br:
                case VMOpCode.Leave:
                case VMOpCode.EndFinally:
                    return true;
                case VMOpCode.BrTrue:
                case VMOpCode.BrFalse:
                    pop = 1;
                    return true;
                case VMOpCode.BrLessThan:
                case VMOpCode.BrGreaterThan:
                case VMOpCode.BrLessOrEqual:
                case VMOpCode.BrGreaterOrEqual:
                case VMOpCode.BrEqual:
                case VMOpCode.BrNotEqual:
                    pop = 2;
                    return true;
                case VMOpCode.Switch:
                    pop = 1;
                    return true;
                case VMOpCode.Stsfld:
                    pop = 1;
                    return true;
                case VMOpCode.Stfld:
                    pop = 2;
                    return true;
                case VMOpCode.Stobj:
                    pop = 2;
                    return true;
                case VMOpCode.Stelem_Ref:
                case VMOpCode.Stelem_I1:
                    pop = 3;
                    return true;
                case VMOpCode.Call:
                case VMOpCode.Callvirt:
                {
                    if (!(operand is int token))
                        return false;
                    IMethodDescriptor descriptor;
                    try
                    {
                        descriptor = module.LookupMember(token) as IMethodDescriptor;
                    }
                    catch
                    {
                        return false;
                    }

                    var sig = descriptor?.Signature ?? descriptor?.Resolve()?.Signature;
                    if (sig == null)
                        return false;
                    pop = sig.ParameterTypes.Count + ((opCode == VMOpCode.Callvirt || sig.HasThis) ? 1 : 0);
                    push = string.Equals(sig.ReturnType?.FullName, "System.Void", StringComparison.Ordinal) ? 0 : 1;
                    return true;
                }
                case VMOpCode.Ret:
                    pop = expectedReturnStack;
                    return true;
                default:
                    return false;
            }
        }

        private struct OperandKindStats
        {
            public int Total;
            public int MethodTokens;
            public int ConstructorMethods;
            public int FieldTokens;
            public int StaticFields;
            public int InstanceFields;
            public int PrivateImplementationFields;
            public int TypeTokens;
            public int UserStrings;
        }

        private struct IndexUsageStats
        {
            public int Total;
            public int LocalLike;
            public int ArgLike;
            public int StoreLike;
            public int LoadLike;
        }

        private sealed class SemanticEvaluationResult
        {
            public int TotalViolations { get; set; }
            public Dictionary<int, int> ViolationsByVmByte { get; } = new Dictionary<int, int>();

            public SemanticEvaluationResult Clone()
            {
                var clone = new SemanticEvaluationResult
                {
                    TotalViolations = TotalViolations
                };
                foreach (var pair in ViolationsByVmByte)
                    clone.ViolationsByVmByte[pair.Key] = pair.Value;
                return clone;
            }
        }

        private sealed class SemanticCandidateAdjustment
        {
            public SemanticCandidateAdjustment(
                int vmByte,
                VMOpCode oldOpcode,
                VMOpCode newOpcode,
                int baselineViolations,
                int candidateViolations,
                int directViolations,
                int baselineCilViolations = -1,
                int candidateCilViolations = -1)
            {
                VmByte = vmByte;
                OldOpcode = oldOpcode;
                NewOpcode = newOpcode;
                BaselineViolations = baselineViolations;
                CandidateViolations = candidateViolations;
                DirectViolations = directViolations;
                BaselineCilViolations = baselineCilViolations;
                CandidateCilViolations = candidateCilViolations;
            }

            public int VmByte { get; }
            public VMOpCode OldOpcode { get; }
            public VMOpCode NewOpcode { get; }
            public int BaselineViolations { get; }
            public int CandidateViolations { get; }
            public int DirectViolations { get; }
            public int BaselineCilViolations { get; }
            public int CandidateCilViolations { get; }
            public int TotalImprovement => BaselineViolations - CandidateViolations;
        }

        private sealed class OpcodeMappingSnapshot
        {
            public OpcodeMappingSnapshot(int vmByte, bool isMapped, VMOpCode opCode, OpcodeMappingConfidence confidence)
            {
                VmByte = vmByte;
                IsMapped = isMapped;
                OpCode = opCode;
                Confidence = confidence;
            }

            public int VmByte { get; }
            public bool IsMapped { get; }
            public VMOpCode OpCode { get; }
            public OpcodeMappingConfidence Confidence { get; }
        }

        // The type pass is only ever used to refute candidates, so a refutation of
        // the mapping actually being shipped is either a real mapping error or a
        // bug in the pass itself. Either way it belongs in the log rather than
        // silently narrowing the search away from the truth.
        private static void ReportTypeCheckerDisagreements(DevirtualizationCtx ctx)
        {
            foreach (var method in ctx.VirtualizedMethods)
            {
                var instructions = method?.MethodBody?.Instructions;
                if (instructions == null || instructions.Count == 0)
                    continue;

                var mapping = new Dictionary<int, VMOpCode>();
                foreach (var instruction in instructions)
                {
                    if (instruction == null || mapping.ContainsKey(instruction.VmByte))
                        continue;
                    if (ctx.PatternMatcher.IsOpCodeValueKnown(instruction.VmByte))
                        mapping[instruction.VmByte] = ctx.PatternMatcher.GetOpCodeValue(instruction.VmByte);
                }

                if (mapping.Count == 0)
                    continue;

                if (TypedStackConstraint.IsTypeConsistent(ctx, method, mapping, out var reason, out var index))
                    continue;

                var vmByte = index >= 0 && index < instructions.Count ? instructions[index].VmByte : -1;
                ctx.Options.Logger.Warning(
                    $"  [type-check] the current mapping is refuted in MethodKey {method.MethodKey} " +
                    $"at VM index {index} (vm 0x{vmByte:X2}): {reason}");
            }
        }

    }
}
