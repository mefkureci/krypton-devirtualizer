using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using AsmResolver.DotNet;
using AsmResolver.DotNet.Builder;
using AsmResolver.DotNet.Code.Cil;
using AsmResolver.DotNet.Signatures;
using AsmResolver.DotNet.Signatures.Types;
using AsmResolver.PE.DotNet.Cil;
using Krypton.Core;

namespace Krypton.Pipeline.Stages
{
    /// <summary>
    /// Recovers NET Reactor "Hide Method Calls" stubs by:
    ///
    ///   1. Invoking Krypton.Runner.exe on the ORIGINAL protected assembly to
    ///      capture the DynamicMethod delegate table at runtime.
    ///
    ///   2. Parsing the dump to build a map:  field_metadata_token → real_callee
    ///      (e.g. 0x0400017E → Control::set_Text(string))
    ///
    ///   3. Scanning every devirtualized method body for the NET Reactor stub pattern:
    ///          ldsfld   <hidden_field>          ; load delegate from anonymous field
    ///          callvirt Delegate::Invoke / ...  ; call it
    ///      and replacing the pair with a direct callvirt to the real method.
    ///
    /// The stage is optional: if Krypton.Runner is not found or the dump fails,
    /// devirtualization proceeds without hidden-call recovery (existing behavior).
    /// </summary>
    public sealed class HiddenCallRecovery : IStage
    {
        public string Name => "HiddenCallRecovery";

        /// <summary>
        /// Applies the same evidence-driven rewrite to a known-valid restored
        /// assembly copy. This is used only as a write fallback when unrelated
        /// malformed bootstrap methods prevent the main donor image from being
        /// serialized; no new recovery logic is involved.
        /// </summary>
        public static int PatchAssemblyCopy(
            string donorPath,
            string outputPath,
            string dumpPath,
            out int siteCount,
            Func<MethodDefinition, bool> methodFilter = null)
        {
            siteCount = 0;
            if (string.IsNullOrWhiteSpace(donorPath) || !File.Exists(donorPath) ||
                string.IsNullOrWhiteSpace(dumpPath) || !File.Exists(dumpPath))
                return 0;

            var module = ModuleDefinition.FromFile(donorPath);
            var map = BuildCalleeMap(dumpPath, null);
            if (map == null || map.Count == 0)
                return 0;

            var sites = new List<HiddenCallSiteResult>();
            var patched = 0;
            foreach (var type in module.GetAllTypes())
            {
                foreach (var method in type.Methods)
                {
                    if (method.CilMethodBody == null ||
                        (methodFilter != null && !methodFilter(method)))
                        continue;
                    patched += PatchMethod(method, map, module, sites);
                }
            }

            module.Write(outputPath, new ManagedPEImageBuilder(new DotNetDirectoryFactory(
                MetadataBuilderFlags.PreserveTypeDefinitionIndices |
                MetadataBuilderFlags.PreserveFieldDefinitionIndices |
                MetadataBuilderFlags.PreserveMethodDefinitionIndices |
                MetadataBuilderFlags.PreserveParameterDefinitionIndices |
                MetadataBuilderFlags.PreserveEventDefinitionIndices |
                MetadataBuilderFlags.PreservePropertyDefinitionIndices |
                MetadataBuilderFlags.PreserveMemberReferenceIndices |
                MetadataBuilderFlags.NoStringsStreamOptimization)));
            siteCount = sites.Count(s => s.Rewrite);
            return patched;
        }

        public void Run(DevirtualizationCtx ctx)
        {
            // Kill-switch: set KRYPTON_HCR_ENABLE=0 to disable.
            var envSwitch = Environment.GetEnvironmentVariable("KRYPTON_HCR_ENABLE");
            if (!string.IsNullOrWhiteSpace(envSwitch) &&
                string.Equals(envSwitch, "0", StringComparison.Ordinal))
            {
                ctx.Options.Logger.Info("[HCR] Disabled via KRYPTON_HCR_ENABLE=0, skipping.");
                return;
            }

            string originalPath = ctx.Options.FilePath;
            if (string.IsNullOrWhiteSpace(originalPath) || !File.Exists(originalPath))
            {
                ctx.Options.Logger.Warning("[HCR] Original assembly path not set — skipping.");
                return;
            }

            // ── 1. Find Krypton.Runner.exe ──────────────────────────────────────
            string runnerPath = FindRunner();
            if (runnerPath == null)
            {
                ctx.Options.Logger.Warning("[HCR] Krypton.Runner.exe not found — skipping hidden-call recovery.");
                return;
            }

            // ── 2. Run Krypton.Runner to produce a dump ─────────────────────────
            string dumpPath = Path.ChangeExtension(originalPath, null) + "-dynamic-dump.json";
            ctx.Options.Logger.Info($"[HCR] Running Krypton.Runner on: {originalPath}");

            bool dumpOk = InvokeRunner(runnerPath, originalPath, dumpPath, ctx);
            if (!dumpOk || !File.Exists(dumpPath))
            {
                ctx.Options.Logger.Warning("[HCR] Runner did not produce a dump — skipping.");
                return;
            }

            // ── 3. Parse dump and build token → callee map ───────────────────────
            var calleeMap = BuildCalleeMap(dumpPath, ctx);
            if (calleeMap == null || calleeMap.Count == 0)
            {
                ctx.Options.Logger.Warning("[HCR] Dump produced no usable entries — skipping.");
                return;
            }
            ctx.Options.Logger.Info($"[HCR] Built callee map with {calleeMap.Count} entries.");

            // ── 4. Patch methods in the module ───────────────────────────────────
            if (ctx.Module == null)
            {
                ctx.Options.Logger.Warning("[HCR] Module not available — skipping.");
                return;
            }

            int patchedCalls   = 0;
            int patchedMethods = 0;
            var siteResults = new List<HiddenCallSiteResult>();

            foreach (var type in ctx.Module.GetAllTypes())
            {
                foreach (var method in type.Methods)
                {
                    if (method.CilMethodBody == null) continue;
                    int patched;
                    try
                    {
                        patched = PatchMethod(method, calleeMap, ctx.Module, siteResults);
                    }
                    catch (Exception ex)
                    {
                        ctx.Options.Logger.Warning(
                            $"[HCR] Patch failed in {method.FullName}: {ex.GetType().Name}: {ex.Message}");
                        continue;
                    }
                    if (patched > 0)
                    {
                        patchedCalls += patched;
                        patchedMethods++;
                    }
                }
            }

            ctx.Options.Logger.Success(
                $"[HCR] Recovered {patchedCalls} hidden call(s) in {patchedMethods} method(s).");
            WriteSiteReport(originalPath, calleeMap, siteResults, ctx);
        }

        // ──────────────────────────────────────────────────────────────────────────
        // Runner invocation
        // ──────────────────────────────────────────────────────────────────────────

        private static string FindRunner()
        {
            // Deployment: Runner.exe sits next to Krypton.exe
            // Development: Krypton is at <root>/Krypton/bin/<cfg>/net8.0/
            //              Runner  is at <root>/Krypton.Runner/bin/<cfg>/net48/
            //              so we walk up 3 levels to reach <root>.
            string baseDir = AppContext.BaseDirectory;
            // Development layout: <root>/Krypton/bin/<cfg>/net8.0/ → 4 levels up to <root>
            string up4 = Path.Combine(baseDir, "..", "..", "..", "..");
            var candidates = new[]
            {
                Path.Combine(baseDir, "Krypton.Runner.exe"),
                Path.Combine(up4, "Krypton.Runner", "bin", "Release", "net48", "Krypton.Runner.exe"),
                Path.Combine(up4, "Krypton.Runner", "bin", "Debug",   "net48", "Krypton.Runner.exe"),
            };
            return candidates.Select(Path.GetFullPath).FirstOrDefault(File.Exists);
        }

        private static bool InvokeRunner(
            string runnerPath,
            string targetPath,
            string dumpPath,
            DevirtualizationCtx ctx)
        {
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName               = runnerPath,
                    Arguments              = $"\"{targetPath}\" \"{dumpPath}\"",
                    UseShellExecute        = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError  = true,
                };

                using var proc = Process.Start(psi);
                if (proc == null) return false;

                string stdout = proc.StandardOutput.ReadToEnd();
                string stderr = proc.StandardError.ReadToEnd();
                proc.WaitForExit(60_000); // 60 second timeout

                foreach (var line in stdout.Split('\n'))
                    if (!string.IsNullOrWhiteSpace(line))
                        ctx.Options.Logger.Info("  [Runner] " + line.TrimEnd());

                foreach (var line in stderr.Split('\n'))
                    if (!string.IsNullOrWhiteSpace(line))
                        ctx.Options.Logger.Warning("  [Runner/err] " + line.TrimEnd());

                return proc.ExitCode == 0;
            }
            catch (Exception ex)
            {
                ctx.Options.Logger.Warning($"[HCR] Failed to start Runner: {ex.Message}");
                return false;
            }
        }

        // ──────────────────────────────────────────────────────────────────────────
        // Dump parsing → token map
        // ──────────────────────────────────────────────────────────────────────────

        /// <summary>
        /// Returns a map from field metadata token (e.g. 0x0400017E) to a resolved
        /// callee descriptor (declaring type full name, method name, signature).
        /// </summary>
        private static Dictionary<int, CalleeDescriptor> BuildCalleeMap(
            string dumpPath,
            DevirtualizationCtx ctx)
        {
            try
            {
                string json = File.ReadAllText(dumpPath);
                using var doc = JsonDocument.Parse(json);
                var root = doc.RootElement;

                if (!root.TryGetProperty("Methods", out var methods)) return null;

                var map = new Dictionary<int, CalleeDescriptor>();

                foreach (var entry in methods.EnumerateArray())
                {
                    // SourceField format: "::|0x04xxxxxx" or "TypeName::FieldName|0x04xxxxxx"
                    if (!entry.TryGetProperty("SourceField", out var sfProp)) continue;
                    string sourceField = sfProp.GetString() ?? string.Empty;

                    int fieldToken = ExtractToken(sourceField);
                    if (fieldToken == 0) continue;

                    // Find the single real call instruction — skip ldarg.*, tail., ret
                    if (!entry.TryGetProperty("Instructions", out var instrs)) continue;

                    CalleeDescriptor callee = ExtractCallee(instrs);
                    if (callee == null) continue;

                    map[fieldToken] = callee;
                }

                // Capture order decides whether dnlib could name a type's assembly: an
                // entry recorded before that assembly was loaded has none, while a later
                // entry for the same type does. Fill the gaps from the evidence itself
                // rather than guessing a scope from the namespace.
                var assemblyByType = new Dictionary<string, string>(StringComparer.Ordinal);
                foreach (var callee in map.Values)
                {
                    if (!string.IsNullOrWhiteSpace(callee.DeclaringType) &&
                        !string.IsNullOrWhiteSpace(callee.DeclaringAssembly))
                    {
                        assemblyByType[callee.DeclaringType] = callee.DeclaringAssembly;
                    }
                }

                var filled = 0;
                foreach (var callee in map.Values)
                {
                    if (!string.IsNullOrWhiteSpace(callee.DeclaringAssembly))
                        continue;
                    if (callee.DeclaringType != null &&
                        assemblyByType.TryGetValue(callee.DeclaringType, out var assemblyName))
                    {
                        callee.DeclaringAssembly = assemblyName;
                        filled++;
                    }
                }

                if (filled > 0 && ctx != null)
                {
                    ctx.Options.Logger.Info(
                        $"[HCR] Completed the declaring assembly of {filled} callee(s) from other entries.");
                }

                return map;
            }
            catch (Exception ex)
            {
                if (ctx != null)
                    ctx.Options.Logger.Warning($"[HCR] Failed to parse dump: {ex.Message}");
                return null;
            }
        }

        private static int ExtractToken(string sourceField)
        {
            // Expect something like "::|0x04000165" or "Type::Field|0x04000165"
            int pipeIdx = sourceField.LastIndexOf('|');
            string tokenStr = pipeIdx >= 0
                ? sourceField.Substring(pipeIdx + 1)
                : sourceField;

            if (tokenStr.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                tokenStr = tokenStr.Substring(2);

            return int.TryParse(tokenStr, System.Globalization.NumberStyles.HexNumber,
                null, out int tok) ? tok : 0;
        }

        private static CalleeDescriptor ExtractCallee(JsonElement instrs)
        {
            // Pattern in each DynamicMethod thunk:
            //   ldarg.0, [ldarg.1, ...], [tail.], call/callvirt RealMethod, ret
            // We want the one instruction that references a real method.
            foreach (var instr in instrs.EnumerateArray())
            {
                if (!instr.TryGetProperty("OperandKind", out var opKind)) continue;
                if (!string.Equals(opKind.GetString(), "method", StringComparison.Ordinal))
                    continue;

                instr.TryGetProperty("Opcode",     out var opcodeProp);
                instr.TryGetProperty("DeclType",   out var declTypeProp);
                instr.TryGetProperty("MemberName", out var memberNameProp);
                instr.TryGetProperty("MemberSig",  out var memberSigProp);
                instr.TryGetProperty("DeclAssembly", out var declAssemblyProp);

                string opcode     = opcodeProp.GetString()     ?? string.Empty;
                string declType   = declTypeProp.GetString()   ?? string.Empty;
                string memberName = memberNameProp.GetString()  ?? string.Empty;
                string memberSig  = memberSigProp.GetString()  ?? string.Empty;
                string declAssembly = declAssemblyProp.ValueKind == JsonValueKind.String
                    ? declAssemblyProp.GetString()
                    : null;

                // Skip delegate Invoke itself (we're looking for the real call inside the thunk)
                if (string.Equals(memberName, "Invoke", StringComparison.Ordinal))
                    continue;

                // Parse parameters from MemberSig for proper arity
                var paramTypes = ParseParamTypes(memberSig, instr);

                var isGenericMethod = instr.TryGetProperty("IsGenericMethod", out var isGenMethodProp) &&
                                       isGenMethodProp.ValueKind == JsonValueKind.True;
                var methodGenericArgs = ReadStringList(instr, "MethodGenericArgs");

                return new CalleeDescriptor
                {
                    Opcode        = opcode,
                    DeclaringType = declType,
                    MethodName    = memberName,
                    MemberSig     = memberSig,
                    DeclaringAssembly = declAssembly,
                    ParamTypes    = paramTypes,
                    IsInstance    = memberSig.StartsWith("instance", StringComparison.Ordinal),
                    IsGenericMethod   = isGenericMethod,
                    MethodGenericArgs = methodGenericArgs,
                };
            }
            return null;
        }

        private static List<string> ParseParamTypes(string sig, JsonElement instr)
        {
            var result = new List<string>();

            // Try reading from "Params" array if present
            if (instr.TryGetProperty("Params", out var paramsArr))
            {
                foreach (var p in paramsArr.EnumerateArray())
                {
                    p.TryGetProperty("Type", out var typeProp);
                    p.TryGetProperty("IsByRef", out var byRefProp);
                    string t = typeProp.GetString() ?? "System.Object";
                    bool r   = byRefProp.ValueKind == JsonValueKind.True;
                    result.Add(r ? t + "&" : t);
                }
            }
            return result;
        }

        private static List<string> ReadStringList(JsonElement instr, string propertyName)
        {
            var result = new List<string>();
            if (!instr.TryGetProperty(propertyName, out var arr) || arr.ValueKind != JsonValueKind.Array)
                return result;

            foreach (var item in arr.EnumerateArray())
                if (item.ValueKind == JsonValueKind.String)
                    result.Add(item.GetString());

            return result;
        }

        // ──────────────────────────────────────────────────────────────────────────
        // IL patching
        // ──────────────────────────────────────────────────────────────────────────

        private static int PatchMethod(
            MethodDefinition method,
            Dictionary<int, CalleeDescriptor> calleeMap,
            ModuleDefinition module,
            ICollection<HiddenCallSiteResult> siteResults)
        {
            var body = method.CilMethodBody;
            var il   = body.Instructions;
            int count = 0;

            for (int i = 0; i < il.Count - 1; i++)
            {
                if (il[i].OpCode != CilOpCodes.Ldsfld) continue;

                var fieldRef = il[i].Operand as IFieldDescriptor;
                if (fieldRef == null) continue;

                int fieldToken = fieldRef.MetadataToken.ToInt32();

                // Find the delegate dispatch call: named "Invoke" or with obfuscated name
                // (NET Reactor renames Invoke to control chars that have no identifier chars).
                int callIdx = FindDelegateCall(il, i + 1, fieldRef, out var pattern);
                if (callIdx < 0) continue;

                var site = new HiddenCallSiteResult
                {
                    Caller = method.FullName,
                    IlOffset = il[i].Offset,
                    DelegateField = $"0x{fieldToken:X8}",
                    Pattern = pattern,
                    Rewrite = false,
                    SignatureCompatible = false
                };
                siteResults?.Add(site);

                if (!calleeMap.TryGetValue(fieldToken, out var callee))
                {
                    site.CapturedTarget = "<missing>";
                    continue;
                }
                site.CapturedTarget = $"{callee.DeclaringType}::{callee.MethodName}";

                if (!IsCompatibleWrapperSignature(il[callIdx].Operand as IMethodDescriptor, fieldRef, callee))
                    continue;
                site.SignatureCompatible = true;

                var replacement = BuildCallInstruction(callee, module);
                if (replacement == null) continue;

                // Patching, label-safe:
                //   BEFORE: ldsfld <delegate>, [arg-loading...], callvirt Invoke
                //   AFTER:  nop,               [arg-loading...], callvirt/call RealMethod
                //
                // Both edits mutate the existing instruction objects. Replacing an
                // instruction object, or removing one, silently invalidates every
                // CilInstructionLabel bound to it, and the module then fails to build
                // with "references an instruction that is not present in the method
                // body" - in a completely unrelated method whose branch happened to
                // target it.
                il[callIdx].OpCode = replacement.OpCode;
                il[callIdx].Operand = replacement.Operand;

                il[i].OpCode = CilOpCodes.Nop;
                il[i].Operand = null;

                count++;
                site.DirectReplacement = replacement.OpCode.Code + " " +
                                        callee.DeclaringType + "::" + callee.MethodName;
                site.Rewrite = true;
            }

            return count;
        }

        /// <summary>
        /// Finds the delegate Invoke call after <paramref name="start"/>.
        /// Returns the first call/callvirt whose method name is "Invoke" (standard)
        /// or empty-string (NET Reactor renames Invoke to "").
        /// Other call instructions are NOT used as fallback — they are not delegate dispatches.
        /// <paramref name="diagName"/> receives the matched name for logging.
        /// Returns -1 if no qualifying call found within 20 slots or at a control-flow boundary.
        /// </summary>
        private static int FindDelegateCall(
            CilInstructionCollection il,
            int start,
            IFieldDescriptor delegateField,
            out string diagName)
        {
            diagName = null;
            int limit = Math.Min(start + 20, il.Count);

            for (int i = start; i < limit; i++)
            {
                var instr = il[i];
                var op    = instr.OpCode;

                if (op == CilOpCodes.Callvirt || op == CilOpCodes.Call)
                {
                    string name = (instr.Operand is IMethodDescriptor md)
                        ? md.Name?.ToString() ?? string.Empty
                        : string.Empty;

                    // Accept "Invoke" (standard) or any name with no visible
                    // identifier characters — NET Reactor renames Invoke to control chars.
                    bool isObfuscatedInvoke = !name.Any(c => char.IsLetterOrDigit(c) || c == '_');
                    if (string.Equals(name, "Invoke", StringComparison.Ordinal) || isObfuscatedInvoke)
                    {
                        diagName = name.Length == 0 ? "<empty>" : isObfuscatedInvoke ? "<ctrlchars>" : "Invoke";
                        return i;
                    }

                    if (IsDelegateWrapperCall(instr.Operand as IMethodDescriptor, delegateField))
                    {
                        diagName = "wrapper";
                        return i;
                    }
                }

                // Stop at unconditional control flow.
                if (op == CilOpCodes.Ret    || op == CilOpCodes.Throw  ||
                    op == CilOpCodes.Br     || op == CilOpCodes.Br_S   ||
                    op == CilOpCodes.Switch)
                    break;
            }

            return -1;
        }

        private static bool IsDelegateWrapperCall(
            IMethodDescriptor method,
            IFieldDescriptor delegateField)
        {
            if (method?.Signature == null || delegateField == null)
                return false;

            var resolved = SafeResolve(method);
            if (resolved != null && !resolved.IsStatic)
                return false;

            var fieldType = delegateField.Signature?.FieldType?.FullName ??
                            delegateField.Resolve()?.Signature?.FieldType?.FullName;
            if (string.IsNullOrWhiteSpace(fieldType) || method.Signature.ParameterTypes.Count == 0)
                return false;

            var last = method.Signature.ParameterTypes[method.Signature.ParameterTypes.Count - 1];
            return string.Equals(last?.FullName, fieldType, StringComparison.Ordinal);
        }

        private static bool IsCompatibleWrapperSignature(
            IMethodDescriptor wrapper,
            IFieldDescriptor delegateField,
            CalleeDescriptor callee)
        {
            if (!IsDelegateWrapperCall(wrapper, delegateField) || callee == null)
                return false;

            var wrapperParameters = wrapper.Signature.ParameterTypes.Count - 1;
            var targetParameters = callee.ParamTypes.Count + (callee.IsInstance ? 1 : 0);
            return wrapperParameters == targetParameters;
        }

        private static MethodDefinition SafeResolve(IMethodDescriptor method)
        {
            try { return method?.Resolve(); }
            catch { return null; }
        }

        private static void WriteSiteReport(
            string originalPath,
            Dictionary<int, CalleeDescriptor> calleeMap,
            IList<HiddenCallSiteResult> sites,
            DevirtualizationCtx ctx)
        {
            try
            {
                var path = Path.ChangeExtension(originalPath, null) + "-hidden-call-report.txt";
                var sb = new StringBuilder();
                sb.AppendLine("Krypton HiddenCallRecovery report");
                sb.AppendLine("================================");
                sb.AppendLine($"captured dynamic targets: {calleeMap.Count}");
                sb.AppendLine($"hidden-call sites: {sites.Count}");
                sb.AppendLine($"rewritten: {sites.Count(s => s.Rewrite)}");
                sb.AppendLine($"remaining: {sites.Count(s => !s.Rewrite)}");
                sb.AppendLine($"unresolved targets: {sites.Count(s => s.CapturedTarget == "<missing>")}");
                sb.AppendLine();
                foreach (var site in sites)
                {
                    sb.AppendLine($"caller: {site.Caller}");
                    sb.AppendLine($"IL offset: 0x{site.IlOffset:X4}");
                    sb.AppendLine($"delegate field: {site.DelegateField}");
                    sb.AppendLine($"pattern: {site.Pattern}");
                    sb.AppendLine($"captured target: {site.CapturedTarget ?? "<none>"}");
                    sb.AppendLine($"signature compatible: {(site.SignatureCompatible ? "YES" : "NO")}");
                    sb.AppendLine($"direct replacement: {site.DirectReplacement ?? "<none>"}");
                    sb.AppendLine($"rewrite: {(site.Rewrite ? "YES" : "NO")}");
                    sb.AppendLine();
                }
                File.WriteAllText(path, sb.ToString());
                ctx.Options.Logger.Info($"[HCR] Site report: {path}");
            }
            catch (Exception ex)
            {
                ctx.Options.Logger.Warning($"[HCR] Could not write site report: {ex.Message}");
            }
        }


        /// <summary>
        /// Builds the replacement CIL instruction that directly calls the real method.
        /// </summary>
        private static CilInstruction BuildCallInstruction(
            CalleeDescriptor callee,
            ModuleDefinition module)
        {
            try
            {
                var scope     = ResolveScope(callee, callee.DeclaringType, module);
                var ns        = GetNamespace(callee.DeclaringType);
                var typeName  = GetTypeName(callee.DeclaringType);

                ITypeDefOrRef typeRef = new TypeReference(module, scope, ns, typeName);

                // Handle nested types (e.g. "System.Windows.Forms.Control/ControlCollection")
                // In AsmResolver 5.x, TypeReference implements IResolutionScope, so nested type
                // references are built by passing the outer TypeReference as the scope.
                if (callee.DeclaringType.Contains("/"))
                {
                    var parts = callee.DeclaringType.Split('/');
                    var outerScope = ResolveScope(callee, parts[0], module);
                    var current = new TypeReference(module, outerScope, GetNamespace(parts[0]), GetTypeName(parts[0]));
                    for (int p = 1; p < parts.Length; p++)
                        current = new TypeReference(module, current, string.Empty, parts[p]);
                    typeRef = current;
                }

                var methodSig = BuildMethodSignature(callee, module);
                if (methodSig == null) return null;

                var memberRef = new MemberReference(typeRef, callee.MethodName, methodSig);

                var opcode = (string.Equals(callee.Opcode, "call",    StringComparison.OrdinalIgnoreCase) ||
                              string.Equals(callee.Opcode, "call.",    StringComparison.OrdinalIgnoreCase))
                    ? CilOpCodes.Call
                    : CilOpCodes.Callvirt;

                // Constructors always use newobj (but they appear as "call" in thunks that
                // forward to them)
                if (string.Equals(callee.MethodName, ".ctor", StringComparison.Ordinal))
                    opcode = CilOpCodes.Newobj;

                IMethodDescriptor target = memberRef;
                if (callee.IsGenericMethod)
                {
                    // Flagged as a generic method instantiation but the runtime dump captured
                    // no concrete arguments — reconstructing would mean guessing the
                    // instantiation. Skip this call site rather than emit a wrong one.
                    if (callee.MethodGenericArgs == null || callee.MethodGenericArgs.Count == 0)
                        return null;

                    var corLib = module.CorLibTypeFactory;
                    var genericArgs = new TypeSignature[callee.MethodGenericArgs.Count];
                    for (var idx = 0; idx < callee.MethodGenericArgs.Count; idx++)
                    {
                        var argSig = ParseTypeSig(callee.MethodGenericArgs[idx], module, corLib);
                        if (argSig == null)
                            return null; // couldn't resolve one of the generic arguments — skip, don't guess

                        genericArgs[idx] = argSig;
                    }

                    target = new MethodSpecification(memberRef, new GenericInstanceMethodSignature(genericArgs));
                }

                return new CilInstruction(opcode, target);
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[HCR] BuildCallInstruction failed for {callee.DeclaringType}::{callee.MethodName}: {ex.Message}");
                return null;
            }
        }

        // ──────────────────────────────────────────────────────────────────────────
        // Helpers for type/sig construction
        // ──────────────────────────────────────────────────────────────────────────

        private static MethodSignature BuildMethodSignature(
            CalleeDescriptor callee,
            ModuleDefinition module)
        {
            var corLib = module.CorLibTypeFactory;
            // Signatures built from parsed names carry freshly-constructed type
            // references; importing them binds every reference into this module's
            // context so the resulting MemberRef/TypeSpec is resolvable (an
            // un-imported generic instance yields an unresolvable member token).
            var returnSig  = ParseTypeSig(ExtractReturnType(callee.MemberSig), module, corLib);
            var paramSigs  = callee.ParamTypes
                .Select(p => ParseTypeSig(p, module, corLib))
                .Where(s => s != null)
                .ToArray();

            if (callee.IsInstance)
                return MethodSignature.CreateInstance(returnSig, paramSigs);
            else
                return MethodSignature.CreateStatic(returnSig, paramSigs);
        }

        // Splits "A,B<C,D>,E" on top-level commas only, respecting <> nesting.
        private static List<string> SplitTopLevelCommas(string text)
        {
            var parts = new List<string>();
            int depth = 0, start = 0;
            for (int i = 0; i < text.Length; i++)
            {
                var c = text[i];
                if (c == '<' || c == '[') depth++;
                else if (c == '>' || c == ']') depth--;
                else if (c == ',' && depth == 0)
                {
                    parts.Add(text.Substring(start, i - start));
                    start = i + 1;
                }
            }
            if (start <= text.Length) parts.Add(text.Substring(start));
            return parts;
        }

        private static int IndexOfTopLevel(string text, char target)
        {
            int depth = 0;
            for (int i = 0; i < text.Length; i++)
            {
                var c = text[i];
                // Check for the target at the top level BEFORE adjusting depth, so a
                // depth-delimiter character (e.g. '<') can itself be found at depth 0.
                if (c == target && depth == 0) return i;
                if (c == '<' || c == '[') depth++;
                else if (c == '>' || c == ']') depth--;
            }
            return -1;
        }

        // Per-module cache of every generic-instance type signature already used in
        // the image (return/parameter/field/local types), keyed by full name. Reusing
        // one guarantees a signature blob the runtime already accepts.
        private static readonly System.Runtime.CompilerServices.ConditionalWeakTable<
            ModuleDefinition, Dictionary<string, TypeSignature>> GenericInstanceCache =
            new System.Runtime.CompilerServices.ConditionalWeakTable<
                ModuleDefinition, Dictionary<string, TypeSignature>>();

        private static TypeSignature FindExistingGenericInstance(ModuleDefinition module, string fullName)
        {
            var map = GenericInstanceCache.GetValue(module, m =>
            {
                var d = new Dictionary<string, TypeSignature>(StringComparer.Ordinal);
                void Consider(TypeSignature sig)
                {
                    if (sig is GenericInstanceTypeSignature gi && !d.ContainsKey(gi.FullName))
                        d[gi.FullName] = gi;
                }
                foreach (var t in m.GetAllTypes())
                {
                    foreach (var method in t.Methods)
                    {
                        var sig = method.Signature;
                        if (sig == null) continue;
                        Consider(sig.ReturnType);
                        foreach (var pt in sig.ParameterTypes) Consider(pt);
                    }
                    foreach (var f in t.Fields)
                        if (f.Signature != null) Consider(f.Signature.FieldType);
                }
                return d;
            });
            return map.TryGetValue(fullName, out var found) ? found : null;
        }

        // Parses the reflection assembly-qualified generic form
        // "Base`N[[Arg1, Asm, ...],[Arg2, Asm, ...]]" into the base name and the bare
        // argument type names (assembly info dropped; recursion re-resolves each).
        private static bool TryParseReflectionGeneric(string fullName, out string basePart, out List<string> args)
        {
            basePart = null; args = new List<string>();
            int bb = fullName.IndexOf("[[", StringComparison.Ordinal);
            if (bb <= 0 || !fullName.EndsWith("]", StringComparison.Ordinal)) return false;
            basePart = fullName.Substring(0, bb);
            if (basePart.IndexOf('`') < 0) return false;
            var content = fullName.Substring(bb + 1, fullName.Length - bb - 2);
            int depth = 0, start = -1;
            for (int i = 0; i < content.Length; i++)
            {
                char c = content[i];
                if (c == '[') { if (depth == 0) start = i + 1; depth++; }
                else if (c == ']') { depth--; if (depth == 0 && start >= 0)
                    {
                        var aqn = content.Substring(start, i - start);
                        int comma = IndexOfTopLevel(aqn, ',');
                        args.Add((comma < 0 ? aqn : aqn.Substring(0, comma)).Trim());
                        start = -1;
                    } }
            }
            return args.Count > 0;
        }

        private static TypeSignature ParseTypeSig(
            string fullName,
            ModuleDefinition module,
            CorLibTypeFactory corLib)
        {
            if (string.IsNullOrWhiteSpace(fullName)) return corLib.Object;

            fullName = fullName.Trim();

            bool isByRef = fullName.EndsWith("&");
            if (isByRef) fullName = fullName.Substring(0, fullName.Length - 1).TrimEnd();

            // Unmanaged pointer suffix.
            if (fullName.EndsWith("*"))
            {
                var pointee = ParseTypeSig(fullName.Substring(0, fullName.Length - 1), module, corLib);
                TypeSignature ptr = pointee != null ? new PointerTypeSignature(pointee) : (TypeSignature)corLib.Object;
                return isByRef ? new ByReferenceTypeSignature(ptr) : ptr;
            }

            // Strip array suffix and build SzArrayTypeSignature recursively.
            if (fullName.EndsWith("[]"))
            {
                var elem = ParseTypeSig(fullName.Substring(0, fullName.Length - 2), module, corLib);
                TypeSignature arr = elem != null ? new SzArrayTypeSignature(elem) : (TypeSignature)corLib.Object;
                return isByRef ? new ByReferenceTypeSignature(arr) : arr;
            }

            // Generic instantiation: "Base`N<Arg1,Arg2,...>". dnlib FullName uses <>.
            // Reconstruct a GenericInstanceTypeSignature over the open definition,
            // recursing on each argument, rather than emitting a literal type name.
            // Reflection assembly-qualified generic form (Base`N[[..],[..]]).
            if (TryParseReflectionGeneric(fullName, out var rBase, out var rArgs))
            {
                var reusedR = FindExistingGenericInstance(module, fullName);
                if (reusedR != null)
                    return isByRef ? new ByReferenceTypeSignature(reusedR) : reusedR;
                var rArgSigs = rArgs.Select(a => ParseTypeSig(a, module, corLib) ?? corLib.Object).ToArray();
                var rGenDef = ResolveOrBuildTypeRef(rBase, module);
                if (rGenDef != null)
                {
                    TypeSignature rgi;
                    try { rgi = rGenDef.MakeGenericInstanceType(rArgSigs); }
                    catch { rgi = new GenericInstanceTypeSignature(rGenDef, IsKnownValueType(rBase), rArgSigs); }
                    return isByRef ? new ByReferenceTypeSignature(rgi) : rgi;
                }
            }

            int lt = IndexOfTopLevel(fullName, '<');
            if (lt > 0 && fullName.EndsWith(">"))
            {
                // Prefer an identical generic instance already present in the module:
                // its signature blob was parsed from the original image and is
                // guaranteed CLR-valid, sidestepping any subtle mismatch in a
                // hand-built blob.
                var reused = FindExistingGenericInstance(module, fullName);
                if (reused != null)
                    return isByRef ? new ByReferenceTypeSignature(reused) : reused;

                var basePart = fullName.Substring(0, lt);
                var argsPart = fullName.Substring(lt + 1, fullName.Length - lt - 2);
                var argSigs = SplitTopLevelCommas(argsPart)
                    .Select(a => ParseTypeSig(a.Trim(), module, corLib) ?? corLib.Object)
                    .ToArray();
                var genDef = ResolveOrBuildTypeRef(basePart, module);
                if (genDef == null) return corLib.Object;
                TypeSignature gi;
                try { gi = genDef.MakeGenericInstanceType(argSigs); }
                catch { gi = new GenericInstanceTypeSignature(genDef, IsKnownValueType(basePart), argSigs); }
                return isByRef ? new ByReferenceTypeSignature(gi) : gi;
            }

            TypeSignature inner = fullName switch
            {
                "System.Void"    => corLib.Void,
                "System.Boolean" => corLib.Boolean,
                "System.Byte"    => corLib.Byte,
                "System.SByte"   => corLib.SByte,
                "System.Int16"   => corLib.Int16,
                "System.Int32"   => corLib.Int32,
                "System.Int64"   => corLib.Int64,
                "System.UInt16"  => corLib.UInt16,
                "System.UInt32"  => corLib.UInt32,
                "System.UInt64"  => corLib.UInt64,
                "System.Single"  => corLib.Single,
                "System.Double"  => corLib.Double,
                "System.Char"    => corLib.Char,
                "System.String"  => corLib.String,
                "System.Object"  => corLib.Object,
                "System.IntPtr"  => corLib.IntPtr,
                "System.UIntPtr" => corLib.UIntPtr,
                "System.TypedReference" => corLib.TypedReference,
                _ => BuildCustomTypeSig(fullName, module),
            };

            return isByRef && inner != null
                ? new ByReferenceTypeSignature(inner)
                : inner;
        }

        private static TypeSignature BuildCustomTypeSig(string fullName, ModuleDefinition module)
        {
            if (string.IsNullOrWhiteSpace(fullName)) return null;

            // Try to find an existing TypeReference in the module
            var existingRef = module.GetImportedTypeReferences()
                .FirstOrDefault(r => string.Equals(
                    r.FullName, fullName, StringComparison.Ordinal));

            if (existingRef != null)
                return new TypeDefOrRefSignature(existingRef);

            // Build a new TypeReference
            var scope  = FindOrAddAssemblyRef(fullName, module);
            var ns     = GetNamespace(fullName);
            var name   = GetTypeName(fullName);
            bool isValueType = IsKnownValueType(fullName);

            var typeRef = new TypeReference(module, scope, ns, name);
            return new TypeDefOrRefSignature(typeRef, isValueType);
        }

        // Builds an open-generic-definition type reference (name carries `N arity),
        // reusing the same scope logic as plain references. Kept separate so the
        // generic-instantiation path does not disturb the plain-reference path.
        private static ITypeDefOrRef ResolveOrBuildTypeRef(string fullName, ModuleDefinition module)
        {
            if (string.IsNullOrWhiteSpace(fullName)) return null;
            fullName = fullName.Trim();

            // Reuse an existing reference, but for a core-library type prefer the
            // core-library-scoped row over a facade (System) row that shares the name,
            // so a generic definition binds to mscorlib rather than System.
            var existingRefs = module.GetImportedTypeReferences()
                .Where(r => string.Equals(r.FullName, fullName, StringComparison.Ordinal))
                .ToList();
            if (existingRefs.Count > 0)
            {
                if (IsCoreLibraryNamespace(fullName))
                {
                    var corlibName = module.CorLibTypeFactory.CorLibScope?.Name;
                    var core = existingRefs.FirstOrDefault(r =>
                        string.Equals(r.Scope?.Name, corlibName, StringComparison.OrdinalIgnoreCase));
                    if (core != null) return core;
                    return new TypeReference(module, module.CorLibTypeFactory.CorLibScope,
                        GetNamespace(fullName), GetTypeName(fullName));
                }
                return existingRefs[0];
            }

            if (fullName.Contains("+"))
            {
                var parts = fullName.Split('+');
                var outerScope = FindOrAddAssemblyRef(parts[0], module);
                TypeReference current = new TypeReference(
                    module, outerScope, GetNamespace(parts[0]), GetTypeName(parts[0]));
                for (int p = 1; p < parts.Length; p++)
                    current = new TypeReference(module, current, string.Empty, parts[p]);
                return current;
            }

            var scope = FindOrAddAssemblyRef(fullName, module);
            return new TypeReference(module, scope, GetNamespace(fullName), GetTypeName(fullName));
        }

        // The assembly recorded at capture time is authoritative; the namespace table
        // below is only a fallback for evidence captured before that field existed.
        private static IResolutionScope ResolveScope(
            CalleeDescriptor callee,
            string typeName,
            ModuleDefinition module)
        {
            var declaring = callee?.DeclaringAssembly;
            if (!string.IsNullOrWhiteSpace(declaring))
            {
                if (string.Equals(declaring, module.Assembly?.Name, StringComparison.OrdinalIgnoreCase))
                    return module;
                if (string.Equals(declaring, module.CorLibTypeFactory.CorLibScope?.Name,
                        StringComparison.OrdinalIgnoreCase))
                    return module.CorLibTypeFactory.CorLibScope;
                return GetOrAddRef(module, declaring);
            }

            return FindOrAddAssemblyRef(typeName, module);
        }

        private static IResolutionScope FindOrAddAssemblyRef(string typeName, ModuleDefinition module)
        {
            var baseTypeName = (typeName ?? string.Empty).Split('/')[0];
            var corlib = module.CorLibTypeFactory.CorLibScope;

            // Authoritative: reuse the scope of a type the module already references.
            // When several rows share the full name (a type both in the core library
            // and forwarded through a facade), prefer the core-library-scoped one for
            // core-library types so a generic definition like IEnumerable`1 does not
            // pick up the System facade assembly.
            var existing = module.GetImportedTypeReferences()
                .Where(r => string.Equals(r.FullName, baseTypeName, StringComparison.Ordinal))
                .ToList();
            if (existing.Count > 0)
            {
                if (IsCoreLibraryNamespace(baseTypeName))
                {
                    var core = existing.FirstOrDefault(r =>
                        string.Equals(r.Scope?.Name, corlib?.Name, StringComparison.OrdinalIgnoreCase));
                    if (core?.Scope != null) return core.Scope;
                    return corlib;
                }
                if (existing[0].Scope != null) return existing[0].Scope;
            }

            // Core-library namespaces live in the core library (mscorlib on this
            // target), regardless of any same-prefixed facade assembly reference.
            if (IsCoreLibraryNamespace(baseTypeName))
                return corlib;

            if (baseTypeName.StartsWith("System.Windows.Forms", StringComparison.Ordinal))
                return GetOrAddRef(module, "System.Windows.Forms");
            if (baseTypeName.StartsWith("System.Drawing", StringComparison.Ordinal))
                return GetOrAddRef(module, "System.Drawing");
            if (baseTypeName.StartsWith("System.Management", StringComparison.Ordinal))
                return GetOrAddRef(module, "System.Management");

            // Match a dotted (sub-namespace) assembly whose name is the longest
            // namespace prefix of the type - e.g. System.Xml.Linq.XElement -> the
            // System.Xml.Linq assembly. The bare "System"/"mscorlib" assemblies are
            // excluded here because their namespace ownership overlaps the core lib.
            var byNamespace = module.AssemblyReferences
                .Where(r => !string.IsNullOrEmpty(r.Name) && r.Name.Contains(".") &&
                            !string.Equals(r.Name, corlib?.Name, StringComparison.OrdinalIgnoreCase) &&
                            (baseTypeName + ".").StartsWith(r.Name + ".", StringComparison.Ordinal))
                .OrderByDescending(r => r.Name.Length)
                .FirstOrDefault();
            if (byNamespace != null)
                return byNamespace;
            return corlib;
        }

        // Namespaces whose types reside in the core library on this target framework
        // (mscorlib for .NET Framework). Kept as prefixes, not a per-type table.
        private static bool IsCoreLibraryNamespace(string fullName)
        {
            if (string.IsNullOrEmpty(fullName)) return false;
            string[] coreNs =
            {
                "System.Collections.Generic.", "System.Collections.ObjectModel.",
                "System.Collections.", "System.Text.", "System.IO.",
                "System.Threading.", "System.Reflection.", "System.Globalization.",
                "System.Runtime.", "System.Security.", "System.Diagnostics.",
            };
            foreach (var ns in coreNs)
                if (fullName.StartsWith(ns, StringComparison.Ordinal)) return true;
            // Bare System.<Type> (no further dots) is core-library too (Object, Uri…).
            var rest = fullName.StartsWith("System.", StringComparison.Ordinal)
                ? fullName.Substring("System.".Length) : null;
            return rest != null && !rest.Contains(".") && !rest.Contains("`") == false
                ? false
                : rest != null && !rest.Contains(".");
        }

        private static AssemblyReference GetOrAddRef(ModuleDefinition module, string name)
        {
            var existing = module.AssemblyReferences
                .FirstOrDefault(r => string.Equals(r.Name, name, StringComparison.OrdinalIgnoreCase));
            if (existing != null) return existing;

            var newRef = new AssemblyReference(name, new Version(4, 0, 0, 0));
            module.AssemblyReferences.Add(newRef);
            return newRef;
        }

        private static string GetNamespace(string fullName)
        {
            // Handle nested types: "System.Windows.Forms.Control/ControlCollection" → "System.Windows.Forms"
            string flat = fullName.Contains('/') ? fullName.Split('/')[0] : fullName;
            int dot = flat.LastIndexOf('.');
            return dot < 0 ? string.Empty : flat.Substring(0, dot);
        }

        private static string GetTypeName(string fullName)
        {
            string flat = fullName.Contains('/') ? fullName.Split('/')[0] : fullName;
            int dot = flat.LastIndexOf('.');
            return dot < 0 ? flat : flat.Substring(dot + 1);
        }

        private static string ExtractReturnType(string sig)
        {
            // sig: "instance void (System.String)"  or "void ()"
            // We want the word after "instance" (if present) up to the first "("
            if (string.IsNullOrWhiteSpace(sig)) return "System.Void";
            sig = sig.TrimStart();
            if (sig.StartsWith("instance ")) sig = sig.Substring(9);
            int paren = IndexOfTopLevel(sig, '(');
            return paren < 0 ? sig.Trim() : sig.Substring(0, paren).Trim();
        }

        private static bool IsKnownValueType(string fullName) =>
            fullName == "System.Drawing.Size"  ||
            fullName == "System.Drawing.SizeF" ||
            fullName == "System.Drawing.Point" ||
            fullName == "System.Drawing.Rectangle" ||
            fullName == "System.Windows.Forms.FormBorderStyle" ||
            fullName == "System.Windows.Forms.FormStartPosition" ||
            fullName == "System.Windows.Forms.AutoScaleMode" ||
            fullName == "System.Windows.Forms.AnchorStyles";
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Data model
    // ──────────────────────────────────────────────────────────────────────────

    internal sealed class HiddenCallSiteResult
    {
        public string Caller { get; set; }
        public int IlOffset { get; set; }
        public string DelegateField { get; set; }
        public string Pattern { get; set; }
        public string CapturedTarget { get; set; }
        public bool SignatureCompatible { get; set; }
        public string DirectReplacement { get; set; }
        public bool Rewrite { get; set; }
    }

    internal sealed class CalleeDescriptor
    {
        public string       Opcode        { get; set; }
        public string       DeclaringType { get; set; }
        public string       MethodName    { get; set; }
        public string       MemberSig     { get; set; }
        public string       DeclaringAssembly { get; set; }
        public List<string> ParamTypes    { get; set; } = new List<string>();
        public bool         IsInstance    { get; set; }
        public bool         IsGenericMethod    { get; set; }
        public List<string> MethodGenericArgs  { get; set; } = new List<string>();
    }
}
