using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Reflection.Emit;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace Krypton.Runner
{
    /// <summary>
    /// Loads the target protected assembly into the current AppDomain,
    /// triggers its bootstrap initialization, and enumerates all delegates
    /// that wrap DynamicMethods so their IL can be captured.
    /// </summary>
    internal sealed class AssemblyRunner
    {
        private readonly string _assemblyPath;
        private readonly bool _traceCctors;
        private readonly int[] _traceMethodTokens;

        // .NET Framework 4.x internal fields for reading DynamicMethod IL
        private static readonly Type DynamicMethodType = typeof(DynamicMethod);
        private static readonly FieldInfo F_mDynamicILInfo =
            DynamicMethodType.GetField("m_DynamicILInfo", BindingFlags.Instance | BindingFlags.NonPublic);
        private static readonly FieldInfo F_mResolver =
            DynamicMethodType.GetField("m_resolver", BindingFlags.Instance | BindingFlags.NonPublic);

        public AssemblyRunner(string assemblyPath)
        {
            _assemblyPath = assemblyPath;
            _traceCctors = IsEnabled(Environment.GetEnvironmentVariable("KRYPTON_RUNNER_TRACE_CCTORS"));
            _traceMethodTokens = ReadTraceMethodTokens();
        }

        /// <summary>
        /// Loads the assembly, triggers initialization, captures all DynamicMethod
        /// delegates found in static fields, and returns the serialized dump.
        /// </summary>
        public DynamicDump Run()
        {
            Console.WriteLine($"[Runner] Loading: {_assemblyPath}");

            // Resolve assembly dependencies from the same directory
            var baseDir = Path.GetDirectoryName(_assemblyPath);
            AppDomain.CurrentDomain.AssemblyResolve += (s, e) =>
            {
                var simpleName = new AssemblyName(e.Name).Name;
                var candidate  = Path.Combine(baseDir, simpleName + ".dll");
                if (File.Exists(candidate))
                    return Assembly.LoadFrom(candidate);
                candidate = Path.Combine(baseDir, simpleName + ".exe");
                if (File.Exists(candidate))
                    return Assembly.LoadFrom(candidate);
                return null;
            };

            // Load as bytes so we can suppress SecurityException on partially-trusted assemblies
            // and to avoid locking the file on disk.
            byte[] rawBytes = File.ReadAllBytes(_assemblyPath);
            Assembly runtimeAssembly;
            try
            {
                runtimeAssembly = Assembly.Load(rawBytes);
            }
            catch (BadImageFormatException)
            {
                // Some NET Reactor versions produce assemblies that need LoadFrom
                runtimeAssembly = Assembly.LoadFrom(_assemblyPath);
            }

            Console.WriteLine($"[Runner] Loaded: {runtimeAssembly.FullName}");

            // Also load via dnlib for token resolution context
            var dnlibModule = ModuleDefMD.Load(_assemblyPath, new ModuleCreationOptions
            {
                TryToLoadPdbFromDisk = false,
            });

            // A DynamicMethod's operands often come back without a named scope, and
            // the only reliable way to say which assembly declares such a type is to
            // ask the assemblies themselves. The target lists what it references, so
            // load those first: without them the probe searches a domain that does
            // not yet contain the declaring assembly and the consumer is left to
            // guess a scope from the namespace.
            LoadReferencedAssemblies(runtimeAssembly);

            // Trigger bootstrap: access all types which fires their .cctor
            TriggerInitialization(runtimeAssembly, _traceCctors, _traceMethodTokens);

            // Now enumerate delegates across all types
            var dump = new DynamicDump
            {
                AssemblyPath   = _assemblyPath,
                CapturedAt     = DateTime.UtcNow.ToString("o"),
                RuntimeVersion = Environment.Version.ToString(),
            };

            EnumerateDynamicMethods(runtimeAssembly, dnlibModule, dump.Methods);
            Console.WriteLine($"[Runner] Captured {dump.Methods.Count} DynamicMethod(s).");
            if (_traceCctors)
                TraceDynamicMethodSummary(dump.Methods);
            return dump;
        }

        private static void LoadReferencedAssemblies(Assembly assembly)
        {
            var loaded = 0;
            var failed = 0;
            foreach (var reference in assembly.GetReferencedAssemblies())
            {
                try
                {
                    Assembly.Load(reference);
                    loaded++;
                }
                catch
                {
                    failed++;
                }
            }

            Console.WriteLine($"[Runner] Referenced assemblies loaded: {loaded} ({failed} unavailable).");
        }

        // ──────────────────────────────────────────────────────────────
        // Bootstrap triggering
        // ──────────────────────────────────────────────────────────────

        private static void TriggerInitialization(Assembly assembly, bool traceCctors, int[] traceMethodTokens)
        {
            Console.WriteLine("[Runner] Triggering assembly initialization...");

            Type[] types;
            try
            {
                types = assembly.GetTypes();
            }
            catch (ReflectionTypeLoadException ex)
            {
                // Partial load — use what we have
                types = ex.Types;
            }

            var initializedTypes = traceCctors ? new List<Type>() : null;
            var watchedMethodStates = traceCctors ? new Dictionary<int, string>() : null;
            if (traceCctors)
            {
                Console.WriteLine("[Trace] .cctor tracing enabled.");
                TraceWatchedMethods(assembly, traceMethodTokens, watchedMethodStates, "initial", true);
            }

            foreach (var t in types)
            {
                if (t == null) continue;
                var beforeDynamicDelegates = traceCctors ? CountDynamicDelegates(initializedTypes) : 0;
                var stopwatch = traceCctors ? Stopwatch.StartNew() : null;
                var status = "OK";
                string error = null;
                try
                {
                    // Accessing static fields triggers the type's .cctor
                    System.Runtime.CompilerServices.RuntimeHelpers.RunClassConstructor(t.TypeHandle);
                    if (traceCctors)
                        initializedTypes.Add(t);
                }
                catch (TypeInitializationException tie)
                {
                    // Bootstrap might call Application.Run or similar — ignore
                    status = "FAIL";
                    error = tie.InnerException == null
                        ? tie.GetType().Name
                        : tie.InnerException.GetType().Name;
                    if (!traceCctors)
                        Console.WriteLine($"[Runner]   Init exception on {t.FullName}: {tie.InnerException?.GetType().Name}");
                }
                catch (Exception ex)
                {
                    status = "FAIL";
                    error = ex.GetType().Name;
                    if (!traceCctors)
                        Console.WriteLine($"[Runner]   Init exception on {t.FullName}: {ex.GetType().Name}");
                }

                if (traceCctors)
                {
                    stopwatch.Stop();
                    var afterDynamicDelegates = CountDynamicDelegates(initializedTypes);
                    var delta = afterDynamicDelegates - beforeDynamicDelegates;
                    Console.WriteLine(
                        $"[Trace] cctor {status,-4} {SafeMetadataToken(t)} {t.FullName} " +
                        $"{stopwatch.ElapsedMilliseconds}ms dyn={beforeDynamicDelegates}->{afterDynamicDelegates} ({delta:+#;-#;0})" +
                        (error == null ? string.Empty : $" err={error}"));
                    TraceWatchedMethods(assembly, traceMethodTokens, watchedMethodStates, "after " + t.FullName, false);
                }
            }

            Console.WriteLine("[Runner] Initialization complete.");
        }

        // ──────────────────────────────────────────────────────────────
        // DynamicMethod enumeration
        // ──────────────────────────────────────────────────────────────

        private void EnumerateDynamicMethods(
            Assembly runtimeAssembly,
            ModuleDef dnlibModule,
            List<DynamicMethodEntry> results)
        {
            Type[] types;
            try { types = runtimeAssembly.GetTypes(); }
            catch (ReflectionTypeLoadException e) { types = e.Types; }

            foreach (var type in types)
            {
                if (type == null) continue;

                var fields = type.GetFields(
                    BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic);

                foreach (var field in fields)
                {
                    try
                    {
                        object value = field.GetValue(null);
                        if (value == null) continue;

                        // Use metadata token as primary key — it's stable, unique, and
                        // NET Reactor itself uses field tokens for its dispatch dictionary.
                        // Fallback to type::name for fields with readable names.
                        string tokenKey = $"0x{field.MetadataToken:X8}";
                        string namedKey = string.IsNullOrEmpty(type.FullName) && string.IsNullOrEmpty(field.Name)
                            ? tokenKey
                            : $"{type.FullName}::{field.Name}";
                        string fieldKey = namedKey == tokenKey ? tokenKey : $"{namedKey}|{tokenKey}";

                        if (value is Delegate singleDelegate)
                        {
                            if (IsDynamicDelegate(singleDelegate))
                                TryCapture(singleDelegate, fieldKey, -1, dnlibModule, results);
                            else
                                TryCaptureDirect(singleDelegate, fieldKey, -1, results);
                        }
                        else if (value.GetType().IsArray)
                        {
                            var arr = (Array)value;
                            for (int i = 0; i < arr.Length; i++)
                            {
                                var elem = arr.GetValue(i);
                                if (elem is Delegate d)
                                {
                                    var indexedKey = $"{fieldKey}[{i}]";
                                    if (IsDynamicDelegate(d))
                                        TryCapture(d, indexedKey, i, dnlibModule, results);
                                    else
                                        TryCaptureDirect(d, indexedKey, i, results);
                                }
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"[Runner]   Field read error {type.FullName}::{field.Name}: {ex.GetType().Name}");
                    }
                }
            }
        }

        private static void TryCapture(
            Delegate d,
            string fieldKey,
            int index,
            ModuleDef dnlibModule,
            List<DynamicMethodEntry> results)
        {
            var mi = d.Method;
            if (mi == null) return;

            // NET Reactor's delegates wrap a DynamicMethod, but d.Method returns the
            // internal RTDynamicMethod class, not DynamicMethod itself.
            bool isDynamic = mi is DynamicMethod
                          || mi.GetType().Name == "RTDynamicMethod";
            if (!isDynamic) return;

            // Extract the actual DynamicMethod to read parameter info.
            var dm = ExtractDynamicMethod(mi);
            if (dm == null) return;

            try
            {
                // Pass the Delegate to dnlib — DynamicMethodBodyReader handles
                // RTDynamicMethod → DynamicMethod resolution internally.
                var reader = new DynamicMethodBodyReader(dnlibModule, d);
                reader.Read();
                var methodDef = reader.GetMethod();
                if (methodDef == null) return;

                var entry = DynamicMethodSerializer.Serialize(dm, methodDef, fieldKey, index);
                results.Add(entry);

                string label = index >= 0 ? $"{fieldKey}[{index}]" : fieldKey;
                Console.WriteLine($"[Runner]   Captured: {label} ({entry.Instructions.Count} instructions)");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[Runner]   Failed to read {fieldKey}[{index}]: {ex.Message}");
            }
        }

        // Some Reactor wrapper fields are delegates bound directly to framework
        // methods rather than DynamicMethods (e.g. String.Concat and
        // String.IsNullOrEmpty). Preserve those runtime targets in the same
        // evidence stream so HiddenCallRecovery can rewrite them without guesses.
        private static void TryCaptureDirect(
            Delegate d,
            string fieldKey,
            int index,
            List<DynamicMethodEntry> results)
        {
            var method = d == null ? null : d.Method;
            if (method == null) return;

            var entry = new DynamicMethodEntry
            {
                SourceField = fieldKey,
                SourceIndex = index,
                ReturnType = DynamicMethodSerializer.GetTypeName(method.ReturnType),
                MaxStack = 8,
                InitLocals = true
            };

            foreach (var p in method.GetParameters())
                entry.ParameterTypes.Add(DynamicMethodSerializer.GetTypeName(p.ParameterType));

            var parameters = method.GetParameters();
            var signature = new System.Text.StringBuilder();
            if (!method.IsStatic) signature.Append("instance ");
            signature.Append(DynamicMethodSerializer.GetTypeName(method.ReturnType));
            signature.Append(" (");
            var paramEntries = new List<ParamEntry>();
            for (var i = 0; i < parameters.Length; i++)
            {
                if (i != 0) signature.Append(", ");
                var p = parameters[i];
                var byRef = p.ParameterType.IsByRef;
                var type = DynamicMethodSerializer.GetTypeName(
                    byRef ? p.ParameterType.GetElementType() : p.ParameterType);
                signature.Append(byRef ? type + "&" : type);
                paramEntries.Add(new ParamEntry { Type = type, IsByRef = byRef });
            }
            signature.Append(")");

            entry.Instructions.Add(new InstructionEntry
            {
                Offset = 0,
                Opcode = method.IsStatic ? "call" : "callvirt",
                OperandKind = "method",
                DeclType = method.DeclaringType == null ? null : method.DeclaringType.FullName,
                // The runtime target is right here, so the assembly that declares it
                // is known exactly. Recording it keeps the consumer from having to
                // infer a scope from the namespace, which is wrong for every type
                // whose namespace does not match its assembly.
                DeclAssembly = method.DeclaringType == null
                    ? null
                    : method.DeclaringType.Assembly.GetName().Name,
                MemberName = method.Name,
                MemberSig = signature.ToString(),
                Params = paramEntries
            });
            results.Add(entry);
            Console.WriteLine("[Runner]   Captured direct delegate: " + fieldKey +
                              " -> " + method.DeclaringType + "::" + method.Name);
        }

        /// <summary>
        /// Extracts the underlying DynamicMethod from either a DynamicMethod or an
        /// RTDynamicMethod (internal .NET Framework wrapper).
        /// </summary>
        private static DynamicMethod ExtractDynamicMethod(MethodInfo mi)
        {
            if (mi is DynamicMethod dm) return dm;

            // RTDynamicMethod.m_owner → DynamicMethod
            var ownerField = mi.GetType()
                .GetField("m_owner", BindingFlags.Instance | BindingFlags.NonPublic);
            return ownerField?.GetValue(mi) as DynamicMethod;
        }

        private static bool IsEnabled(string value)
        {
            if (string.IsNullOrWhiteSpace(value))
                return false;

            value = value.Trim();
            return string.Equals(value, "1", StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(value, "true", StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(value, "yes", StringComparison.OrdinalIgnoreCase);
        }

        private static int[] ReadTraceMethodTokens()
        {
            var raw = Environment.GetEnvironmentVariable("KRYPTON_RUNNER_TRACE_METHODS");
            if (string.IsNullOrWhiteSpace(raw))
                raw = Environment.GetEnvironmentVariable("KRYPTON_RUNNER_TRACE_METHOD");
            if (string.IsNullOrWhiteSpace(raw))
                return new int[0];

            var tokens = new List<int>();
            foreach (var part in raw.Split(new[] { ',', ';', ' ' }, StringSplitOptions.RemoveEmptyEntries))
            {
                if (TryParseMetadataToken(part.Trim(), out var token))
                    tokens.Add(token);
            }

            return tokens.ToArray();
        }

        private static bool TryParseMetadataToken(string value, out int token)
        {
            token = 0;
            if (string.IsNullOrWhiteSpace(value))
                return false;

            value = value.Trim();
            if (value.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                return int.TryParse(
                    value.Substring(2),
                    System.Globalization.NumberStyles.HexNumber,
                    System.Globalization.CultureInfo.InvariantCulture,
                    out token);

            return int.TryParse(
                value,
                System.Globalization.NumberStyles.Integer,
                System.Globalization.CultureInfo.InvariantCulture,
                out token);
        }

        private static void TraceWatchedMethods(
            Assembly assembly,
            int[] tokens,
            Dictionary<int, string> states,
            string reason,
            bool force)
        {
            if (tokens == null || tokens.Length == 0 || states == null)
                return;

            foreach (var token in tokens)
            {
                var state = DescribeMethodBody(assembly, token);
                string previous;
                if (!states.TryGetValue(token, out previous) || force || !string.Equals(previous, state, StringComparison.Ordinal))
                {
                    states[token] = state;
                    Console.WriteLine($"[Trace] method {reason}: {state}");
                }
            }
        }

        private static string DescribeMethodBody(Assembly assembly, int token)
        {
            try
            {
                var method = assembly.ManifestModule.ResolveMethod(token);
                var body = method.GetMethodBody();
                var il = body?.GetILAsByteArray();
                var name = method.DeclaringType == null
                    ? method.Name
                    : method.DeclaringType.FullName + "::" + method.Name;

                if (body == null || il == null)
                    return $"0x{token:X8} {name} il=<none>";

                return string.Format(
                    "0x{0:X8} {1} il={2} maxStack={3} locals={4} bytes={5}",
                    token,
                    name,
                    il.Length,
                    body.MaxStackSize,
                    body.LocalVariables.Count,
                    FormatIlBytes(il, 32));
            }
            catch (Exception ex)
            {
                return $"0x{token:X8} <resolve failed: {ex.GetType().Name}>";
            }
        }

        private static string FormatIlBytes(byte[] il, int maxBytes)
        {
            if (il == null || il.Length == 0)
                return string.Empty;

            var count = Math.Min(il.Length, maxBytes);
            var parts = new string[count];
            for (var i = 0; i < count; i++)
                parts[i] = il[i].ToString("X2");

            var formatted = string.Join("-", parts);
            if (il.Length > maxBytes)
                formatted += "...";
            return formatted;
        }

        private static int CountDynamicDelegates(List<Type> initializedTypes)
        {
            if (initializedTypes == null || initializedTypes.Count == 0)
                return 0;

            var count = 0;
            foreach (var type in initializedTypes)
            {
                if (type == null)
                    continue;

                FieldInfo[] fields;
                try
                {
                    fields = type.GetFields(BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic);
                }
                catch
                {
                    continue;
                }

                foreach (var field in fields)
                {
                    object value;
                    try
                    {
                        value = field.GetValue(null);
                    }
                    catch
                    {
                        continue;
                    }

                    if (value is Delegate singleDelegate)
                    {
                        if (IsDynamicDelegate(singleDelegate))
                            count++;
                    }
                    else if (value is Array arr)
                    {
                        foreach (var item in arr)
                        {
                            if (item is Delegate delegateItem && IsDynamicDelegate(delegateItem))
                                count++;
                        }
                    }
                }
            }

            return count;
        }

        private static bool IsDynamicDelegate(Delegate d)
        {
            var mi = d?.Method;
            return mi is DynamicMethod || string.Equals(mi?.GetType().Name, "RTDynamicMethod", StringComparison.Ordinal);
        }

        private static string SafeMetadataToken(Type type)
        {
            try
            {
                return $"0x{type.MetadataToken:X8}";
            }
            catch
            {
                return "0x????????";
            }
        }

        private static void TraceDynamicMethodSummary(List<DynamicMethodEntry> methods)
        {
            if (methods == null || methods.Count == 0)
                return;

            var printed = 0;
            Console.WriteLine("[Trace] Dynamic WinForms/Form delegates:");
            foreach (var method in methods)
            {
                if (!IsWinFormsOrFormDynamicMethod(method))
                    continue;

                printed++;
                Console.WriteLine($"[Trace]   {method.SourceField} -> {SummarizeDynamicCalls(method, 6)}");
                if (printed >= 80)
                {
                    Console.WriteLine("[Trace]   ... truncated ...");
                    break;
                }
            }

            if (printed == 0)
                Console.WriteLine("[Trace]   <none>");
        }

        private static bool IsWinFormsOrFormDynamicMethod(DynamicMethodEntry method)
        {
            if (method?.Instructions == null)
                return false;

            foreach (var instruction in method.Instructions)
            {
                if (!string.Equals(instruction.OperandKind, "method", StringComparison.Ordinal) &&
                    !string.Equals(instruction.OperandKind, "field", StringComparison.Ordinal) &&
                    !string.Equals(instruction.OperandKind, "type", StringComparison.Ordinal))
                {
                    continue;
                }

                var declType = instruction.DeclType ?? string.Empty;
                var memberName = instruction.MemberName ?? string.Empty;
                if (declType.StartsWith("System.Windows.Forms.", StringComparison.Ordinal) ||
                    declType.IndexOf(".Form", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    string.Equals(memberName, ".ctor", StringComparison.Ordinal) ||
                    memberName.StartsWith("set_", StringComparison.Ordinal) ||
                    memberName.StartsWith("add_", StringComparison.Ordinal))
                {
                    return true;
                }
            }

            return false;
        }

        private static string SummarizeDynamicCalls(DynamicMethodEntry method, int maxItems)
        {
            if (method?.Instructions == null)
                return "<empty>";

            var seen = new HashSet<string>(StringComparer.Ordinal);
            var items = new List<string>();
            foreach (var instruction in method.Instructions)
            {
                if (!string.Equals(instruction.OperandKind, "method", StringComparison.Ordinal))
                    continue;

                var declType = instruction.DeclType ?? "?";
                var memberName = instruction.MemberName ?? "?";
                var identity = declType + "::" + memberName;
                if (!seen.Add(identity))
                    continue;

                items.Add(identity);
                if (items.Count >= maxItems)
                    break;
            }

            return items.Count == 0 ? "<no method calls>" : string.Join(", ", items.ToArray());
        }
    }
}
