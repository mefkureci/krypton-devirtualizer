using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.Serialization;
using HarmonyLib;
using Newtonsoft.Json;

namespace Krypton.Runner
{
    /// <summary>
    /// Observes one invocation of a single virtualized method and records, in one
    /// ordered event list, everything the managed layer can see the VM do.
    ///
    /// The VM's own methods are NecroBit stubs in the file, so nothing inside the
    /// interpreter can be patched. What is observable is the boundary: the byte
    /// fetches from the bytecode stream (BinaryReader) and every framework call
    /// the interpreter makes. The point of this runner is to establish, factually,
    /// whether the *execution* phase crosses that boundary at all — the decode
    /// phase demonstrably does.
    ///
    /// Nothing here interprets opcodes or assigns CLR names. It records observed
    /// state only.
    /// </summary>
    internal static class VmExecTraceRunner
    {
        private sealed class VmEvent
        {
            public int Seq;
            public string Phase;
            public string Kind;
            public string Detail;
            public long Offset = -1;
            public int Value = -1;
            public int DepthBefore = -1;
            public bool VmOrigin;
            public string VmFrame;
            public string Result;
            public string Caller;
        }

        private static Harmony _harmony;
        private static readonly object Sync = new object();

        [ThreadStatic] private static bool _inHook;
        [ThreadStatic] private static Dictionary<string, List<int>> _pendingByKind;

        private static readonly HashSet<string> KindsWithResult = new HashSet<string>(
            new[]
            {
                "Module.ResolveMethod", "Module.ResolveField", "Module.ResolveType", "Module.ResolveMember",
                "MethodBase.Invoke", "ConstructorInfo.Invoke", "Activator.CreateInstance",
                "Array.CreateInstance", "RtFieldInfo.GetValue"
            },
            StringComparer.Ordinal);
        private static bool _active;
        private static string _phase = "pre-invoke";

        private static VmEvent[] _events;
        private static int _eventCount;
        private static int _maxEvents = 400000;

        private static long _streamLength = 46615;
        private static long _recordStart = 0x15FD;
        private static long _recordEnd = 0x186C;
        private static int _opcodeFetches;
        private static Assembly _targetAssembly;
        private static int _stage = 1;

        private static readonly Dictionary<string, int> ChainBudget =
            new Dictionary<string, int>(StringComparer.Ordinal);

        public static int Run(string targetPath, string outputPath)
        {
            if (!File.Exists(targetPath))
            {
                Console.Error.WriteLine("[VmExec] File not found: " + targetPath);
                return 1;
            }

            ReadOptions();
            _events = new VmEvent[_maxEvents];

            var token = ReadTokenOption();
            Console.WriteLine("[VmExec] stage=" + _stage +
                              " token=0x" + token.ToString("X8") +
                              " record=0x" + _recordStart.ToString("X") +
                              "..0x" + _recordEnd.ToString("X") +
                              " streamLength=" + _streamLength);

            try
            {
                InstallPatches();
                ExitGuard.Install();
                ExitGuard.Behavior = ExitGuardBehavior.Suppress;

                var assembly = LoadTarget(targetPath);
                _targetAssembly = assembly;
                Console.WriteLine("[VmExec] Loaded: " + assembly.FullName);
                TriggerInitialization(assembly);
                InstallStubs(assembly);
                ApplyFieldPresets(assembly);

                // An exception a method catches itself never reaches the invoke result,
                // so the throwing instruction is invisible from the outside. First-chance
                // notification records it as it is raised.
                if (string.Equals(Environment.GetEnvironmentVariable("KRYPTON_VM_TRACE_FIRSTCHANCE"), "1",
                        StringComparison.Ordinal))
                {
                    AppDomain.CurrentDomain.FirstChanceException += (sender, e) =>
                    {
                        if (_inHook || !_active)
                            return;
                        _inHook = true;
                        try
                        {
                            var frames = new StackTrace(e.Exception, true);
                            var located = new List<string>();
                            for (var i = 0; i < frames.FrameCount && i < 4; i++)
                            {
                                var frame = frames.GetFrame(i);
                                var m = frame.GetMethod();
                                var offset = frame.GetILOffset();
                                located.Add((m?.DeclaringType?.FullName ?? "?") + "::" + (m?.Name ?? "?") +
                                            (offset == StackFrame.OFFSET_UNKNOWN ? " IL_?" : " IL_" + offset.ToString("X4")));
                            }
                            Record("first-chance",
                                e.Exception.GetType().FullName + ": " + e.Exception.Message + " | " +
                                string.Join(" | ", located), -1, -1, -1, false);
                        }
                        catch
                        {
                        }
                        finally
                        {
                            _inHook = false;
                        }
                    };
                }
                if (_stage >= 4)
                    InstallThunkPatches(assembly);

                string invokeOutcome = null;
                if (string.Equals(Environment.GetEnvironmentVariable("KRYPTON_VM_TRACE_STA"), "1",
                        StringComparison.Ordinal))
                {
                    // WPF types refuse to initialize off an STA thread, so event
                    // handlers have to be invoked on one.
                    var worker = new System.Threading.Thread(
                        () => { invokeOutcome = InvokeFocused(assembly, token); }, 16 * 1024 * 1024);
                    worker.SetApartmentState(System.Threading.ApartmentState.STA);
                    worker.IsBackground = true;
                    worker.Start();
                    if (!worker.Join(TimeSpan.FromMinutes(3)))
                        invokeOutcome = "timed out on STA thread";
                }
                else
                {
                    invokeOutcome = InvokeFocused(assembly, token);
                }

                var dump = new
                {
                    AssemblyPath = Path.GetFullPath(targetPath),
                    CapturedAt = DateTime.UtcNow.ToString("o"),
                    RuntimeVersion = Environment.Version.ToString(),
                    MethodToken = "0x" + token.ToString("X8"),
                    Stage = _stage,
                    RecordStart = _recordStart,
                    RecordEnd = _recordEnd,
                    OpcodeFetchCandidates = _opcodeFetches,
                    InvokeOutcome = invokeOutcome,
                    EventCount = _eventCount,
                    Events = Take()
                };

                File.WriteAllText(
                    outputPath,
                    JsonConvert.SerializeObject(dump, Formatting.Indented),
                    System.Text.Encoding.UTF8);

                Console.WriteLine("[VmExec] Wrote: " + outputPath);
                Console.WriteLine("[VmExec] Events: " + _eventCount);
                Console.WriteLine("[VmExec] Invoke outcome: " + invokeOutcome);
                Summarize();
                return 0;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("[VmExec] Fatal: " + ex);
                return 2;
            }
            finally
            {
                if (_harmony != null)
                {
                    try { _harmony.UnpatchAll("krypton.runner.vmexec"); }
                    catch { }
                }
            }
        }

        private static VmEvent[] Take()
        {
            var copy = new VmEvent[_eventCount];
            Array.Copy(_events, copy, _eventCount);
            return copy;
        }

        private static void Summarize()
        {
            var byPhaseKind = new Dictionary<string, int>(StringComparer.Ordinal);
            for (var i = 0; i < _eventCount; i++)
            {
                var key = _events[i].Phase + " | " + _events[i].Kind;
                int current;
                byPhaseKind.TryGetValue(key, out current);
                byPhaseKind[key] = current + 1;
            }

            Console.WriteLine("[VmExec] --- observed events by phase ---");
            foreach (var pair in byPhaseKind.OrderBy(p => p.Key, StringComparer.Ordinal))
                Console.WriteLine("[VmExec]   " + pair.Value.ToString().PadLeft(7) + "  " + pair.Key);
        }

        private static void ReadOptions()
        {
            int intValue;
            long longValue;
            if (int.TryParse(Environment.GetEnvironmentVariable("KRYPTON_VM_TRACE_STAGE"), out intValue))
                _stage = intValue;
            if (int.TryParse(Environment.GetEnvironmentVariable("KRYPTON_VM_TRACE_MAX_EVENTS"), out intValue) && intValue > 0)
                _maxEvents = intValue;
            if (long.TryParse(Environment.GetEnvironmentVariable("KRYPTON_VM_TRACE_STREAM_LENGTH"), out longValue))
                _streamLength = longValue;
            _recordStart = ReadHexOption("KRYPTON_VM_TRACE_RECORD_START", _recordStart);
            _recordEnd = ReadHexOption("KRYPTON_VM_TRACE_RECORD_END", _recordEnd);
        }

        private static long ReadHexOption(string name, long fallback)
        {
            var raw = Environment.GetEnvironmentVariable(name);
            if (string.IsNullOrWhiteSpace(raw))
                return fallback;
            raw = raw.Trim();
            if (raw.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                raw = raw.Substring(2);
            long parsed;
            return long.TryParse(raw, System.Globalization.NumberStyles.HexNumber, null, out parsed)
                ? parsed
                : fallback;
        }

        private static int ReadTokenOption()
        {
            var raw = Environment.GetEnvironmentVariable("KRYPTON_VM_TRACE_TOKEN");
            if (string.IsNullOrWhiteSpace(raw))
                return 0x060003A9;
            raw = raw.Trim();
            if (raw.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                raw = raw.Substring(2);
            int parsed;
            return int.TryParse(raw, System.Globalization.NumberStyles.HexNumber, null, out parsed)
                ? parsed
                : 0x060003A9;
        }

        private static Assembly LoadTarget(string targetPath)
        {
            var baseDir = Path.GetDirectoryName(Path.GetFullPath(targetPath));
            AppDomain.CurrentDomain.AssemblyResolve += (s, e) =>
            {
                var simpleName = new AssemblyName(e.Name).Name;
                var candidate = Path.Combine(baseDir, simpleName + ".dll");
                if (File.Exists(candidate))
                    return Assembly.LoadFrom(candidate);
                candidate = Path.Combine(baseDir, simpleName + ".exe");
                if (File.Exists(candidate))
                    return Assembly.LoadFrom(candidate);
                return null;
            };

            // Loading from bytes keeps the file unlocked, but it also leaves
            // Assembly.Location empty, and a method that branches on its own
            // location then never reaches its main path. KRYPTON_VM_TRACE_LOADFROM
            // selects the file-backed load so that path can be exercised; the
            // default is unchanged so earlier captures stay comparable.
            if (string.Equals(Environment.GetEnvironmentVariable("KRYPTON_VM_TRACE_LOADFROM"), "1",
                    StringComparison.Ordinal))
            {
                return Assembly.LoadFrom(targetPath);
            }

            try
            {
                return Assembly.Load(File.ReadAllBytes(targetPath));
            }
            catch (BadImageFormatException)
            {
                return Assembly.LoadFrom(targetPath);
            }
        }

        private static void TriggerInitialization(Assembly assembly)
        {
            Type[] types;
            try { types = assembly.GetTypes(); }
            catch (ReflectionTypeLoadException ex) { types = ex.Types; }

            foreach (var type in types)
            {
                if (type == null || type.ContainsGenericParameters)
                    continue;
                try { System.Runtime.CompilerServices.RuntimeHelpers.RunClassConstructor(type.TypeHandle); }
                catch { }
            }
            Console.WriteLine("[VmExec] Initialization complete.");
        }

        private static string InvokeFocused(Assembly assembly, int token)
        {
            MethodInfo method;
            try
            {
                method = assembly.ManifestModule.ResolveMethod(token) as MethodInfo;
            }
            catch (Exception ex)
            {
                return "resolve-failed: " + ex.Message;
            }

            if (method == null)
                return "token is not a MethodInfo";

            object instance = null;
            if (!method.IsStatic)
                instance = FormatterServices.GetUninitializedObject(method.DeclaringType);

            // Successive string parameters can be given distinct values with
            // KRYPTON_VM_TRACE_ARG="first|second|..."; a single value applies to all.
            var argumentText = Environment.GetEnvironmentVariable("KRYPTON_VM_TRACE_ARG")
                               ?? "krypton-vm-exec-trace";
            var argumentList = argumentText.Split('|');
            var stringIndex = 0;
            var values = method.GetParameters().Select(p =>
            {
                if (p.ParameterType == typeof(string))
                {
                    var text = argumentList[Math.Min(stringIndex, argumentList.Length - 1)];
                    stringIndex++;
                    return (object)text;
                }
                return p.ParameterType.IsValueType ? Activator.CreateInstance(p.ParameterType) : null;
            }).ToArray();

            Console.WriteLine("[VmExec] Invoking " + method.DeclaringType.FullName + "::" + method.Name);
            _phase = "invoke-entry";
            _active = true;
            try
            {
                var result = method.Invoke(instance, values);
                return "returned " + (result == null ? "<null>" : result.GetType().FullName + " '" + result + "'");
            }
            catch (Exception ex)
            {
                var root = ex;
                while (root.InnerException != null)
                    root = root.InnerException;
                // The JIT keeps an IL offset map even without a PDB, so the throwing
                // instruction can be named exactly rather than by method alone.
                var located = new List<string>();
                try
                {
                    var trace = new StackTrace(root, true);
                    for (var i = 0; i < trace.FrameCount && i < 6; i++)
                    {
                        var frame = trace.GetFrame(i);
                        var frameMethod = frame.GetMethod();
                        var ilOffset = frame.GetILOffset();
                        located.Add(
                            (frameMethod?.DeclaringType?.FullName ?? "?") + "::" + (frameMethod?.Name ?? "?") +
                            (ilOffset == StackFrame.OFFSET_UNKNOWN ? " IL_?" : " IL_" + ilOffset.ToString("X4")) +
                            (frameMethod != null ? " token=0x" + frameMethod.MetadataToken.ToString("X8") : ""));
                    }
                }
                catch
                {
                }

                if (located.Count == 0)
                {
                    var frames = (root.StackTrace ?? string.Empty).Split('\n');
                    located.AddRange(frames.Take(4).Select(f => f.Trim()));
                }

                return "threw " + root.GetType().FullName + ": " + root.Message + " | at " +
                       string.Join(" | ", located);
            }
            finally
            {
                _active = false;
            }
        }

        // ------------------------------------------------------------ recording

        private static void Record(string kind, string detail, long offset, int value, int depthBefore, bool wantChain)
        {
            // Provenance first: an event only counts as evidence about the VM if a
            // frame from the protected assembly is on the stack below it. Framework
            // internals (exception construction, configuration loading) reach the
            // same patched methods and must be excluded rather than guessed at.
            string vmFrame;
            var vmOrigin = TryFindVmFrame(out vmFrame);

            lock (Sync)
            {
                if (_eventCount >= _maxEvents)
                    return;

                string caller = null;
                if (wantChain)
                {
                    int budget;
                    ChainBudget.TryGetValue(kind, out budget);
                    if (budget < 400)
                    {
                        ChainBudget[kind] = budget + 1;
                        caller = CallerChain();
                    }
                }

                _events[_eventCount] = new VmEvent
                {
                    Seq = _eventCount,
                    Phase = _phase,
                    Kind = kind,
                    Detail = detail,
                    Offset = offset,
                    Value = value,
                    DepthBefore = depthBefore,
                    VmOrigin = vmOrigin,
                    VmFrame = vmFrame,
                    Caller = caller
                };

                // Nested interpretation means a prefix can fire again before the outer
                // postfix returns, so results are paired through a per-kind stack
                // instead of "the most recent event of this kind".
                if (KindsWithResult.Contains(kind))
                {
                    if (_pendingByKind == null)
                        _pendingByKind = new Dictionary<string, List<int>>(StringComparer.Ordinal);
                    List<int> stack;
                    if (!_pendingByKind.TryGetValue(kind, out stack))
                    {
                        stack = new List<int>();
                        _pendingByKind[kind] = stack;
                    }
                    stack.Add(_eventCount);
                }

                _eventCount++;
            }
        }

        private static bool TryFindVmFrame(out string vmFrame)
        {
            vmFrame = null;
            if (_targetAssembly == null)
                return false;
            try
            {
                var frames = new StackTrace(1, false).GetFrames();
                if (frames == null)
                    return false;
                for (var i = 0; i < frames.Length; i++)
                {
                    var method = frames[i].GetMethod();
                    if (method == null || method.DeclaringType == null)
                        continue;
                    if (!ReferenceEquals(method.DeclaringType.Assembly, _targetAssembly))
                        continue;
                    vmFrame = Describe(method);
                    return true;
                }
            }
            catch
            {
            }
            return false;
        }

        private static void RecordResult(MethodBase original, string text)
        {
            var owner = original.DeclaringType;
            var kind = (owner == null ? "?" : owner.Name) + "." + original.Name;
            lock (Sync)
            {
                List<int> stack;
                if (_pendingByKind == null || !_pendingByKind.TryGetValue(kind, out stack) || stack.Count == 0)
                    return;
                var index = stack[stack.Count - 1];
                stack.RemoveAt(stack.Count - 1);
                if (index >= 0 && index < _eventCount && _events[index] != null)
                    _events[index].Result = text;
            }
        }

        private static string CallerChain()
        {
            try
            {
                return string.Join(" <- ", new StackTrace(2, false).GetFrames()
                    .Select(f => f.GetMethod())
                    .Where(m => m != null &&
                                m.DeclaringType != typeof(VmExecTraceRunner) &&
                                !(m.DeclaringType == null ? "" : m.DeclaringType.FullName)
                                    .StartsWith("HarmonyLib.", StringComparison.Ordinal))
                    .Take(10)
                    .Select(Describe));
            }
            catch
            {
                return "<stack unavailable>";
            }
        }

        private static string Describe(MethodBase method)
        {
            try
            {
                return (method.DeclaringType == null ? "<type>" : method.DeclaringType.FullName) +
                       "::" + method.Name + "|0x" + method.MetadataToken.ToString("X8");
            }
            catch
            {
                return "<frame>";
            }
        }

        private static string Brief(object value)
        {
            if (value == null)
                return "null";
            try
            {
                var type = value.GetType();
                if (type == typeof(string))
                {
                    var text = (string)value;
                    return "String:\"" + (text.Length > 400 ? text.Substring(0, 400) + "..." : text) + "\"";
                }
                if (type.IsPrimitive || type.IsEnum)
                    return type.Name + ":" + value;
                if (value is Array)
                {
                    var elements = (Array)value;
                    // The contents matter: an array reaching a call site tells us
                    // whether the instructions between its creation and that call
                    // actually stored into it.
                    var shown = new string[Math.Min(elements.Length, 16)];
                    for (var i = 0; i < shown.Length; i++)
                    {
                        object element = null;
                        try { element = elements.GetValue(i); } catch { }
                        shown[i] = element == null
                            ? "null"
                            : element is string
                                ? "\"" + (((string)element).Length > 120
                                      ? ((string)element).Substring(0, 120) + "..."
                                      : (string)element) + "\""
                                : element.GetType().Name;
                    }
                    return type.Name + "[len=" + elements.Length + "]{" + string.Join(", ", shown) +
                           (elements.Length > shown.Length ? ", ..." : "") + "}";
                }
                return type.FullName;
            }
            catch
            {
                return "<value>";
            }
        }

        private static string Deep(object value)
        {
            if (value == null)
                return "null";
            var array = value as object[];
            if (array == null)
                return Brief(value);
            var parts = new string[Math.Min(array.Length, 32)];
            for (var i = 0; i < parts.Length; i++)
                parts[i] = Brief(array[i]);
            return "object[" + array.Length + "]{" + string.Join(", ", parts) +
                   (array.Length > parts.Length ? ", ..." : "") + "}";
        }

        private static string DeepArgs(object[] args)
        {
            if (args == null || args.Length == 0)
                return "()";
            var parts = new string[args.Length];
            for (var i = 0; i < args.Length; i++)
                parts[i] = Deep(args[i]);
            return "(" + string.Join(", ", parts) + ")";
        }

        private static string BriefArgs(object[] args)
        {
            if (args == null || args.Length == 0)
                return "()";
            return "(" + string.Join(", ", args.Select(Brief)) + ")";
        }

        // -------------------------------------------------------------- patches

        public static void ReadBytePostfix(BinaryReader __instance, byte __result)
        {
            if (_inHook)
                return;
            _inHook = true;
            try
            {
                var stream = __instance == null ? null : __instance.BaseStream;
                if (stream == null || stream.Length != _streamLength)
                    return;
                var offset = stream.Position - 1;
                if (offset < _recordStart || offset >= _recordEnd)
                    return;

                Record("stream-read", null, offset, __result, -1, _opcodeFetches < 40);
                _opcodeFetches++;

                if (offset == _recordEnd - 1)
                {
                    _phase = "post-record";
                    Record("phase", "last record byte consumed", offset, __result, -1, false);
                }
                else if (!string.Equals(_phase, "record", StringComparison.Ordinal) &&
                         !string.Equals(_phase, "post-record", StringComparison.Ordinal))
                {
                    _phase = "record";
                    Record("phase", "first record byte consumed", offset, __result, -1, false);
                }
            }
            catch
            {
            }
            finally
            {
                _inHook = false;
            }
        }

        public static void UniversalPrefix(MethodBase __originalMethod, object __instance, object[] __args)
        {
            if (_inHook || !_active)
                return;
            _inHook = true;
            try
            {
                var owner = __originalMethod.DeclaringType;
                var kind = (owner == null ? "?" : owner.Name) + "." + __originalMethod.Name;
                Record(kind, DeepArgs(__args), -1, -1, -1, true);
            }
            catch
            {
            }
            finally
            {
                _inHook = false;
            }
        }

        public static void ObjectResultPostfix(MethodBase __originalMethod, object __result)
        {
            if (_inHook || !_active)
                return;
            _inHook = true;
            try { RecordResult(__originalMethod, Deep(__result)); }
            catch { }
            finally { _inHook = false; }
        }

        // A resolved metadata member tells us the declared call target: its declaring
        // type, whether it is virtual or abstract, and whether it is an interface
        // member. That is what separates a non-virtual call from a virtual dispatch.
        public static void ResolveResultPostfix(MethodBase __originalMethod, object __result)
        {
            if (_inHook || !_active)
                return;
            _inHook = true;
            try { RecordResult(__originalMethod, DescribeMember(__result)); }
            catch { }
            finally { _inHook = false; }
        }

        private static string DescribeMember(object member)
        {
            if (member == null)
                return "null";

            var type = member as Type;
            if (type != null)
            {
                return "TYPE " + type.FullName +
                       (type.IsInterface ? " [interface]" : "") +
                       (type.IsValueType ? " [valuetype]" : "") +
                       (type.IsEnum ? " [enum]" : "");
            }

            var method = member as MethodBase;
            if (method != null)
            {
                var declaring = method.DeclaringType;
                var methodInfo = method as MethodInfo;
                return "METHOD " + (declaring == null ? "?" : declaring.FullName) + "::" + method.Name +
                       "(" + string.Join(", ", method.GetParameters().Select(p => p.ParameterType.Name)) + ")" +
                       " ret=" + (methodInfo == null ? "void/ctor" : methodInfo.ReturnType.Name) +
                       (method.IsStatic ? " [static]" : "") +
                       (method.IsVirtual ? " [virtual]" : "") +
                       (method.IsAbstract ? " [abstract]" : "") +
                       (method.IsFinal ? " [final]" : "") +
                       (declaring != null && declaring.IsInterface ? " [interface-member]" : "") +
                       (declaring != null && declaring.IsValueType ? " [valuetype-owner]" : "");
            }

            var field = member as FieldInfo;
            if (field != null)
            {
                return "FIELD " + (field.DeclaringType == null ? "?" : field.DeclaringType.FullName) +
                       "::" + field.Name + " : " + field.FieldType.FullName +
                       (field.IsStatic ? " [static]" : " [instance]");
            }

            return member.GetType().FullName;
        }

        public static void ArrayResultPostfix(MethodBase __originalMethod, Array __result)
        {
            if (_inHook || !_active)
                return;
            _inHook = true;
            try
            {
                RecordResult(__originalMethod,
                    __result == null ? "null" : __result.GetType().Name + "[len=" + __result.Length + "]");
            }
            catch { }
            finally { _inHook = false; }
        }

        public static void StackPrefix(MethodBase __originalMethod, object __instance, object[] __args)
        {
            if (_inHook || !_active)
                return;
            _inHook = true;
            try
            {
                var depth = -1;
                string top = null;
                var generic = __instance as Stack<object>;
                if (generic != null)
                {
                    depth = generic.Count;
                    if (depth > 0)
                        top = Brief(generic.Peek());
                }
                else
                {
                    var plain = __instance as Stack;
                    if (plain != null)
                    {
                        depth = plain.Count;
                        if (depth > 0)
                            top = Brief(plain.Peek());
                    }
                    else
                    {
                        return;
                    }
                }

                var owner = __originalMethod.DeclaringType;
                var kind = "STACK." + (owner == null ? "?" : owner.Name) + "." + __originalMethod.Name;
                var detail = "id=" + (__instance == null
                                 ? "?"
                                 : System.Runtime.CompilerServices.RuntimeHelpers.GetHashCode(__instance).ToString("X8")) +
                             " top=" + (top ?? "-") +
                             " arg=" + (__args == null || __args.Length == 0 ? "-" : Brief(__args[0]));
                Record(kind, detail, -1, -1, depth, true);
            }
            catch
            {
            }
            finally
            {
                _inHook = false;
            }
        }

        public static void ListPrefix(MethodBase __originalMethod, object __instance, object[] __args)
        {
            if (_inHook || !_active)
                return;
            _inHook = true;
            try
            {
                var list = __instance as IList;
                if (list == null)
                    return;
                var owner = __originalMethod.DeclaringType;
                var kind = "LIST." + (owner == null ? "?" : owner.Name) + "." + __originalMethod.Name;
                Record(kind,
                    "id=" + System.Runtime.CompilerServices.RuntimeHelpers.GetHashCode(__instance).ToString("X8") +
                    " arg=" + (__args == null || __args.Length == 0 ? "-" : Brief(__args[0])),
                    -1, -1, list.Count, true);
            }
            catch
            {
            }
            finally
            {
                _inHook = false;
            }
        }

        // ------------------------------------------------------- network guard
        //
        // Executing a licensing method must not reach the network. Every outbound
        // path is either answered from a fixed local value or made to fail; nothing
        // is read from the internet. The canned answer is an input we control, which
        // is also how different branches of the method get exercised.

        private static string CannedResponse()
        {
            var raw = Environment.GetEnvironmentVariable("KRYPTON_VM_NET_RESPONSE");
            return raw ?? "0";
        }

        public static bool DownloadStringPrefix(object __0, ref string __result)
        {
            __result = CannedResponse();
            // The requested address is the whole first half of the method condensed
            // into one observable value, which makes it the differential signal.
            Record("net-blocked",
                "WebClient.DownloadString(" + (__0 == null ? "null" : __0.ToString()) +
                ") -> canned \"" + __result + "\"", -1, -1, -1, true);
            return false;
        }

        public static bool FileWritePrefix(MethodBase __originalMethod, object[] __args)
        {
            // Only the traced invocation is prevented from touching the disk; the
            // runner still has to write its own dump.
            if (!_active)
                return true;
            Record("file-blocked",
                __originalMethod.Name + BriefArgs(__args), -1, -1, -1, true);
            return false;
        }

        public static bool DownloadDataPrefix(ref byte[] __result)
        {
            __result = System.Text.Encoding.UTF8.GetBytes(CannedResponse());
            Record("net-blocked", "WebClient.DownloadData -> canned", -1, -1, -1, true);
            return false;
        }

        public static bool OpenReadPrefix(ref Stream __result)
        {
            __result = new MemoryStream(System.Text.Encoding.UTF8.GetBytes(CannedResponse()));
            Record("net-blocked", "WebClient.OpenRead -> canned", -1, -1, -1, true);
            return false;
        }

        public static bool DenyPrefix(MethodBase __originalMethod)
        {
            var name = (__originalMethod.DeclaringType == null ? "?" : __originalMethod.DeclaringType.Name) +
                       "::" + __originalMethod.Name;
            Record("net-denied", name, -1, -1, -1, true);
            throw new InvalidOperationException("krypton: outbound network denied (" + name + ")");
        }

        private static void InstallNetworkGuard()
        {
            var webClient = typeof(System.Net.WebClient);
            foreach (var method in webClient.GetMethods(BindingFlags.Public | BindingFlags.Instance)
                         .Where(m => m.Name == "DownloadString" && m.ReturnType == typeof(string)))
                Patch(method, nameof(DownloadStringPrefix));
            foreach (var method in webClient.GetMethods(BindingFlags.Public | BindingFlags.Instance)
                         .Where(m => m.Name == "DownloadData" && m.ReturnType == typeof(byte[])))
                Patch(method, nameof(DownloadDataPrefix));
            foreach (var method in webClient.GetMethods(BindingFlags.Public | BindingFlags.Instance)
                         .Where(m => m.Name == "OpenRead"))
                Patch(method, nameof(OpenReadPrefix));

            // Anything else that could carry bytes off the machine fails instead.
            foreach (var name in new[] { "UploadString", "UploadData", "UploadValues", "UploadFile",
                                         "DownloadFile", "DownloadStringTaskAsync", "DownloadDataTaskAsync" })
                foreach (var method in webClient.GetMethods(BindingFlags.Public | BindingFlags.Instance)
                             .Where(m => m.Name == name))
                    Patch(method, nameof(DenyPrefix));

            Patch(typeof(System.Net.WebRequest).GetMethod("GetResponse",
                BindingFlags.Public | BindingFlags.Instance, null, Type.EmptyTypes, null), nameof(DenyPrefix));
            Patch(typeof(System.Net.HttpWebRequest).GetMethod("GetResponse",
                BindingFlags.Public | BindingFlags.Instance, null, Type.EmptyTypes, null), nameof(DenyPrefix));
            Patch(typeof(System.Net.WebRequest).GetMethod("GetRequestStream",
                BindingFlags.Public | BindingFlags.Instance, null, Type.EmptyTypes, null), nameof(DenyPrefix));
            foreach (var method in typeof(System.Net.Sockets.Socket)
                         .GetMethods(BindingFlags.Public | BindingFlags.Instance)
                         .Where(m => m.Name == "Connect" || m.Name == "ConnectAsync" || m.Name == "SendTo"))
                Patch(method, nameof(DenyPrefix));
            // File writes are side effects too; both sides of a differential run must
            // be equally prevented from performing them.
            if (string.Equals(Environment.GetEnvironmentVariable("KRYPTON_VM_TRACE_BLOCK_FILES"), "1",
                    StringComparison.Ordinal))
            {
                foreach (var name in new[] { "WriteAllText", "WriteAllBytes", "WriteAllLines",
                                             "AppendAllText", "Delete", "Copy", "Move" })
                    foreach (var method in typeof(File).GetMethods(BindingFlags.Public | BindingFlags.Static)
                                 .Where(m => m.Name == name && m.ReturnType == typeof(void)))
                        Patch(method, nameof(FileWritePrefix));
            }

            foreach (var method in typeof(System.Net.Dns)
                         .GetMethods(BindingFlags.Public | BindingFlags.Static)
                         .Where(m => m.Name.StartsWith("GetHost", StringComparison.Ordinal)))
                Patch(method, nameof(DenyPrefix));
        }

        // ------------------------------------------------- interpreter state probe
        //
        // Every VM handler body is a NecroBit stub, so handlers cannot be patched.
        // But .NET Reactor routes their internal calls through static helper methods
        // on delegate types, and those helpers carry real IL. Patching them yields a
        // per-call observation point whose delegate argument exposes Target: the
        // handler instance, i.e. the interpreter's own state object.

        private static string DescribeState(object target)
        {
            if (target == null)
                return "static";
            var type = target.GetType();
            var parts = new List<string> { type.FullName };
            foreach (var field in type.GetFields(BindingFlags.Instance | BindingFlags.Public |
                                                 BindingFlags.NonPublic))
            {
                object value;
                try { value = field.GetValue(target); }
                catch { continue; }
                if (value == null)
                {
                    parts.Add(field.Name + "=null");
                    continue;
                }
                var array = value as Array;
                if (array != null)
                {
                    parts.Add(field.Name + "=" + Brief(value));
                    continue;
                }
                if (value.GetType().IsPrimitive || value.GetType().IsEnum || value is string)
                {
                    parts.Add(field.Name + "=" + Brief(value));
                    continue;
                }
                var collection = value as ICollection;
                parts.Add(field.Name + "=" + value.GetType().Name +
                          (collection == null ? "" : "[count=" + collection.Count + "]"));
            }
            return string.Join(" ", parts);
        }

        public static void ThunkPrefix(MethodBase __originalMethod, object[] __args)
        {
            if (_inHook || !_active)
                return;
            _inHook = true;
            try
            {
                Delegate callback = null;
                if (__args != null)
                {
                    for (var i = __args.Length - 1; i >= 0; i--)
                    {
                        callback = __args[i] as Delegate;
                        if (callback != null)
                            break;
                    }
                }

                var owner = __originalMethod.DeclaringType;
                var kind = "THUNK." + (owner == null ? "?" : owner.Name);
                var detail = "-> " + (callback == null ? "?" : Describe(callback.Method)) +
                             " | state: " + DescribeState(callback == null ? null : callback.Target) +
                             " | args " + DeepArgs(__args);
                Record(kind, detail, -1, -1, -1, true);
            }
            catch
            {
            }
            finally
            {
                _inHook = false;
            }
        }

        // ------------------------------------------------------ controlled inputs
        //
        // Some paths through a method are only reachable for particular return values
        // of the methods it calls (an activation check, a settings predicate). Those
        // are inputs, not VM semantics: forcing one changes which branch the
        // interpreter takes without altering a single opcode or bytecode byte.
        // Configured as KRYPTON_VM_TRACE_STUB=0x06000123=true,0x06000456=null

        private static readonly Dictionary<int, string> StubbedReturns = new Dictionary<int, string>();

        public static bool StubBoolPrefix(MethodBase __originalMethod, ref bool __result)
        {
            __result = ResolveStub(__originalMethod, "true");
            return false;
        }

        public static bool StubObjectPrefix(MethodBase __originalMethod, ref object __result)
        {
            __result = null;
            RecordStub(__originalMethod, "null");
            return false;
        }

        public static bool StubVoidPrefix(MethodBase __originalMethod)
        {
            RecordStub(__originalMethod, "void");
            return false;
        }

        private static bool ResolveStub(MethodBase original, string fallback)
        {
            string text;
            if (!StubbedReturns.TryGetValue(original.MetadataToken, out text))
                text = fallback;
            var value = string.Equals(text, "true", StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(text, "1", StringComparison.Ordinal);
            RecordStub(original, value ? "true" : "false");
            return value;
        }

        private static void RecordStub(MethodBase original, string value)
        {
            if (_inHook)
                return;
            _inHook = true;
            try
            {
                Record("stub", (original.DeclaringType == null ? "?" : original.DeclaringType.Name) +
                               "::" + original.Name + " -> " + value, -1, -1, -1, true);
            }
            catch
            {
            }
            finally
            {
                _inHook = false;
            }
        }

        // A modal dialog blocks the traced thread forever. Answering it locally with a
        // fixed value is another controlled input: it selects which branch the
        // interpreter takes without touching the bytecode.
        public static bool ShowDialogPrefix(ref System.Windows.Forms.DialogResult __result)
        {
            var raw = Environment.GetEnvironmentVariable("KRYPTON_VM_TRACE_DIALOG");
            int value;
            if (!int.TryParse(raw, out value))
                value = 2;
            __result = (System.Windows.Forms.DialogResult)value;
            if (!_inHook)
            {
                _inHook = true;
                try { Record("stub", "CommonDialog.ShowDialog -> " + (int)__result + " (" + __result + ")", -1, -1, -1, true); }
                catch { }
                finally { _inHook = false; }
            }
            return false;
        }

        // Effects both implementations must produce identically: the values handed to
        // the framework. These are hooked in the VM run and in the reconstructed run
        // alike, so the two sequences can be compared directly.
        public static void EffectPrefix(MethodBase __originalMethod, object[] __args)
        {
            if (_inHook || !_active)
                return;
            _inHook = true;
            try
            {
                Record("effect",
                    (__originalMethod.DeclaringType == null ? "?" : __originalMethod.DeclaringType.Name) +
                    "::" + __originalMethod.Name + DeepArgs(__args), -1, -1, -1, false);
            }
            catch
            {
            }
            finally
            {
                _inHook = false;
            }
        }

        private static void InstallEffectHooks()
        {
            var dialog = typeof(System.Windows.Forms.FileDialog);
            foreach (var name in new[] { "set_Filter", "set_FileName", "set_Title", "set_InitialDirectory" })
                Patch(dialog.GetMethod(name, BindingFlags.Public | BindingFlags.Instance), nameof(EffectPrefix));

            foreach (var method in typeof(string).GetMethods(BindingFlags.Public | BindingFlags.Static)
                         .Where(m => m.Name == "Concat" &&
                                     m.GetParameters().All(p => p.ParameterType == typeof(string))))
                Patch(method, nameof(EffectPrefix));

            Patch(typeof(System.IO.Path).GetMethod("Combine", BindingFlags.Public | BindingFlags.Static,
                null, new[] { typeof(string), typeof(string) }, null), nameof(EffectPrefix));
        }

        private static void InstallDialogStub()
        {
            if (string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("KRYPTON_VM_TRACE_DIALOG")))
                return;
            var target = typeof(System.Windows.Forms.CommonDialog).GetMethod(
                "ShowDialog", BindingFlags.Public | BindingFlags.Instance, null, Type.EmptyTypes, null);
            if (target == null)
                return;
            try
            {
                _harmony.Patch(target, prefix: new HarmonyMethod(
                    typeof(VmExecTraceRunner).GetMethod(nameof(ShowDialogPrefix),
                        BindingFlags.Public | BindingFlags.Static)));
                Console.WriteLine("[VmExec] stubbed CommonDialog::ShowDialog -> " +
                                  Environment.GetEnvironmentVariable("KRYPTON_VM_TRACE_DIALOG"));
            }
            catch (Exception ex)
            {
                Console.WriteLine("[VmExec] dialog stub failed: " + ex.Message);
            }
        }

        // Static state can be set before the traced invocation with
        // KRYPTON_VM_TRACE_SETFIELD=<fieldToken>=<int>[,...]. This is a controlled
        // input, exactly like the canned network answer: it selects which value the
        // method observes without touching a single opcode.
        private static void ApplyFieldPresets(Assembly assembly)
        {
            var raw = Environment.GetEnvironmentVariable("KRYPTON_VM_TRACE_SETFIELD");
            if (string.IsNullOrWhiteSpace(raw))
                return;

            foreach (var entry in raw.Split(','))
            {
                var parts = entry.Split('=');
                if (parts.Length != 2)
                    continue;
                var text = parts[0].Trim();
                if (text.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                    text = text.Substring(2);
                int token;
                if (!int.TryParse(text, System.Globalization.NumberStyles.HexNumber, null, out token))
                    continue;

                try
                {
                    var field = assembly.ManifestModule.ResolveField(token);
                    var text2 = parts[1].Trim();
                    object value;
                    if (string.Equals(text2, "null", StringComparison.OrdinalIgnoreCase))
                    {
                        // Clearing a cached reference is the only way to observe the
                        // initialisation path of a method that short-circuits once its
                        // cache is populated. It is a controlled input like any other
                        // preset: no opcode and no method body is touched.
                        value = null;
                    }
                    else if (string.Equals(text2, "new", StringComparison.OrdinalIgnoreCase))
                    {
                        // A fresh instance, so a reference field can be equalised on both
                        // sides of a differential without reviving any protection state.
                        value = Activator.CreateInstance(
                            field.FieldType == typeof(object) ? typeof(object) : field.FieldType);
                    }
                    else
                    {
                        var number = Convert.ToInt64(text2);
                        value = field.FieldType.IsEnum
                            ? Enum.ToObject(field.FieldType, number)
                            : Convert.ChangeType(number, field.FieldType);
                    }
                    field.SetValue(null, value);
                    Console.WriteLine("[VmExec] preset " + field.DeclaringType.Name + "::" + field.Name +
                                      " = " + (value ?? "<null>") + " (" + field.FieldType.Name + ")");
                    Record("preset", field.DeclaringType.Name + "::" + field.Name + " = " + (value ?? "<null>"),
                        -1, -1, -1, false);
                }
                catch (Exception ex)
                {
                    Console.WriteLine("[VmExec] preset failed for " + parts[0] + ": " + ex.Message);
                }
            }
        }

        private static void InstallStubs(Assembly assembly)
        {
            var raw = Environment.GetEnvironmentVariable("KRYPTON_VM_TRACE_STUB");
            if (string.IsNullOrWhiteSpace(raw))
                return;

            foreach (var entry in raw.Split(','))
            {
                var parts = entry.Split('=');
                if (parts.Length != 2)
                    continue;
                var text = parts[0].Trim();
                if (text.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                    text = text.Substring(2);
                int token;
                if (!int.TryParse(text, System.Globalization.NumberStyles.HexNumber, null, out token))
                    continue;

                MethodBase resolved;
                try
                {
                    resolved = assembly.ManifestModule.ResolveMethod(token);
                }
                catch
                {
                    Console.WriteLine("[VmExec] stub token unresolvable: " + parts[0]);
                    continue;
                }
                if (resolved == null)
                    continue;
                var method = resolved as MethodInfo;
                if (method == null)
                {
                    // A constructor the output leaves empty: skip its body too.
                    StubbedReturns[token] = parts[1].Trim();
                    try
                    {
                        _harmony.Patch(resolved, prefix: new HarmonyMethod(
                            typeof(VmExecTraceRunner).GetMethod(nameof(StubVoidPrefix),
                                BindingFlags.Public | BindingFlags.Static)));
                        Console.WriteLine("[VmExec] stubbed ctor " + resolved.DeclaringType.Name + "::" + resolved.Name);
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine("[VmExec] ctor stub failed for " + resolved.Name + ": " + ex.Message);
                    }
                    continue;
                }

                StubbedReturns[token] = parts[1].Trim();
                var handler = method.ReturnType == typeof(void)
                    ? nameof(StubVoidPrefix)
                    : method.ReturnType == typeof(bool)
                        ? nameof(StubBoolPrefix)
                        : method.ReturnType.IsValueType ? null : nameof(StubObjectPrefix);
                if (handler == null)
                {
                    Console.WriteLine("[VmExec] stub unsupported return type " + method.ReturnType.Name +
                                      " for " + method.Name);
                    continue;
                }

                try
                {
                    _harmony.Patch(method, prefix: new HarmonyMethod(
                        typeof(VmExecTraceRunner).GetMethod(handler,
                            BindingFlags.Public | BindingFlags.Static)));
                    Console.WriteLine("[VmExec] stubbed " + method.DeclaringType.Name + "::" + method.Name +
                                      " -> " + parts[1].Trim());
                }
                catch (Exception ex)
                {
                    Console.WriteLine("[VmExec] stub failed for " + method.Name + ": " + ex.Message);
                }
            }
        }

        private static void InstallThunkPatches(Assembly assembly)
        {
            Type[] types;
            try { types = assembly.GetTypes(); }
            catch (ReflectionTypeLoadException ex) { types = ex.Types; }

            var patched = 0;
            var skipped = 0;
            foreach (var type in types)
            {
                if (type == null || !typeof(Delegate).IsAssignableFrom(type))
                    continue;
                MethodInfo[] candidates;
                try
                {
                    candidates = type.GetMethods(BindingFlags.Static | BindingFlags.Public |
                                                 BindingFlags.NonPublic | BindingFlags.DeclaredOnly);
                }
                catch
                {
                    continue;
                }

                foreach (var method in candidates)
                {
                    byte[] il = null;
                    try
                    {
                        var body = method.GetMethodBody();
                        il = body == null ? null : body.GetILAsByteArray();
                    }
                    catch
                    {
                    }

                    // A real thunk: short body that ends in a call through the delegate.
                    if (il == null || il.Length < 5 || il.Length > 32)
                        continue;
                    try
                    {
                        if (!method.GetParameters().Any(p => typeof(Delegate).IsAssignableFrom(p.ParameterType)))
                            continue;
                    }
                    catch
                    {
                        // Signature references an assembly that is not present.
                        skipped++;
                        continue;
                    }

                    try
                    {
                        _harmony.Patch(method, prefix: new HarmonyMethod(
                            typeof(VmExecTraceRunner).GetMethod(nameof(ThunkPrefix),
                                BindingFlags.Public | BindingFlags.Static)));
                        patched++;
                    }
                    catch
                    {
                        skipped++;
                    }
                }
            }
            Console.WriteLine("[VmExec] delegate thunks patched: " + patched + ", skipped: " + skipped);
        }

        private static void InstallPatches()
        {
            _harmony = new Harmony("krypton.runner.vmexec");

            InstallNetworkGuard();
            InstallDialogStub();
            if (string.Equals(Environment.GetEnvironmentVariable("KRYPTON_VM_TRACE_EFFECTS"), "1",
                    StringComparison.Ordinal))
                InstallEffectHooks();

            Patch(typeof(BinaryReader).GetMethod("ReadByte", BindingFlags.Public | BindingFlags.Instance,
                    null, Type.EmptyTypes, null),
                nameof(ReadBytePostfix), postfix: true);

            // Stage 1 — reflection and allocation surface. A managed interpreter that
            // implements Call / Newobj / Ldfld / Ldstr through reflection must cross here.
            var module = typeof(Module);
            foreach (var name in new[] { "ResolveMethod", "ResolveField", "ResolveType", "ResolveMember", "ResolveString", "ResolveSignature" })
                Patch(module.GetMethod(name, BindingFlags.Public | BindingFlags.Instance, null, new[] { typeof(int) }, null),
                    nameof(UniversalPrefix));

            Patch(typeof(MethodBase).GetMethod("Invoke", BindingFlags.Public | BindingFlags.Instance,
                    null, new[] { typeof(object), typeof(object[]) }, null), nameof(UniversalPrefix));
            Patch(typeof(ConstructorInfo).GetMethod("Invoke", BindingFlags.Public | BindingFlags.Instance,
                    null, new[] { typeof(object[]) }, null), nameof(UniversalPrefix));
            Patch(typeof(FieldInfo).GetMethod("SetValue", BindingFlags.Public | BindingFlags.Instance,
                    null, new[] { typeof(object), typeof(object) }, null), nameof(UniversalPrefix));
            Patch(typeof(Delegate).GetMethod("DynamicInvoke", BindingFlags.Public | BindingFlags.Instance),
                nameof(UniversalPrefix));
            Patch(typeof(Activator).GetMethod("CreateInstance", BindingFlags.Public | BindingFlags.Static,
                    null, new[] { typeof(Type), typeof(object[]) }, null), nameof(UniversalPrefix));
            Patch(typeof(Activator).GetMethod("CreateInstance", BindingFlags.Public | BindingFlags.Static,
                    null, new[] { typeof(Type) }, null), nameof(UniversalPrefix));
            Patch(typeof(Array).GetMethod("CreateInstance", BindingFlags.Public | BindingFlags.Static,
                    null, new[] { typeof(Type), typeof(int) }, null), nameof(UniversalPrefix));

            var rtField = typeof(FieldInfo).Assembly.GetType("System.Reflection.RtFieldInfo", false);
            if (rtField != null)
            {
                Patch(rtField.GetMethod("GetValue", BindingFlags.Public | BindingFlags.Instance,
                    null, new[] { typeof(object) }, null), nameof(UniversalPrefix));
            }

            var rtMethod = typeof(MethodInfo).Assembly.GetType("System.Reflection.RuntimeMethodInfo", false);
            if (rtMethod != null)
            {
                foreach (var candidate in rtMethod.GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.NonPublic)
                             .Where(m => m.Name == "Invoke" && m.GetParameters().Length >= 4))
                    Patch(candidate, nameof(UniversalPrefix));
            }

            foreach (var name in new[] { "ToInt32", "ToInt64", "ToDouble", "ToBoolean", "ToSingle" })
                Patch(typeof(Convert).GetMethod(name, BindingFlags.Public | BindingFlags.Static,
                    null, new[] { typeof(object) }, null), nameof(UniversalPrefix));

            foreach (var name in new[] { "ResolveMethod", "ResolveField", "ResolveType", "ResolveMember" })
                PatchPostfixOn(module.GetMethod(name, BindingFlags.Public | BindingFlags.Instance,
                    null, new[] { typeof(int) }, null), nameof(ResolveResultPostfix));

            // Return values: the value the interpreter pushes back onto its stack.
            PatchPostfixOn(typeof(MethodBase).GetMethod("Invoke", BindingFlags.Public | BindingFlags.Instance,
                null, new[] { typeof(object), typeof(object[]) }, null), nameof(ObjectResultPostfix));
            PatchPostfixOn(typeof(ConstructorInfo).GetMethod("Invoke", BindingFlags.Public | BindingFlags.Instance,
                null, new[] { typeof(object[]) }, null), nameof(ObjectResultPostfix));
            PatchPostfixOn(typeof(Activator).GetMethod("CreateInstance", BindingFlags.Public | BindingFlags.Static,
                null, new[] { typeof(Type), typeof(object[]) }, null), nameof(ObjectResultPostfix));
            PatchPostfixOn(typeof(Array).GetMethod("CreateInstance", BindingFlags.Public | BindingFlags.Static,
                null, new[] { typeof(Type), typeof(int) }, null), nameof(ArrayResultPostfix));
            if (rtField != null)
                PatchPostfixOn(rtField.GetMethod("GetValue", BindingFlags.Public | BindingFlags.Instance,
                    null, new[] { typeof(object) }, null), nameof(ObjectResultPostfix));

            if (_stage != 2 && _stage != 3)
                return;

            // Stage 2 — an evaluation stack held in a framework collection.
            foreach (var name in new[] { "Push", "Pop", "Peek" })
            {
                Patch(typeof(Stack<object>).GetMethod(name), nameof(StackPrefix));
                Patch(typeof(Stack).GetMethod(name), nameof(StackPrefix));
            }

            if (_stage < 3)
                return;

            // Stage 3 — an evaluation stack held in a growable list.
            Patch(typeof(List<object>).GetMethod("Add"), nameof(ListPrefix));
            Patch(typeof(List<object>).GetMethod("RemoveAt"), nameof(ListPrefix));
            Patch(typeof(ArrayList).GetMethod("Add"), nameof(ListPrefix));
            Patch(typeof(ArrayList).GetMethod("RemoveAt"), nameof(ListPrefix));
        }

        private static void PatchPostfixOn(MethodBase target, string handler)
        {
            Patch(target, handler, postfix: true);
        }

        private static void Patch(MethodBase target, string handler, bool postfix = false)
        {
            if (target == null)
                return;
            try
            {
                var patch = new HarmonyMethod(typeof(VmExecTraceRunner).GetMethod(
                    handler, BindingFlags.Public | BindingFlags.Static));
                if (postfix)
                    _harmony.Patch(target, postfix: patch);
                else
                    _harmony.Patch(target, prefix: patch);
                Console.WriteLine("[VmExec] patched " + (target.DeclaringType == null ? "?" : target.DeclaringType.Name) +
                                  "::" + target.Name);
            }
            catch (Exception ex)
            {
                Console.WriteLine("[VmExec] patch skipped " +
                                  (target.DeclaringType == null ? "?" : target.DeclaringType.Name) +
                                  "::" + target.Name + " -> " + ex.GetType().Name + ": " + ex.Message);
            }
        }
    }
}
