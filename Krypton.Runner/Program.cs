using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using Newtonsoft.Json;

namespace Krypton.Runner
{
    /// <summary>
    /// Krypton.Runner — dynamic analysis helper (net48).
    ///
    /// Usage:  Krypton.Runner.exe  &lt;protected-exe&gt;  &lt;output-dump.json&gt;
    ///
    /// Loads the NET Reactor protected assembly inside a real .NET Framework 4.x
    /// process, lets the bootstrap run so all DynamicMethods are created, captures
    /// their IL via dnlib's DynamicMethodBodyReader, and writes the resolved IL to
    /// a JSON dump consumed by Krypton's HiddenCallRecovery stage.
    ///
    /// Exit codes:
    ///   0 — success
    ///   1 — bad arguments
    ///   2 — load / capture failure
    /// </summary>
    internal static class Program
    {
        private static string ScopeOf(dnlib.DotNet.TypeSig sig)
        {
            return sig?.ScopeType?.Scope?.ScopeName ?? "?";
        }

        private static int Main(string[] args)
        {
            Console.WriteLine("Krypton.Runner  [dynamic DynamicMethod capture for NET Reactor]");
            Console.WriteLine();

            if (args.Length >= 2 && args[0] == "--diag")
            {
                DiagnosticRunner.Run(args[1]);
                return 0;
            }

            // --snapshot <exe> <forms.json>  — runs ONLY form snapshot (called as child process)
            if (args.Length >= 3 && args[0] == "--snapshot")
            {
                return RunFormSnapshot(args[1], args[2]);
            }

            // --payload-trace <exe> <payload-trace.json>  - captures runtime byte buffers
            // produced by NET Reactor resource/method-body decryptors.
            if (args.Length >= 3 && args[0] == "--payload-trace")
            {
                return PayloadTraceRunner.Run(args[1], args[2]);
            }

            // --eval-keyed-strings <exe> <out.json> <singletonField> <decoder> <keyField:encId>...
            // Reactor's keyed string decoder takes an id that the call site xors with a
            // key held on the runtime singleton. Both are only known once the bootstrap
            // has run, so the ids are evaluated here rather than guessed statically.
            if (args.Length >= 6 && args[0] == "--eval-keyed-strings")
            {
                var baseDir5 = Path.GetDirectoryName(Path.GetFullPath(args[1]));
                AppDomain.CurrentDomain.AssemblyResolve += (s6, e6) =>
                {
                    var simple = new AssemblyName(e6.Name).Name;
                    foreach (var ext in new[] { ".dll", ".exe" })
                    {
                        var candidate = Path.Combine(baseDir5, simple + ext);
                        if (File.Exists(candidate))
                            return Assembly.LoadFrom(candidate);
                    }
                    return null;
                };

                ExitGuard.Install();
                ExitGuard.Behavior = ExitGuardBehavior.Suppress;
                var asm5 = Assembly.LoadFrom(args[1]);
                Type[] types5;
                try { types5 = asm5.GetTypes(); }
                catch (ReflectionTypeLoadException rex5) { types5 = rex5.Types; }
                foreach (var t in types5)
                {
                    if (t == null || t.ContainsGenericParameters) continue;
                    try { System.Runtime.CompilerServices.RuntimeHelpers.RunClassConstructor(t.TypeHandle); }
                    catch { }
                }

                var module5 = asm5.ManifestModule;
                Func<string, int> hex = v => int.Parse(
                    v.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? v.Substring(2) : v,
                    System.Globalization.NumberStyles.HexNumber);

                var singletonField = module5.ResolveField(hex(args[3]));
                var decoder5 = module5.ResolveMethod(hex(args[4])) as MethodInfo;
                var singleton = singletonField.GetValue(null);
                if (singleton == null || decoder5 == null)
                {
                    Console.Error.WriteLine("[KeyedStrings] singleton or decoder unavailable");
                    return 2;
                }

                Console.WriteLine("[KeyedStrings] singleton=" + singleton.GetType().FullName +
                                  " decoder=" + decoder5.DeclaringType.Name + "::" + decoder5.Name);

                // Each site carries its own key field; the pairs arrive as
                // <keyFieldToken>:<encodedConstant>, either as trailing args or, to
                // avoid the OS command-line length limit at assembly scale, from a
                // file named by a single "@path" argument (one pair per line).
                var pairArgs = new List<string>();
                for (var i = 5; i < args.Length; i++)
                {
                    if (args[i].StartsWith("@"))
                        pairArgs.AddRange(File.ReadAllLines(args[i].Substring(1))
                            .Select(x => x.Trim()).Where(x => x.Length > 0));
                    else
                        pairArgs.Add(args[i]);
                }
                var results = new List<object>();
                foreach (var pairArg in pairArgs)
                {
                    var parts5 = pairArg.Split(':');
                    if (parts5.Length != 2)
                        continue;
                    var keyFieldToken = hex(parts5[0]);
                    var encoded = unchecked((int)Convert.ToInt64(
                        parts5[1].StartsWith("0x", StringComparison.OrdinalIgnoreCase)
                            ? parts5[1].Substring(2) : parts5[1], 16));
                    string value = null, error = null;
                    int key = 0;
                    try
                    {
                        key = Convert.ToInt32(module5.ResolveField(keyFieldToken).GetValue(singleton));
                        value = decoder5.Invoke(null, new object[] { encoded ^ key }) as string;
                    }
                    catch (Exception ex)
                    {
                        var root = ex;
                        while (root.InnerException != null) root = root.InnerException;
                        error = root.GetType().Name + ": " + root.Message;
                    }
                    results.Add(new
                    {
                        KeyField = "0x" + keyFieldToken.ToString("X8"),
                        Encoded = "0x" + encoded.ToString("X8"),
                        Key = "0x" + key.ToString("X8"),
                        Value = value,
                        Error = error
                    });
                }

                File.WriteAllText(args[2], JsonConvert.SerializeObject(new
                {
                    Assembly = Path.GetFullPath(args[1]),
                    Singleton = "0x" + hex(args[3]).ToString("X8"),
                    Decoder = "0x" + hex(args[4]).ToString("X8"),
                    Strings = results
                }, Formatting.Indented), System.Text.Encoding.UTF8);
                Console.WriteLine("[KeyedStrings] evaluated " + results.Count + " id(s) -> " + args[2]);
                return 0;
            }

            // --necrobit-body-dump-all <exe> <out.json>  - assembly-wide generalization
            // of --necrobit-body-dump. dnlib reads the on-disk bodies to detect NecroBit
            // stubs by SHAPE (a 1-2 instruction ldnull/ldc/nop + ret), then the bootstrap
            // materialises the real bodies and reflection captures each. No token list.
            if (args.Length >= 3 && args[0] == "--necrobit-body-dump-all")
            {
                var baseDirDa = Path.GetDirectoryName(Path.GetFullPath(args[1]));
                AppDomain.CurrentDomain.AssemblyResolve += (sda, eda) =>
                {
                    var simple = new AssemblyName(eda.Name).Name;
                    foreach (var ext in new[] { ".dll", ".exe" })
                    {
                        var candidate = Path.Combine(baseDirDa, simple + ext);
                        if (File.Exists(candidate))
                            return Assembly.LoadFrom(candidate);
                    }
                    return null;
                };

                // 1. dnlib pass: classify every method's on-disk body shape.
                var stubTokens = new List<int>();
                var classCounts = new Dictionary<string, int>();
                using (var dn = dnlib.DotNet.ModuleDefMD.Load(args[1]))
                {
                    foreach (var t in dn.GetTypes())
                    {
                        foreach (var m in t.Methods)
                        {
                            string cls;
                            if (!m.HasBody || m.Body == null || m.Body.Instructions.Count == 0)
                            {
                                cls = (m.IsAbstract || m.IsPinvokeImpl || m.IsInternalCall || m.IsRuntime)
                                    ? "ABSTRACT_EXTERN" : "NO_BODY";
                            }
                            else
                            {
                                var ins = m.Body.Instructions;
                                bool isStub = false;
                                // NecroBit stub shapes: {nop|ldnull|ldc.i4.*} ... ret, <= 3 instrs,
                                // no calls/branches, no locals, no EH.
                                if (ins.Count <= 6 && m.Body.ExceptionHandlers.Count == 0 &&
                                    (m.Body.Variables == null || m.Body.Variables.Count == 0))
                                {
                                    var last = ins[ins.Count - 1];
                                    bool tail = last.OpCode.Code == dnlib.DotNet.Emit.Code.Ret ||
                                                last.OpCode.Code == dnlib.DotNet.Emit.Code.Throw;
                                    bool onlyTrivial = true;
                                    for (int k = 0; k < ins.Count - 1; k++)
                                    {
                                        var c = ins[k].OpCode.Code;
                                        if (!(c == dnlib.DotNet.Emit.Code.Nop || c == dnlib.DotNet.Emit.Code.Ldnull ||
                                              c.ToString().StartsWith("Ldc_I4") || c == dnlib.DotNet.Emit.Code.Ldc_I8 ||
                                              c == dnlib.DotNet.Emit.Code.Ldc_R4 || c == dnlib.DotNet.Emit.Code.Ldc_R8))
                                        { onlyTrivial = false; break; }
                                    }
                                    isStub = tail && onlyTrivial;
                                }
                                cls = isStub ? "NECROBIT_STUB" : "NORMAL_IL";
                                if (isStub) stubTokens.Add(m.MDToken.ToInt32());
                            }
                            classCounts[cls] = classCounts.TryGetValue(cls, out var cc) ? cc + 1 : 1;
                        }
                    }
                }
                Console.WriteLine("[DumpAll] classification: " + string.Join(", ",
                    classCounts.OrderByDescending(kv => kv.Value).Select(kv => kv.Key + "=" + kv.Value)));
                Console.WriteLine("[DumpAll] NecroBit stubs to capture: " + stubTokens.Count);

                // 2. bootstrap so reflection sees the real bodies.
                ExitGuard.Install();
                ExitGuard.Behavior = ExitGuardBehavior.Suppress;
                var asmDa = Assembly.LoadFrom(args[1]);
                Type[] typesDa;
                try { typesDa = asmDa.GetTypes(); }
                catch (ReflectionTypeLoadException rex) { typesDa = rex.Types; }
                foreach (var t in typesDa)
                {
                    if (t == null || t.ContainsGenericParameters) continue;
                    try { System.Runtime.CompilerServices.RuntimeHelpers.RunClassConstructor(t.TypeHandle); }
                    catch { }
                }
                Console.WriteLine("[DumpAll] bootstrap executed");

                // 3. capture each stub's materialised body.
                var moduleDa = asmDa.ManifestModule;
                var rowsDa = new List<object>();
                int okDa = 0, failDa = 0;
                var failKinds = new Dictionary<string, int>();
                foreach (var token in stubTokens)
                {
                    try
                    {
                        var method = moduleDa.ResolveMethod(token);
                        var body = method.GetMethodBody();
                        if (body == null) { failDa++; failKinds["no_body"] = failKinds.TryGetValue("no_body", out var f0) ? f0 + 1 : 1; continue; }
                        var il = body.GetILAsByteArray();
                        if (il == null || il.Length == 0) { failDa++; failKinds["null_il"] = failKinds.TryGetValue("null_il", out var f1) ? f1 + 1 : 1; continue; }
                        var clauses = new List<object>();
                        foreach (var clause in body.ExceptionHandlingClauses)
                        {
                            string cn = null, ca = null;
                            try { if (clause.Flags == System.Reflection.ExceptionHandlingClauseOptions.Clause)
                                { cn = clause.CatchType.FullName; ca = clause.CatchType.Assembly.GetName().Name; } }
                            catch { }
                            clauses.Add(new { Flags = clause.Flags.ToString(), clause.TryOffset, clause.TryLength,
                                clause.HandlerOffset, clause.HandlerLength, CatchTypeName = cn, CatchTypeAssembly = ca,
                                FilterOffset = clause.Flags == System.Reflection.ExceptionHandlingClauseOptions.Filter ? clause.FilterOffset : 0 });
                        }
                        rowsDa.Add(new
                        {
                            Token = "0x" + token.ToString("X8"),
                            Name = (method.DeclaringType == null ? "?" : method.DeclaringType.FullName) + "::" + method.Name,
                            body.MaxStackSize, body.InitLocals,
                            LocalSignatureToken = "0x" + body.LocalSignatureMetadataToken.ToString("X8"),
                            LocalCount = body.LocalVariables.Count,
                            Eh = clauses, Length = il.Length, Base64 = Convert.ToBase64String(il)
                        });
                        okDa++;
                    }
                    catch (Exception ex)
                    {
                        failDa++;
                        var root = ex; while (root.InnerException != null) root = root.InnerException;
                        var key = root.GetType().Name;
                        failKinds[key] = failKinds.TryGetValue(key, out var fc) ? fc + 1 : 1;
                    }
                }
                File.WriteAllText(args[2], JsonConvert.SerializeObject(new
                {
                    Assembly = Path.GetFullPath(args[1]),
                    CapturedAt = DateTime.UtcNow.ToString("o"),
                    RuntimeVersion = Environment.Version.ToString(),
                    StubTotal = stubTokens.Count,
                    Captured = okDa,
                    Methods = rowsDa
                }, Formatting.Indented), System.Text.Encoding.UTF8);
                Console.WriteLine("[DumpAll] captured=" + okDa + " failed=" + failDa +
                    (failKinds.Count == 0 ? "" : " [" + string.Join(", ", failKinds.Select(kv => kv.Key + ":" + kv.Value)) + "]"));
                Console.WriteLine("[DumpAll] wrote " + rowsDa.Count + " body/bodies to " + args[2]);
                return 0;
            }

            // --necrobit-body-dump <exe> <out.json> <token>...  - the protection
            // bootstrap materialises the real method body into the loaded image, so
            // after running it reflection reports the decrypted IL, its local
            // signature token and its exception clauses. Dumped in the shape the
            // pipeline's NecroBit restore step already consumes.
            if (args.Length >= 4 && args[0] == "--necrobit-body-dump")
            {
                var baseDir4 = Path.GetDirectoryName(Path.GetFullPath(args[1]));
                AppDomain.CurrentDomain.AssemblyResolve += (s5, e5) =>
                {
                    var simple = new AssemblyName(e5.Name).Name;
                    foreach (var ext in new[] { ".dll", ".exe" })
                    {
                        var candidate = Path.Combine(baseDir4, simple + ext);
                        if (File.Exists(candidate))
                            return Assembly.LoadFrom(candidate);
                    }
                    return null;
                };

                ExitGuard.Install();
                ExitGuard.Behavior = ExitGuardBehavior.Suppress;
                var target4 = Assembly.LoadFrom(args[1]);
                Type[] types4;
                try { types4 = target4.GetTypes(); }
                catch (ReflectionTypeLoadException rex4) { types4 = rex4.Types; }
                foreach (var t in types4)
                {
                    if (t == null || t.ContainsGenericParameters) continue;
                    try { System.Runtime.CompilerServices.RuntimeHelpers.RunClassConstructor(t.TypeHandle); }
                    catch { }
                }
                Console.WriteLine("[NecroBody] bootstrap executed");

                var module4 = target4.ManifestModule;
                var rows = new List<object>();
                for (var i = 3; i < args.Length; i++)
                {
                    var text = args[i].StartsWith("0x", StringComparison.OrdinalIgnoreCase)
                        ? args[i].Substring(2) : args[i];
                    int token = int.Parse(text, System.Globalization.NumberStyles.HexNumber);
                    try
                    {
                        var method = module4.ResolveMethod(token);
                        var body = method.GetMethodBody();
                        var il = body.GetILAsByteArray();
                        var clauses = new List<object>();
                        foreach (var clause in body.ExceptionHandlingClauses)
                        {
                            int catchToken = 0;
                            string catchName = null;
                            string catchAssembly = null;
                            try
                            {
                                if (clause.Flags == System.Reflection.ExceptionHandlingClauseOptions.Clause)
                                {
                                    // The reflected token belongs to the module that DEFINES the
                                    // type, so it must not be resolved against the target module.
                                    // The name is what survives the trip.
                                    catchToken = clause.CatchType.MetadataToken;
                                    catchName = clause.CatchType.FullName;
                                    catchAssembly = clause.CatchType.Assembly.GetName().Name;
                                }
                            }
                            catch { }
                            clauses.Add(new
                            {
                                Flags = clause.Flags.ToString(),
                                clause.TryOffset,
                                clause.TryLength,
                                clause.HandlerOffset,
                                clause.HandlerLength,
                                CatchToken = "0x" + catchToken.ToString("X8"),
                                CatchTypeName = catchName,
                                CatchTypeAssembly = catchAssembly,
                                FilterOffset = clause.Flags == System.Reflection.ExceptionHandlingClauseOptions.Filter
                                    ? clause.FilterOffset : 0
                            });
                        }
                        rows.Add(new
                        {
                            Token = "0x" + token.ToString("X8"),
                            Name = (method.DeclaringType == null ? "?" : method.DeclaringType.FullName) +
                                   "::" + method.Name,
                            body.MaxStackSize,
                            body.InitLocals,
                            LocalSignatureToken = "0x" + body.LocalSignatureMetadataToken.ToString("X8"),
                            LocalCount = body.LocalVariables.Count,
                            Eh = clauses,
                            Length = il.Length,
                            Base64 = Convert.ToBase64String(il)
                        });
                        Console.WriteLine("[NecroBody] 0x" + token.ToString("X8") + " " +
                                          method.Name + " il=" + il.Length +
                                          " locals=" + body.LocalVariables.Count +
                                          " maxstack=" + body.MaxStackSize +
                                          " eh=" + clauses.Count);
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine("[NecroBody] 0x" + token.ToString("X8") + " FAILED: " + ex.Message);
                    }
                }

                File.WriteAllText(args[2], JsonConvert.SerializeObject(new
                {
                    Assembly = Path.GetFullPath(args[1]),
                    CapturedAt = DateTime.UtcNow.ToString("o"),
                    RuntimeVersion = Environment.Version.ToString(),
                    Methods = rows
                }, Formatting.Indented), System.Text.Encoding.UTF8);
                Console.WriteLine("[NecroBody] wrote " + rows.Count + " body/bodies to " + args[2]);
                return 0;
            }

            // --dump-il <exe> <token>  - emits the method body exactly as the runtime
            // sees it, for byte-level structural comparison against the VM stream.
            if (args.Length >= 3 && args[0] == "--dump-il")
            {
                var baseDir3 = Path.GetDirectoryName(Path.GetFullPath(args[1]));
                AppDomain.CurrentDomain.AssemblyResolve += (s4, e4) =>
                {
                    var simple = new AssemblyName(e4.Name).Name;
                    foreach (var ext in new[] { ".dll", ".exe" })
                    {
                        var candidate = Path.Combine(baseDir3, simple + ext);
                        if (File.Exists(candidate))
                            return Assembly.LoadFrom(candidate);
                    }
                    return null;
                };
                var loaded3 = Assembly.LoadFrom(args[1]);
                if (string.Equals(Environment.GetEnvironmentVariable("KRYPTON_DUMP_IL_INIT"), "1",
                        StringComparison.Ordinal))
                {
                    // Let the protection bootstrap run first: if it rewrites method
                    // bodies in the loaded image, reflection will show the real IL.
                    ExitGuard.Install();
                    ExitGuard.Behavior = ExitGuardBehavior.Suppress;
                    Type[] all;
                    try { all = loaded3.GetTypes(); }
                    catch (ReflectionTypeLoadException rex) { all = rex.Types; }
                    foreach (var t in all)
                    {
                        if (t == null || t.ContainsGenericParameters) continue;
                        try { System.Runtime.CompilerServices.RuntimeHelpers.RunClassConstructor(t.TypeHandle); }
                        catch { }
                    }
                    Console.WriteLine("(bootstrap executed before dumping)");
                }
                var module3 = loaded3.ManifestModule;
                for (var i = 2; i < args.Length; i++)
                {
                    var text = args[i].StartsWith("0x", StringComparison.OrdinalIgnoreCase)
                        ? args[i].Substring(2) : args[i];
                    int token = int.Parse(text, System.Globalization.NumberStyles.HexNumber);
                    MethodBase method;
                    System.Reflection.MethodBody body;
                    byte[] il;
                    try
                    {
                        method = module3.ResolveMethod(token);
                        body = method.GetMethodBody();
                        il = body == null ? null : body.GetILAsByteArray();
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine("METHOD 0x" + token.ToString("X8") + " <unreadable: " +
                                          ex.GetType().Name + ">");
                        Console.WriteLine("IL ");
                        continue;
                    }
                    if (il == null)
                    {
                        Console.WriteLine("METHOD 0x" + token.ToString("X8") + " " +
                                          (method.DeclaringType == null ? "?" : method.DeclaringType.FullName) +
                                          "::" + method.Name + " <no body>");
                        Console.WriteLine("IL ");
                        continue;
                    }
                    Console.WriteLine("METHOD 0x" + token.ToString("X8") + " " +
                                      (method.DeclaringType == null ? "?" : method.DeclaringType.FullName) +
                                      "::" + method.Name);
                    Console.WriteLine("MAXSTACK " + body.MaxStackSize);
                    Console.WriteLine("LOCALSIG 0x" + body.LocalSignatureMetadataToken.ToString("X8") +
                                      " count=" + body.LocalVariables.Count +
                                      " initLocals=" + body.InitLocals);
                    foreach (var local in body.LocalVariables)
                        Console.WriteLine("LOCAL " + local.LocalIndex + " " + local.LocalType.FullName);
                    foreach (var clause in body.ExceptionHandlingClauses)
                    {
                        string caught = "-";
                        try { if (clause.Flags == System.Reflection.ExceptionHandlingClauseOptions.Clause) caught = clause.CatchType.FullName; }
                        catch { }
                        Console.WriteLine("EH " + clause.Flags + " " + clause.TryOffset + " " + clause.TryLength +
                                          " " + clause.HandlerOffset + " " + clause.HandlerLength + " " + caught);
                    }
                    Console.WriteLine("IL " + BitConverter.ToString(il).Replace("-", ""));
                }
                return 0;
            }

            // --validate-methods <exe> <token> [token...]  - reports the emitted body as
            // the runtime itself sees it, then forces a JIT compile. Reporting only.
            if (args.Length >= 3 && args[0] == "--validate-methods")
            {
                var baseDir2 = Path.GetDirectoryName(Path.GetFullPath(args[1]));
                AppDomain.CurrentDomain.AssemblyResolve += (s3, e3) =>
                {
                    var simple = new AssemblyName(e3.Name).Name;
                    foreach (var ext in new[] { ".dll", ".exe" })
                    {
                        var candidate = Path.Combine(baseDir2, simple + ext);
                        if (File.Exists(candidate))
                            return Assembly.LoadFrom(candidate);
                    }
                    return null;
                };

                var module2 = Assembly.LoadFrom(args[1]).ManifestModule;
                int bad = 0;
                for (var i = 2; i < args.Length; i++)
                {
                    var text = args[i].StartsWith("0x", StringComparison.OrdinalIgnoreCase)
                        ? args[i].Substring(2) : args[i];
                    int token = int.Parse(text, System.Globalization.NumberStyles.HexNumber);
                    var method = module2.ResolveMethod(token);
                    var name = (method.DeclaringType == null ? "?" : method.DeclaringType.Name) + "::" + method.Name;
                    try
                    {
                        var body = method.GetMethodBody();
                        var il = body.GetILAsByteArray();
                        Console.WriteLine(name);
                        Console.WriteLine("  ilBytes=" + il.Length +
                                          " maxstack=" + body.MaxStackSize +
                                          " initLocals=" + body.InitLocals +
                                          " locals=" + body.LocalVariables.Count +
                                          " ehClauses=" + body.ExceptionHandlingClauses.Count);
                        foreach (var local in body.LocalVariables)
                            Console.WriteLine("    local V_" + local.LocalIndex + " : " + local.LocalType.FullName);
                        foreach (var clause in body.ExceptionHandlingClauses)
                        {
                            var kind = clause.Flags.ToString();
                            string caught = "";
                            try { if (clause.Flags == System.Reflection.ExceptionHandlingClauseOptions.Clause) caught = " catch=" + clause.CatchType.FullName; }
                            catch { }
                            Console.WriteLine("    eh " + kind +
                                              " try=[" + clause.TryOffset + "," + (clause.TryOffset + clause.TryLength) + ")" +
                                              " handler=[" + clause.HandlerOffset + "," + (clause.HandlerOffset + clause.HandlerLength) + ")" +
                                              caught);
                        }
                        System.Runtime.CompilerServices.RuntimeHelpers.PrepareMethod(method.MethodHandle);
                        Console.WriteLine("  JIT: ACCEPTED");
                    }
                    catch (Exception ex)
                    {
                        var root = ex;
                        while (root.InnerException != null) root = root.InnerException;
                        Console.WriteLine(name + "  FAILED: " + root.GetType().Name + ": " + root.Message);
                        bad++;
                    }
                }
                Console.WriteLine("failures: " + bad);
                return bad == 0 ? 0 : 3;
            }

            // --inspect-member <exe> <token>...  - dnlib raw view of a MemberRef /
            // TypeSpec / MethodSpec (parent, name, full signature, scopes). Diagnostics
            // only; used to see how a reconstructed reference actually serialized.
            if (args.Length >= 3 && args[0] == "--inspect-member")
            {
                var dnm = dnlib.DotNet.ModuleDefMD.Load(args[1]);
                for (int ai = 2; ai < args.Length; ai++)
                {
                    var txt = args[ai].StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? args[ai].Substring(2) : args[ai];
                    uint tok = uint.Parse(txt, System.Globalization.NumberStyles.HexNumber);
                    Console.WriteLine("== 0x" + tok.ToString("X8"));
                    try
                    {
                        var mt = new dnlib.DotNet.MDToken(tok);
                        object obj = dnm.ResolveToken(tok);
                        if (obj is dnlib.DotNet.MemberRef mr)
                        {
                            Console.WriteLine("  MemberRef name=" + mr.Name);
                            Console.WriteLine("  class/parent=" + (mr.Class?.ToString() ?? "?") +
                                "  parentScope=" + (mr.Class is dnlib.DotNet.ITypeDefOrRef td ? (td.Scope?.ScopeName ?? "?") : "?"));
                            Console.WriteLine("  sig=" + mr.Signature);
                            if (mr.MethodSig != null)
                            {
                                Console.WriteLine("  retType=" + mr.MethodSig.RetType + "  (scope=" +
                                    ScopeOf(mr.MethodSig.RetType) + ")  etype=" + mr.MethodSig.RetType.ElementType);
                                if (mr.MethodSig.RetType is dnlib.DotNet.GenericInstSig gis)
                                {
                                    Console.WriteLine("    genDef=" + gis.GenericType + " defEtype=" + gis.GenericType.ElementType + " defScope=" + ScopeOf(gis.GenericType));
                                    foreach (var ga in gis.GenericArguments)
                                        Console.WriteLine("    arg=" + ga + " etype=" + ga.ElementType + " scope=" + ScopeOf(ga));
                                }
                                for (int p = 0; p < mr.MethodSig.Params.Count; p++)
                                    Console.WriteLine("  param[" + p + "]=" + mr.MethodSig.Params[p] +
                                        "  (scope=" + ScopeOf(mr.MethodSig.Params[p]) + ")");
                            }
                        }
                        else Console.WriteLine("  " + obj?.GetType().Name + ": " + obj);
                    }
                    catch (Exception ex) { Console.WriteLine("  <error: " + ex.Message + ">"); }
                }
                return 0;
            }

            // --standalone-check <exe>  - loads the restored assembly, runs every
            // type initializer, and JIT-prepares every method. Reports cctor failures
            // and JIT rejections by kind. Compiles application code without running it,
            // so no network/file guard is needed for this pass.
            if (args.Length >= 2 && args[0] == "--standalone-check")
            {
                var baseDirSc = Path.GetDirectoryName(Path.GetFullPath(args[1]));
                AppDomain.CurrentDomain.AssemblyResolve += (ssc, esc) =>
                {
                    var simple = new AssemblyName(esc.Name).Name;
                    foreach (var ext in new[] { ".dll", ".exe" })
                    {
                        var candidate = Path.Combine(baseDirSc, simple + ext);
                        if (File.Exists(candidate))
                            return Assembly.LoadFrom(candidate);
                    }
                    return null;
                };
                ExitGuard.Install();
                ExitGuard.Behavior = ExitGuardBehavior.Suppress;

                Assembly asmSc;
                try { asmSc = Assembly.LoadFrom(args[1]); }
                catch (Exception ex)
                {
                    Console.WriteLine("LOAD FAILED: " + ex.GetType().Name + ": " + ex.Message);
                    return 1;
                }
                Console.WriteLine("LOAD OK: " + asmSc.FullName);

                Type[] typesSc;
                try { typesSc = asmSc.GetTypes(); }
                catch (ReflectionTypeLoadException rex)
                {
                    typesSc = rex.Types;
                    Console.WriteLine("GetTypes partial: " + (rex.LoaderExceptions?.Length ?? 0) + " loader exception(s)");
                }
                Console.WriteLine("TYPES: " + typesSc.Count(t => t != null));

                int cctorOk = 0, cctorFail = 0;
                var cctorKinds = new Dictionary<string, int>();
                foreach (var t in typesSc)
                {
                    if (t == null || t.ContainsGenericParameters) continue;
                    try
                    {
                        System.Runtime.CompilerServices.RuntimeHelpers.RunClassConstructor(t.TypeHandle);
                        cctorOk++;
                    }
                    catch (Exception ex)
                    {
                        cctorFail++;
                        var root = ex; while (root.InnerException != null) root = root.InnerException;
                        var key = root.GetType().Name;
                        cctorKinds[key] = cctorKinds.TryGetValue(key, out var c) ? c + 1 : 1;
                        Console.WriteLine("  CCTOR-FAIL " + t.FullName + " : " + root.GetType().Name +
                            " @ " + (root.TargetSite == null ? "?" : (root.TargetSite.DeclaringType?.Name + "::" + root.TargetSite.Name)) +
                            " | " + new string((root.Message ?? "").Replace((char)10, ' ').Take(60).ToArray()));
                    }
                }
                Console.WriteLine("CCTOR ok=" + cctorOk + " fail=" + cctorFail +
                    (cctorKinds.Count == 0 ? "" : " [" + string.Join(", ",
                        cctorKinds.Select(kv => kv.Key + ":" + kv.Value)) + "]"));

                int jitOk = 0, jitFail = 0;
                var jitKinds = new Dictionary<string, List<string>>();
                var jitKindTotals = new Dictionary<string, int>();
                foreach (var t in typesSc)
                {
                    if (t == null) continue;
                    MethodInfo[] methods;
                    try { methods = t.GetMethods(BindingFlags.Public | BindingFlags.NonPublic |
                        BindingFlags.Static | BindingFlags.Instance | BindingFlags.DeclaredOnly); }
                    catch { continue; }
                    foreach (var m in methods)
                    {
                        if (m.IsAbstract || m.ContainsGenericParameters ||
                            (m.DeclaringType != null && m.DeclaringType.ContainsGenericParameters))
                            continue;
                        try
                        {
                            System.Runtime.CompilerServices.RuntimeHelpers.PrepareMethod(m.MethodHandle);
                            jitOk++;
                        }
                        catch (Exception ex)
                        {
                            jitFail++;
                            var root = ex; while (root.InnerException != null) root = root.InnerException;
                            var key = root.GetType().Name;
                            jitKindTotals[key] = jitKindTotals.TryGetValue(key, out var kt) ? kt + 1 : 1;
                            if (!jitKinds.TryGetValue(key, out var lst)) { lst = new List<string>(); jitKinds[key] = lst; }
                            if (lst.Count < 6) lst.Add((m.DeclaringType?.Name ?? "?") + "::" + m.Name);
                        }
                    }
                }
                Console.WriteLine("JIT ok=" + jitOk + " fail=" + jitFail);
                foreach (var kv in jitKindTotals.OrderByDescending(x=>x.Value))
                    Console.WriteLine("  " + kv.Key + " total=" + kv.Value + " e.g. " + string.Join(", ", jitKinds.TryGetValue(kv.Key, out var ex) ? ex : new List<string>()));
                return jitFail == 0 && cctorFail == 0 ? 0 : 2;
            }

            // --prepare-methods <exe> <token> [token...]  - forces the CLR to JIT each
            // method without running it. The JIT rejects malformed IL, so acceptance
            // validates decode, stack, branch targets, EH, locals, maxstack and tokens.
            if (args.Length >= 3 && args[0] == "--prepare-methods")
            {
                var baseDir = Path.GetDirectoryName(Path.GetFullPath(args[1]));
                AppDomain.CurrentDomain.AssemblyResolve += (s2, e2) =>
                {
                    var simple = new AssemblyName(e2.Name).Name;
                    foreach (var ext in new[] { ".dll", ".exe" })
                    {
                        var candidate = Path.Combine(baseDir, simple + ext);
                        if (File.Exists(candidate))
                            return Assembly.LoadFrom(candidate);
                    }
                    return null;
                };

                var module = Assembly.LoadFrom(args[1]).ManifestModule;
                int failures = 0;
                for (var i = 2; i < args.Length; i++)
                {
                    var text = args[i].StartsWith("0x", StringComparison.OrdinalIgnoreCase)
                        ? args[i].Substring(2) : args[i];
                    int token;
                    if (!int.TryParse(text, System.Globalization.NumberStyles.HexNumber, null, out token))
                    {
                        Console.WriteLine(args[i] + " : unparsable");
                        failures++;
                        continue;
                    }
                    string label = "0x" + token.ToString("X8");
                    try
                    {
                        var method = module.ResolveMethod(token);
                        label += " " + (method.DeclaringType == null ? "?" : method.DeclaringType.Name) +
                                 "::" + method.Name;
                        System.Runtime.CompilerServices.RuntimeHelpers.PrepareMethod(method.MethodHandle);
                        Console.WriteLine(label + " : JIT ACCEPTED");
                    }
                    catch (Exception ex)
                    {
                        var root = ex;
                        while (root.InnerException != null) root = root.InnerException;
                        Console.WriteLine(label + " : JIT REJECTED - " + root.GetType().Name + ": " + root.Message);
                        failures++;
                    }
                }
                Console.WriteLine("failures: " + failures);
                return failures == 0 ? 0 : 3;
            }

            // --resolve-tokens <exe> <token> [token...]  - prints what each metadata
            // token denotes, so VM operands can be read without guessing.
            if (args.Length >= 3 && args[0] == "--resolve-tokens")
            {
                var module = System.Reflection.Assembly.LoadFrom(args[1]).ManifestModule;
                for (var i = 2; i < args.Length; i++)
                {
                    var text = args[i].StartsWith("0x", StringComparison.OrdinalIgnoreCase)
                        ? args[i].Substring(2)
                        : args[i];
                    int token;
                    if (!int.TryParse(text, System.Globalization.NumberStyles.HexNumber, null, out token) &&
                        !int.TryParse(args[i], out token))
                    {
                        Console.WriteLine(args[i] + " : unparsable");
                        continue;
                    }
                    string described = null;
                    foreach (var attempt in new Func<object>[]
                             {
                                 () => module.ResolveMethod(token),
                                 () => module.ResolveField(token),
                                 () => module.ResolveType(token),
                                 () => module.ResolveMember(token)
                             })
                    {
                        try
                        {
                            var member = attempt();
                            if (member == null)
                                continue;
                            var method = member as System.Reflection.MethodBase;
                            if (method != null)
                            {
                                var info = method as System.Reflection.MethodInfo;
                                described = (method.DeclaringType == null ? "?" : method.DeclaringType.FullName) +
                                            "::" + method.Name + "(" +
                                            string.Join(", ", method.GetParameters()
                                                .Select(pi => pi.ParameterType.Name)) + ")" +
                                            " ret=" + (info == null ? "void/ctor" : info.ReturnType.Name) +
                                            (method.IsStatic ? " [static]" : " [instance]") +
                                            (method.IsVirtual ? " [virtual]" : "") +
                                            (method.IsAbstract ? " [abstract]" : "") +
                                            (method.DeclaringType != null &&
                                             typeof(Delegate).IsAssignableFrom(method.DeclaringType)
                                                ? " [delegate-type]" : "");
                            }
                            else
                            {
                                described = member.ToString();
                            }
                            break;
                        }
                        catch
                        {
                        }
                    }
                    Console.WriteLine("0x" + token.ToString("X8") + " (" + token + ") : " +
                                      (described ?? "unresolvable"));
                }
                return 0;
            }

            // --vm-exec-trace <exe> <trace.json>  - records every managed-visible
            // event during one invocation of a single virtualized method.
            if (args.Length >= 3 && args[0] == "--vm-exec-trace")
            {
                return VmExecTraceRunner.Run(args[1], args[2]);
            }

            // --necrobit-dump <exe> <necrobit-dump.json>  - extracts NecroBit runtime
            // Hashtable method bodies and maps them back to metadata method tokens.
            if (args.Length >= 3 && args[0] == "--necrobit-dump")
            {
                return NecrobitDumpRunner.Run(args[1], args[2]);
            }

            // --dump-fields <exe> <fields.json> [metadata-token...]
            if (args.Length >= 3 && args[0] == "--dump-fields")
            {
                return RuntimeValueRunner.DumpFields(args);
            }

            // --eval-strings <exe> <strings.json> [decoder-token] <index...>
            if (args.Length >= 4 && args[0] == "--eval-strings")
            {
                return RuntimeValueRunner.EvaluateStrings(args);
            }

            if (args.Length < 2)
            {
                Console.Error.WriteLine("Usage: Krypton.Runner.exe <protected-exe> <output-dump.json>");
                Console.Error.WriteLine("       Krypton.Runner.exe --diag <protected-exe>");
                Console.Error.WriteLine("       Krypton.Runner.exe --payload-trace <protected-exe> <payload-trace.json>");
                Console.Error.WriteLine("       Krypton.Runner.exe --necrobit-dump <protected-exe> <necrobit-dump.json>");
                Console.Error.WriteLine("       Krypton.Runner.exe --dump-fields <protected-exe> <fields.json> [metadata-token...]");
                Console.Error.WriteLine("       Krypton.Runner.exe --eval-strings <protected-exe> <strings.json> [decoder-token] <index...>");
                return 1;
            }

            string targetPath = args[0];
            string outputPath = args[1];

            if (!File.Exists(targetPath))
            {
                Console.Error.WriteLine($"[Runner] File not found: {targetPath}");
                return 1;
            }

            try
            {
                var runner = new AssemblyRunner(targetPath);
                var dump   = runner.Run();

                // Write DynamicMethod dump immediately — before attempting form snapshot
                // (form snapshot runs in a child process and may call Environment.Exit).
                string json = JsonConvert.SerializeObject(dump, Formatting.Indented);
                File.WriteAllText(outputPath, json, System.Text.Encoding.UTF8);

                Console.WriteLine();
                Console.WriteLine($"[Runner] Dump written to: {outputPath}");
                Console.WriteLine($"[Runner] Methods captured: {dump.Methods.Count}");

                // Attempt form snapshot in a child process so that NET Reactor's
                // Environment.Exit() calls don't kill us.
                string formsPath = outputPath + ".forms.json";
                Console.WriteLine("[Runner] Attempting form snapshot via child process...");
                bool snapshotOk = RunChildSnapshot(targetPath, formsPath);

                if (snapshotOk && File.Exists(formsPath))
                {
                    // Merge forms into main dump
                    string formsJson = File.ReadAllText(formsPath);
                    var forms = JsonConvert.DeserializeObject<List<FormEntry>>(formsJson);
                    if (forms != null && forms.Count > 0)
                    {
                        dump.Forms = forms;
                        // Re-write dump with forms included
                        File.WriteAllText(outputPath,
                            JsonConvert.SerializeObject(dump, Formatting.Indented),
                            System.Text.Encoding.UTF8);
                        Console.WriteLine($"[Runner] Form snapshots merged: {forms.Count}");
                    }
                    File.Delete(formsPath);
                }
                else
                {
                    Console.WriteLine("[Runner] Form snapshot unavailable (protected form may call Environment.Exit).");
                }

                return 0;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[Runner] Fatal error: {ex}");
                return 2;
            }
        }

        private static bool RunChildSnapshot(string targetPath, string formsPath)
        {
            try
            {
                string exePath = System.Reflection.Assembly.GetExecutingAssembly().Location;
                var psi = new System.Diagnostics.ProcessStartInfo
                {
                    FileName        = exePath,
                    Arguments       = $"--snapshot \"{targetPath}\" \"{formsPath}\"",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError  = true,
                };
                using (var p = System.Diagnostics.Process.Start(psi))
                {
                    string stdout = p.StandardOutput.ReadToEnd();
                    string stderr = p.StandardError.ReadToEnd();
                    p.WaitForExit(15000); // 15 second timeout

                    if (!string.IsNullOrWhiteSpace(stdout))
                        foreach (var line in stdout.Split('\n'))
                            if (!string.IsNullOrWhiteSpace(line))
                                Console.WriteLine("[ChildRunner] " + line.TrimEnd());

                    if (!string.IsNullOrWhiteSpace(stderr))
                        foreach (var line in stderr.Split('\n'))
                            if (!string.IsNullOrWhiteSpace(line))
                                Console.Error.WriteLine("[ChildRunner/err] " + line.TrimEnd());

                    return p.ExitCode == 0;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[Runner] Child snapshot process error: {ex.Message}");
                return false;
            }
        }

        private static int RunFormSnapshot(string targetPath, string outputPath)
        {
            if (!File.Exists(targetPath))
            {
                Console.Error.WriteLine($"[Snapshot] File not found: {targetPath}");
                return 1;
            }

            try
            {
                // Install Harmony patches BEFORE loading the assembly — NET Reactor may
                // call Environment.Exit at any point from here on (cctors, ctor, etc.).
                ExitGuard.Install();
                ExitGuard.Behavior = ExitGuardBehavior.Suppress;

                var baseDir = Path.GetDirectoryName(targetPath);
                AppDomain.CurrentDomain.AssemblyResolve += (s, e) =>
                {
                    var name = new AssemblyName(e.Name).Name;
                    var p    = Path.Combine(baseDir, name + ".dll");
                    return File.Exists(p) ? System.Reflection.Assembly.LoadFrom(p) : null;
                };

                var assembly = System.Reflection.Assembly.LoadFrom(targetPath);

                // Trigger .cctors so bootstrap runs and installs all hooks
                Type[] types;
                try { types = assembly.GetTypes(); }
                catch (ReflectionTypeLoadException ex) { types = ex.Types; }

                foreach (var t in types)
                {
                    if (t == null || t.ContainsGenericParameters) continue;
                    try { System.Runtime.CompilerServices.RuntimeHelpers.RunClassConstructor(t.TypeHandle); }
                    catch { /* expected */ }
                }

                // Capture form snapshots (may call Environment.Exit — that's OK here)
                var forms = new List<FormEntry>();
                if (string.Equals(
                        Environment.GetEnvironmentVariable("KRYPTON_RUNNER_SNAPSHOT_ENTRYPOINT"),
                        "1",
                        StringComparison.Ordinal))
                {
                    forms = FormSnapshot.CaptureFromEntryPoint(assembly);
                }

                if (forms.Count == 0 || forms.TrueForAll(IsEmptyFormSnapshot))
                    forms = FormSnapshot.CaptureAll(assembly);
                string json = JsonConvert.SerializeObject(forms, Formatting.Indented);
                File.WriteAllText(outputPath, json, System.Text.Encoding.UTF8);
                Console.WriteLine($"[Snapshot] Wrote {forms.Count} form(s) to {outputPath}");
                return 0;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[Snapshot] Error: {ex}");
                return 2;
            }
        }

        private static bool IsEmptyFormSnapshot(FormEntry form)
        {
            if (form == null) return true;
            if (form.Controls != null && form.Controls.Count > 0) return false;
            if (!string.IsNullOrEmpty(form.Text)) return false;
            if ((form.ClientWidth ?? 0) > 0 || (form.ClientHeight ?? 0) > 0) return false;
            return true;
        }
    }
}
