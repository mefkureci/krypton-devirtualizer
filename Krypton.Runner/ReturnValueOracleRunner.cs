using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.Serialization;
using Newtonsoft.Json;

namespace Krypton.Runner
{
    // A VM byte with no operand and no distinctive neighbourhood cannot be told apart
    // from its siblings by any amount of static reasoning: Dup and Ldnull both leave a
    // reference where an array is wanted, Ret and Throw both end a method. What does
    // tell them apart is what the method computes -- and the protected assembly still
    // computes it, because its interpreter is intact.
    //
    // So the assignment stops being a guess and becomes a measurement: invoke the
    // original virtualized method to see what it really returns, then evaluate each
    // candidate assignment of the same VM stream and keep the ones that reproduce it.
    // Evaluation is an interpreter rather than emitted IL: a wrong candidate simply
    // throws here, where emitted IL would have to be verified first.
    internal static class ReturnValueOracleRunner
    {
        public sealed class OraclePlan
        {
            public List<OracleMethod> Methods { get; set; } = new List<OracleMethod>();
        }

        public sealed class OracleMethod
        {
            public int MethodKey { get; set; }
            public int MethodToken { get; set; }
            public List<OracleInstruction> Instructions { get; set; } = new List<OracleInstruction>();
            public List<int> LocalTypeTokens { get; set; } = new List<int>();
            public List<Dictionary<string, string>> Candidates { get; set; } =
                new List<Dictionary<string, string>>();
        }

        public sealed class OracleInstruction
        {
            public int VmByte { get; set; }
            public int Operand { get; set; }
            public bool HasOperand { get; set; }
        }

        public sealed class OracleResult
        {
            public List<OracleMethodResult> Methods { get; set; } = new List<OracleMethodResult>();
        }

        public sealed class OracleMethodResult
        {
            public int MethodKey { get; set; }
            public string ObservedValue { get; set; }
            public string ObservedError { get; set; }
            public List<int> MatchingCandidates { get; set; } = new List<int>();
            public int Evaluated { get; set; }
        }

        public static int Run(string[] args)
        {
            var targetPath = args[1];
            var outputPath = args[2];
            var planPath = args[3];

            if (!File.Exists(targetPath) || !File.Exists(planPath))
            {
                Console.Error.WriteLine("[ReturnOracle] Target or plan file not found.");
                return 1;
            }

            OraclePlan plan;
            try
            {
                plan = JsonConvert.DeserializeObject<OraclePlan>(File.ReadAllText(planPath));
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("[ReturnOracle] Plan could not be read: " + ex.Message);
                return 1;
            }

            if (plan?.Methods == null || plan.Methods.Count == 0)
            {
                Console.Error.WriteLine("[ReturnOracle] Plan contains no methods.");
                return 1;
            }

            Assembly assembly;
            try
            {
                assembly = LoadAndInitialize(targetPath);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("[ReturnOracle] Load failed: " + ex.Message);
                return 2;
            }

            var module = assembly.ManifestModule;
            var result = new OracleResult();

            foreach (var method in plan.Methods)
            {
                var row = new OracleMethodResult { MethodKey = method.MethodKey };
                result.Methods.Add(row);

                object observed;
                try
                {
                    observed = InvokeOriginal(module, method.MethodToken);
                }
                catch (Exception ex)
                {
                    row.ObservedError = Describe(ex);
                    Console.WriteLine($"[ReturnOracle] key {method.MethodKey}: original call failed ({row.ObservedError}).");
                    continue;
                }

                row.ObservedValue = Render(observed);
                Console.WriteLine($"[ReturnOracle] key {method.MethodKey}: original returns {row.ObservedValue}");

                for (var i = 0; i < method.Candidates.Count; i++)
                {
                    row.Evaluated++;
                    object produced;
                    try
                    {
                        produced = Evaluate(module, method, method.Candidates[i]);
                    }
                    catch
                    {
                        // A candidate that cannot run is a candidate that is not the
                        // answer; nothing here needs to know why.
                        continue;
                    }

                    if (ValuesMatch(observed, produced))
                        row.MatchingCandidates.Add(i);
                }

                Console.WriteLine(
                    $"[ReturnOracle] key {method.MethodKey}: {row.MatchingCandidates.Count} of {row.Evaluated} candidate(s) reproduce it.");
            }

            File.WriteAllText(outputPath, JsonConvert.SerializeObject(result, Formatting.Indented));
            Console.WriteLine("[ReturnOracle] Wrote " + outputPath);
            return 0;
        }

        private static object InvokeOriginal(Module module, int token)
        {
            var method = module.ResolveMethod(token) as MethodInfo;
            if (method == null)
                throw new InvalidOperationException("token is not a method");

            var instance = method.IsStatic ? null : CreateInstance(method.DeclaringType);
            return method.Invoke(instance, new object[0]);
        }

        // The oracle methods do not use the instance they hang off, and running a real
        // constructor here would drag in whatever the protection does at construction
        // time, so the instance is allocated without running one.
        private static object CreateInstance(Type type)
        {
            if (type == null)
                return null;
            try
            {
                return FormatterServices.GetUninitializedObject(type);
            }
            catch
            {
                return Activator.CreateInstance(type, nonPublic: true);
            }
        }

        private static object Evaluate(Module module, OracleMethod method, IDictionary<string, string> assignment)
        {
            var stack = new Stack<object>();
            var locals = new object[Math.Max(8, method.LocalTypeTokens.Count)];
            var instructions = method.Instructions;
            var steps = 0;

            for (var index = 0; index >= 0 && index < instructions.Count;)
            {
                if (++steps > 100000)
                    throw new InvalidOperationException("candidate does not terminate");

                var instruction = instructions[index];
                if (!assignment.TryGetValue(Key(instruction.VmByte), out var name))
                    throw new InvalidOperationException("byte has no value in this candidate");

                var operand = instruction.Operand;
                var next = index + 1;

                switch (name)
                {
                    case "Nop":
                        break;
                    case "Dup":
                        stack.Push(stack.Peek());
                        break;
                    case "Pop":
                        stack.Pop();
                        break;
                    case "Ldnull":
                        stack.Push(null);
                        break;
                    case "Ldc_I4":
                        stack.Push(operand);
                        break;
                    case "Ldc_I8":
                        stack.Push((long) operand);
                        break;
                    case "Ldstr":
                        // The VM stores a raw #US heap offset; ResolveString wants the
                        // token, so the string-table tag goes back on.
                        stack.Push(module.ResolveString(
                            (operand & unchecked((int) 0xFF000000)) == 0x70000000
                                ? operand
                                : 0x70000000 | operand));
                        break;
                    case "Ldtoken":
                        stack.Push(ResolveHandle(module, operand));
                        break;
                    case "Newarr":
                        stack.Push(Array.CreateInstance(module.ResolveType(operand), Convert.ToInt32(stack.Pop())));
                        break;
                    case "Ldlen":
                        stack.Push(((Array) stack.Pop()).Length);
                        break;
                    case "Stelem_Ref":
                    case "Stelem_I1":
                    case "Stelem_I2":
                    case "Stelem_I4":
                    case "Stelem_I8":
                    case "Stelem":
                    {
                        var value = stack.Pop();
                        var elementIndex = Convert.ToInt32(stack.Pop());
                        ((Array) stack.Pop()).SetValue(value, elementIndex);
                        break;
                    }

                    case "Ldelem_Ref":
                    case "Ldelem_U1":
                    case "Ldelem_I1":
                    case "Ldelem_I4":
                    case "Ldelem":
                    {
                        var elementIndex = Convert.ToInt32(stack.Pop());
                        stack.Push(((Array) stack.Pop()).GetValue(elementIndex));
                        break;
                    }

                    case "Stloc":
                        locals[operand] = stack.Pop();
                        break;
                    case "Ldloc":
                        stack.Push(locals[operand]);
                        break;

                    case "Ldsfld":
                        stack.Push(((FieldInfo) module.ResolveField(operand)).GetValue(null));
                        break;
                    case "Stsfld":
                        ((FieldInfo) module.ResolveField(operand)).SetValue(null, stack.Pop());
                        break;
                    case "Ldfld":
                        stack.Push(((FieldInfo) module.ResolveField(operand)).GetValue(stack.Pop()));
                        break;
                    case "Stfld":
                    {
                        var value = stack.Pop();
                        ((FieldInfo) module.ResolveField(operand)).SetValue(stack.Pop(), value);
                        break;
                    }

                    case "Call":
                    case "Callvirt":
                    {
                        var target = module.ResolveMethod(operand) as MethodInfo;
                        if (target == null)
                            throw new InvalidOperationException("call target is not a method");
                        var arguments = PopArguments(stack, target.GetParameters().Length);
                        var instance = target.IsStatic ? null : stack.Pop();
                        var value = target.Invoke(instance, arguments);
                        if (target.ReturnType != typeof(void))
                            stack.Push(value);
                        break;
                    }

                    case "Newobj":
                    {
                        var constructor = module.ResolveMethod(operand) as ConstructorInfo;
                        if (constructor == null)
                            throw new InvalidOperationException("newobj target is not a constructor");
                        stack.Push(constructor.Invoke(PopArguments(stack, constructor.GetParameters().Length)));
                        break;
                    }

                    case "Conv_I4":
                    case "Conv_Ovf_I4":
                    case "Conv_U4":
                        stack.Push(Convert.ToInt32(stack.Pop()));
                        break;
                    case "Conv_I8":
                    case "Conv_U8":
                        stack.Push(Convert.ToInt64(stack.Pop()));
                        break;
                    case "Conv_U1":
                        stack.Push((int) Convert.ToByte(stack.Pop()));
                        break;

                    case "Add":
                        stack.Push(Arithmetic(stack, (a, b) => a + b));
                        break;
                    case "Sub":
                        stack.Push(Arithmetic(stack, (a, b) => a - b));
                        break;
                    case "Mul":
                        stack.Push(Arithmetic(stack, (a, b) => a * b));
                        break;
                    case "Xor":
                        stack.Push(Arithmetic(stack, (a, b) => a ^ b));
                        break;
                    case "And":
                        stack.Push(Arithmetic(stack, (a, b) => a & b));
                        break;
                    case "Or":
                        stack.Push(Arithmetic(stack, (a, b) => a | b));
                        break;
                    case "Shl":
                        stack.Push(Arithmetic(stack, (a, b) => a << (int) b));
                        break;
                    case "Shr":
                        stack.Push(Arithmetic(stack, (a, b) => a >> (int) b));
                        break;
                    case "Neg":
                        stack.Push(-Convert.ToInt64(stack.Pop()));
                        break;
                    case "Not":
                        stack.Push(~Convert.ToInt64(stack.Pop()));
                        break;

                    case "Ceq":
                        stack.Push(Equals(stack.Pop(), stack.Pop()) ? 1 : 0);
                        break;

                    case "Br":
                        next = operand;
                        break;
                    case "BrTrue":
                        next = IsTrue(stack.Pop()) ? operand : index + 1;
                        break;
                    case "BrFalse":
                        next = IsTrue(stack.Pop()) ? index + 1 : operand;
                        break;

                    case "Ret":
                        return stack.Count > 0 ? stack.Pop() : null;

                    case "Throw":
                        throw new InvalidOperationException("candidate throws");

                    default:
                        throw new InvalidOperationException("opcode not modelled: " + name);
                }

                index = next;
            }

            throw new InvalidOperationException("candidate ran off the end");
        }

        private static object[] PopArguments(Stack<object> stack, int count)
        {
            var arguments = new object[count];
            for (var i = count - 1; i >= 0; i--)
                arguments[i] = stack.Pop();
            return arguments;
        }

        private static long Arithmetic(Stack<object> stack, Func<long, long, long> apply)
        {
            var right = Convert.ToInt64(stack.Pop());
            var left = Convert.ToInt64(stack.Pop());
            return apply(left, right);
        }

        private static bool IsTrue(object value)
        {
            if (value == null)
                return false;
            if (value is bool flag)
                return flag;
            try { return Convert.ToInt64(value) != 0; }
            catch { return true; }
        }

        private static object ResolveHandle(Module module, int token)
        {
            var member = module.ResolveMember(token);
            switch (member)
            {
                case Type type:
                    return type.TypeHandle;
                case FieldInfo field:
                    return field.FieldHandle;
                case MethodBase method:
                    return method.MethodHandle;
                default:
                    throw new InvalidOperationException("token is not a member");
            }
        }

        private static bool ValuesMatch(object observed, object produced)
        {
            if (observed == null || produced == null)
                return ReferenceEquals(observed, produced);
            if (observed is string left && produced is string right)
                return string.Equals(left, right, StringComparison.Ordinal);

            if (observed is Array observedArray && produced is Array producedArray)
            {
                if (observedArray.Length != producedArray.Length)
                    return false;
                for (var i = 0; i < observedArray.Length; i++)
                {
                    if (!Equals(observedArray.GetValue(i), producedArray.GetValue(i)))
                        return false;
                }

                return true;
            }

            return Equals(observed, produced);
        }

        private static string Render(object value)
        {
            switch (value)
            {
                case null:
                    return "<null>";
                case string text:
                    return text.Length > 120 ? text.Substring(0, 120) + "..." : text;
                case Array array:
                    return array.GetType().GetElementType()?.Name + "[" + array.Length + "]";
                default:
                    return Convert.ToString(value);
            }
        }

        private static string Describe(Exception ex)
        {
            var inner = (ex as TargetInvocationException)?.InnerException ?? ex;
            return inner.GetType().Name + ": " + inner.Message;
        }

        private static string Key(int vmByte) => "0x" + vmByte.ToString("X2");

        private static Assembly LoadAndInitialize(string targetPath)
        {
            ExitGuard.Install();
            ExitGuard.Behavior = ExitGuardBehavior.Suppress;

            var fullPath = Path.GetFullPath(targetPath);
            var baseDir = Path.GetDirectoryName(fullPath);
            AppDomain.CurrentDomain.AssemblyResolve += (s, e) =>
            {
                var name = new AssemblyName(e.Name).Name;
                var candidate = Path.Combine(baseDir ?? string.Empty, name + ".dll");
                return File.Exists(candidate) ? Assembly.LoadFrom(candidate) : null;
            };

            var assembly = Assembly.LoadFrom(fullPath);
            foreach (var module in assembly.Modules)
            {
                try { RuntimeHelpers.RunModuleConstructor(module.ModuleHandle); }
                catch { /* protected initializers are best effort */ }
            }

            Type[] types;
            try { types = assembly.GetTypes(); }
            catch (ReflectionTypeLoadException ex) { types = ex.Types; }

            foreach (var type in types)
            {
                if (type == null || type.ContainsGenericParameters)
                    continue;
                try { RuntimeHelpers.RunClassConstructor(type.TypeHandle); }
                catch { /* same */ }
            }

            return assembly;
        }
    }
}
