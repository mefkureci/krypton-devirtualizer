using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection.PortableExecutable;
using Krypton.Core;
using Krypton.Pipeline;
using Krypton.Tests.Harness;
using Xunit;

namespace Krypton.Tests
{
    public class SampleRegressionTests
    {
        [Fact]
        [Trait("Category", "Regression")]
        public void Devirtualize_KnownSamples_WhenAvailable()
        {
            var samplePaths = DiscoverSamplePaths();
            if (samplePaths.Count == 0)
                return;

            var repoRoot = ResolveRepoRoot();
            var runnerPath = FindRunnerExecutable(repoRoot);

            foreach (var samplePath in samplePaths)
            {
                var options = new DevirtualizationOptions(samplePath, new TestLogger())
                {
                    StrictDiagnostics = false
                };
                var ctx = new DevirtualizationCtx(options);
                var devirtualizer = new Devirtualizer(ctx);

                devirtualizer.Devirtualize();

                Assert.NotNull(ctx.VirtualizedMethods);
                Assert.True(ctx.VirtualizedMethods.Count > 0, $"No VM methods found for sample: {samplePath}");

                if (!File.Exists(options.OutPath))
                    continue; // nothing to structurally/behaviorally check without an output file

                if (runnerPath != null)
                {
                    var structuralOk = RunStandaloneCheck(runnerPath, options.OutPath);
                    Assert.True(structuralOk, $"--standalone-check reported load/cctor/JIT failures for {options.OutPath}");
                }

                if (!IsGuiAssembly(ctx.Module))
                {
                    var diff = BehavioralDiffRunner.Run(samplePath, options.OutPath, Array.Empty<string>(), TimeSpan.FromSeconds(15));
                    Assert.True(diff.MatchesBaseline, $"Behavioral diff failed for {samplePath}: {diff.Explanation}");
                }
            }
        }

        private static string ResolveRepoRoot()
        {
            var baseDir = AppContext.BaseDirectory;
            return Path.GetFullPath(Path.Combine(baseDir, "..", "..", "..", "..", ".."));
        }

        private static string FindRunnerExecutable(string repoRoot)
        {
            var candidates = new[]
            {
                Path.Combine(repoRoot, "Krypton.Runner", "bin", "Release", "net48", "Krypton.Runner.exe"),
                Path.Combine(repoRoot, "Krypton.Runner", "bin", "Debug", "net48", "Krypton.Runner.exe"),
            };
            return candidates.Select(Path.GetFullPath).FirstOrDefault(File.Exists);
        }

        // Runs Krypton.Runner's own --standalone-check (loads the assembly, runs every type
        // initializer, JIT-prepares every method) - the CLR is the real oracle for whether
        // recompiled IL is valid, so this is preferred over re-simulating verification rules.
        private static bool RunStandaloneCheck(string runnerPath, string targetPath)
        {
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = runnerPath,
                    Arguments = $"--standalone-check \"{targetPath}\"",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true,
                };
                using var proc = Process.Start(psi);
                if (proc == null)
                    return false;
                proc.WaitForExit(60_000);
                return proc.HasExited && proc.ExitCode == 0;
            }
            catch
            {
                return false;
            }
        }

        private static bool IsGuiAssembly(AsmResolver.DotNet.ModuleDefinition module)
        {
            return module.AssemblyReferences.Any(r =>
                string.Equals(r.Name, "System.Windows.Forms", StringComparison.OrdinalIgnoreCase));
        }

        private List<string> DiscoverSamplePaths()
        {
            var knownSamples = new[]
            {
                "Crackme.exe",
                "awesome_msil.exe",
                "Offline_sales_bills_msil.exe",
                "WindowsFormsApplication41.exe"
            };

            var baseDir = AppContext.BaseDirectory;
            var repoRoot = Path.GetFullPath(Path.Combine(baseDir, "..", "..", "..", "..", ".."));
            var workspaceRoot = Path.GetFullPath(Path.Combine(repoRoot, ".."));

            var candidates = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                repoRoot,
                workspaceRoot
            };

            var results = new List<string>();
            foreach (var root in candidates)
            {
                foreach (var sampleName in knownSamples)
                {
                    var path = Path.Combine(root, sampleName);
                    if (!File.Exists(path))
                        continue;
                    if (!IsManagedAssembly(path))
                        continue;
                    if (!results.Contains(path, StringComparer.OrdinalIgnoreCase))
                        results.Add(path);
                }
            }

            return results;
        }

        private bool IsManagedAssembly(string path)
        {
            try
            {
                using var stream = File.OpenRead(path);
                using var peReader = new PEReader(stream, PEStreamOptions.LeaveOpen);
                return peReader.HasMetadata;
            }
            catch
            {
                return false;
            }
        }

        private sealed class TestLogger : ILogger
        {
            public void Success(string message)
            {
            }

            public void Warning(string message)
            {
            }

            public void Error(string message)
            {
            }

            public void Info(string message)
            {
            }

            public void InfoStr(string message, string message2)
            {
            }
        }
    }
}
