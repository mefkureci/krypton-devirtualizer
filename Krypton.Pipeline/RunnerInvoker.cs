using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace Krypton.Pipeline
{
    // Krypton.Runner is a separate net48 process: it loads the protected assembly and
    // reports what the protection computes at runtime. Both the devirtualizer and the
    // opcode mapper need it, so the launch logic lives here rather than in either one.
    internal static class RunnerInvoker
    {
        public static string FindExecutable()
        {
            var baseDir = AppContext.BaseDirectory;
            var up4 = Path.Combine(baseDir, "..", "..", "..", "..");
            var candidates = new[]
            {
                Path.Combine(baseDir, "Krypton.Runner.exe"),
                Path.Combine(up4, "Krypton.Runner", "bin", "Release", "net48", "Krypton.Runner.exe"),
                Path.Combine(up4, "Krypton.Runner", "bin", "Debug", "net48", "Krypton.Runner.exe"),
            };

            return candidates.Select(Path.GetFullPath).FirstOrDefault(File.Exists);
        }

        public static bool Invoke(
            string mode,
            string targetPath,
            string outputPath,
            string logPrefix,
            Action<string> info,
            Action<string> warn,
            string[] extraArgs = null)
        {
            var runnerPath = FindExecutable();
            if (runnerPath == null)
            {
                warn?.Invoke($"[{logPrefix}] Krypton.Runner.exe not found.");
                return false;
            }

            try
            {
                var args = new List<string> { mode, targetPath, outputPath };
                if (extraArgs != null)
                    args.AddRange(extraArgs);

                var psi = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = runnerPath,
                    Arguments = string.Join(" ", args.Select(QuoteArgument)),
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                };

                using var proc = System.Diagnostics.Process.Start(psi);
                if (proc == null)
                    return false;

                var stdout = proc.StandardOutput.ReadToEnd();
                var stderr = proc.StandardError.ReadToEnd();
                proc.WaitForExit(60_000);

                foreach (var line in stdout.Split('\n'))
                    if (!string.IsNullOrWhiteSpace(line))
                        info?.Invoke($"  [{logPrefix}] {line.TrimEnd()}");
                foreach (var line in stderr.Split('\n'))
                    if (!string.IsNullOrWhiteSpace(line))
                        warn?.Invoke($"  [{logPrefix}/err] {line.TrimEnd()}");

                return proc.ExitCode == 0 && File.Exists(outputPath);
            }
            catch (Exception ex)
            {
                warn?.Invoke($"[{logPrefix}] Runner invocation failed: {ex.Message}");
                return false;
            }
        }

        private static string QuoteArgument(string value)
        {
            if (value == null)
                return "\"\"";
            return "\"" + value.Replace("\"", "\\\"", StringComparison.Ordinal) + "\"";
        }
    }
}
