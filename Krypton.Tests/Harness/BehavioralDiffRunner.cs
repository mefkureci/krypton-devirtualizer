using System;
using System.Diagnostics;
using System.Text;

namespace Krypton.Tests.Harness
{
    public sealed class BehavioralDiffResult
    {
        public bool MatchesBaseline { get; set; }
        public int? OriginalExitCode { get; set; }
        public int? DevirtualizedExitCode { get; set; }
        public string OriginalStdout { get; set; }
        public string DevirtualizedStdout { get; set; }
        public string Explanation { get; set; } = string.Empty;
    }

    /// <summary>
    /// Executes an original assembly and its devirtualized counterpart with identical
    /// arguments, each in its own process with a hard timeout, and diffs exit code + stdout.
    /// Used by SampleRegressionTests for console/library samples where full execution is safe
    /// and deterministic - real behavioral evidence against the original, not just a structural
    /// check of the output (see Krypton.Runner's --standalone-check for that).
    /// </summary>
    public static class BehavioralDiffRunner
    {
        public static BehavioralDiffResult Run(
            string originalPath,
            string devirtualizedPath,
            string[] args,
            TimeSpan timeout)
        {
            var argString = args == null ? string.Empty : string.Join(" ", args);
            return RunProcesses(originalPath, argString, devirtualizedPath, argString, timeout);
        }

        internal static BehavioralDiffResult RunProcesses(
            string originalExe,
            string originalArgs,
            string devirtualizedExe,
            string devirtualizedArgs,
            TimeSpan timeout)
        {
            var (originalExit, originalStdout) = RunOne(originalExe, originalArgs, timeout);
            var (devirtualizedExit, devirtualizedStdout) = RunOne(devirtualizedExe, devirtualizedArgs, timeout);

            var result = new BehavioralDiffResult
            {
                OriginalExitCode = originalExit,
                DevirtualizedExitCode = devirtualizedExit,
                OriginalStdout = originalStdout,
                DevirtualizedStdout = devirtualizedStdout,
            };

            if (originalExit == null || devirtualizedExit == null)
            {
                result.MatchesBaseline = false;
                result.Explanation = "one or both processes failed to start or timed out";
                return result;
            }

            if (originalExit != devirtualizedExit)
            {
                result.MatchesBaseline = false;
                result.Explanation = $"exit code differs: original={originalExit}, devirtualized={devirtualizedExit}";
                return result;
            }

            if (!string.Equals(originalStdout, devirtualizedStdout, StringComparison.Ordinal))
            {
                result.MatchesBaseline = false;
                result.Explanation = "stdout differs";
                return result;
            }

            result.MatchesBaseline = true;
            result.Explanation = "match";
            return result;
        }

        private static (int? exitCode, string stdout) RunOne(string exePath, string args, TimeSpan timeout)
        {
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = exePath,
                    Arguments = args,
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true,
                };

                using var proc = Process.Start(psi);
                if (proc == null)
                    return (null, null);

                var stdout = new StringBuilder();
                proc.OutputDataReceived += (_, e) => { if (e.Data != null) stdout.AppendLine(e.Data); };
                proc.BeginOutputReadLine();

                if (!proc.WaitForExit((int)timeout.TotalMilliseconds))
                {
                    try { proc.Kill(); } catch { /* best effort */ }
                    return (null, stdout.ToString());
                }

                return (proc.ExitCode, stdout.ToString());
            }
            catch
            {
                return (null, null);
            }
        }
    }
}
