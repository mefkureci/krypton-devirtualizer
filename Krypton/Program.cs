using System;
using Krypton.Core;
using Krypton.Pipeline;
using Console = Colorful.Console;

namespace Krypton
{
    internal class Program
    {
        public static Version CurrentVersion = new Version("1.0.0");

        private static void Main(string[] args)
        {
            var logger = new ConsoleLogger();
            Console.Title = $"Krypton - {CurrentVersion}";
            Environment.ExitCode = 0;

            var launchArguments = ParseArguments(args);
            var pauseOnExit = launchArguments.PauseOnExit;

            try
            {
                if (launchArguments.ShowHelp)
                {
                    WriteUsage(logger, isError: false);
                    return;
                }

                if (string.IsNullOrWhiteSpace(launchArguments.InputPath))
                {
                    WriteUsage(logger, isError: true);
                    Environment.ExitCode = 1;
                    return;
                }

                LogBuildProvenance(logger);

                var opts = new DevirtualizationOptions(launchArguments.InputPath, logger)
                {
                    StrictDiagnostics = launchArguments.StrictDiagnostics
                };
                var ctx = new DevirtualizationCtx(opts);

                var devirtualizer = new Devirtualizer(ctx);
                devirtualizer.Devirtualize();
                if (!devirtualizer.InventoryOnlyCompleted)
                    devirtualizer.Save();
            }
            catch (Exception ex)
            {
                logger.Error($"Krypton failed: {ex.Message}");
                if (string.Equals(Environment.GetEnvironmentVariable("KRYPTON_LOG_EXCEPTIONS"), "1", StringComparison.Ordinal))
                    logger.Error(ex.ToString());
                Environment.ExitCode = 1;
            }
            finally
            {
                if (pauseOnExit)
                {
                    Console.WriteLine();
                    Console.WriteLine("Press any key to close...");
                    Console.ReadKey(intercept: true);
                }
            }
        }

        // A silently stale binary produces experiment results that look real and
        // are not. Print exactly which pipeline build is running so a run can
        // always be tied back to the code that produced it.
        private static void LogBuildProvenance(ConsoleLogger logger)
        {
            try
            {
                var assembly = typeof(Pipeline.Devirtualizer).Assembly;
                var path = assembly.Location;
                if (string.IsNullOrEmpty(path) || !System.IO.File.Exists(path))
                    return;

                var info = new System.IO.FileInfo(path);
                string hash;
                using (var stream = System.IO.File.OpenRead(path))
                using (var sha = System.Security.Cryptography.SHA256.Create())
                {
                    hash = BitConverter.ToString(sha.ComputeHash(stream)).Replace("-", string.Empty).Substring(0, 16);
                }

                logger.Info($"Pipeline build: {info.Name} | {info.LastWriteTimeUtc:yyyy-MM-dd HH:mm:ss}Z | sha256:{hash.ToLowerInvariant()}");
            }
            catch
            {
                // Provenance is diagnostic only; never let it stop a run.
            }
        }

        private static LauncherArguments ParseArguments(string[] args)
        {
            var parsed = new LauncherArguments
            {
                PauseOnExit = !string.Equals(
                    Environment.GetEnvironmentVariable("KRYPTON_NO_PAUSE"),
                    "1",
                    StringComparison.Ordinal)
            };

            foreach (var arg in args ?? Array.Empty<string>())
            {
                if (string.Equals(arg, "--help", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(arg, "-h", StringComparison.OrdinalIgnoreCase))
                {
                    parsed.ShowHelp = true;
                    parsed.PauseOnExit = false;
                    continue;
                }

                if (string.Equals(arg, "--no-pause", StringComparison.OrdinalIgnoreCase))
                {
                    parsed.PauseOnExit = false;
                    continue;
                }

                if (string.Equals(arg, "--strict-diagnostics", StringComparison.OrdinalIgnoreCase))
                {
                    parsed.StrictDiagnostics = true;
                    continue;
                }

                if (!arg.StartsWith("--", StringComparison.Ordinal) &&
                    string.IsNullOrWhiteSpace(parsed.InputPath))
                {
                    parsed.InputPath = arg;
                }
            }

            return parsed;
        }

        private static void WriteUsage(ConsoleLogger logger, bool isError)
        {
            const string usage = "Usage: Krypton.exe <input-assembly> [--strict-diagnostics] [--no-pause] [--help]";
            if (isError)
                logger.Error(usage);
            else
                logger.Info(usage);
        }

        private sealed class LauncherArguments
        {
            public string InputPath { get; set; }
            public bool StrictDiagnostics { get; set; }
            public bool PauseOnExit { get; set; }
            public bool ShowHelp { get; set; }
        }

    }
}
