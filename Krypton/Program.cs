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

                var opts = new DevirtualizationOptions(launchArguments.InputPath, logger)
                {
                    StrictDiagnostics = launchArguments.StrictDiagnostics
                };
                var ctx = new DevirtualizationCtx(opts);

                var devirtualizer = new Devirtualizer(ctx);
                devirtualizer.Devirtualize();
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
