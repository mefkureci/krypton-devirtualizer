param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Debug"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$repoRoot = $PSScriptRoot

function Invoke-DotNet {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Command,

        [Parameter(Mandatory = $true)]
        [string[]]$Arguments
    )

    & dotnet $Command @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "dotnet $Command failed with exit code $LASTEXITCODE."
    }
}

Invoke-DotNet restore @((Join-Path $repoRoot "Krypton.Core\Krypton.Core.csproj"))
Invoke-DotNet restore @((Join-Path $repoRoot "Krypton.Pipeline\Krypton.Pipeline.csproj"))
# Workaround for intermittent static-graph restore/build failures on Krypton.csproj.
Invoke-DotNet msbuild @((Join-Path $repoRoot "Krypton\Krypton.csproj"), "/t:Restore", "/m:1")

Invoke-DotNet build @((Join-Path $repoRoot "Krypton.Core\Krypton.Core.csproj"), "-c", $Configuration, "--no-restore")
Invoke-DotNet build @((Join-Path $repoRoot "Krypton.Pipeline\Krypton.Pipeline.csproj"), "-c", $Configuration, "--no-restore")
Invoke-DotNet msbuild @((Join-Path $repoRoot "Krypton\Krypton.csproj"), "/t:Build", "/p:Configuration=$Configuration", "/m:1")

# Krypton.Runner is a .NET Framework host that Krypton launches as a child
# process: it runs the protected assembly and reports what it observes, which is
# what the NecroBit dumper and the runtime-field opcode solver read. It is not a
# project reference, so nothing pulled it into this build or dropped it next to
# Krypton.dll -- and when it is missing those stages go quiet instead of failing,
# which is exactly the kind of silence that costs an afternoon.
Invoke-DotNet restore @((Join-Path $repoRoot "Krypton.Runner\Krypton.Runner.csproj"))
Invoke-DotNet build @((Join-Path $repoRoot "Krypton.Runner\Krypton.Runner.csproj"), "-c", $Configuration, "--no-restore")

$runnerOut = Join-Path $repoRoot (Join-Path "Krypton.Runner\bin" (Join-Path $Configuration "net48"))
$hostOut = Join-Path $repoRoot (Join-Path "Krypton\bin" (Join-Path $Configuration "net8.0"))
if ((Test-Path $runnerOut) -and (Test-Path $hostOut)) {
    foreach ($name in @("Krypton.Runner.exe", "Krypton.Runner.exe.config", "Krypton.Runner.pdb",
                        "dnlib.dll", "0Harmony.dll", "Newtonsoft.Json.dll")) {
        $source = Join-Path $runnerOut $name
        if (Test-Path $source) {
            Copy-Item $source $hostOut -Force
        }
    }

    Write-Host "Deployed Krypton.Runner into '$hostOut'."
}
else {
    Write-Warning "Krypton.Runner output not found; runtime-observation stages will be disabled."
}

Write-Host "Build completed for configuration '$Configuration'."
