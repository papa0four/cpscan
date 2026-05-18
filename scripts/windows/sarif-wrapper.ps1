# =============================================================================
# Invoke-PSScriptAnalyzerSarif.ps1
# Runs PSScriptAnalyzer and converts output to SARIF format for upload
# to the GitHub Security tab.
#
# Parameters:
#   -Path         Path to scan (default: ./scripts/windows)
#   -Settings     Path to PSScriptAnalyzer config file
#   -OutputPath   Path to write the SARIF report
# =============================================================================

param (
    [string]$Path = "./scripts/windows",
    [string]$Settings = "./scripts/windows/.psscriptanalyzerconfig",
    [string]$OutputPath = "psscriptanalyzer.sarif"
)

# -----------------------------------------------------------------------------
# Run PSScriptAnalyzer
# -----------------------------------------------------------------------------
$results = Invoke-ScriptAnalyzer `
    -Path $Path `
    -Recurse `
    -Severity Error, Warning `
    -Settings $Settings

# -----------------------------------------------------------------------------
# Build SARIF rule index from findings
# -----------------------------------------------------------------------------
$ruleMap = @{}
foreach ($result in $results) {
    if (-not $ruleMap.ContainsKey($result.RuleName)) {
        $ruleMap[$result.RuleName] = @{
            id               = $result.RuleName
            name             = $result.RuleName
            shortDescription = @{ text = $result.RuleName }
            defaultConfiguration = @{
                level = if ($result.Severity -eq "Error") { "error" } else { "warning" }
            }
        }
    }
}

# -----------------------------------------------------------------------------
# Build SARIF results array
# -----------------------------------------------------------------------------
$sarifResults = @()
foreach ($result in $results) {
    # Normalize path to forward slashes relative to repo root
    $relativePath = $result.ScriptPath -replace [regex]::Escape((Get-Location).Path + "\"), ""
    $relativePath = $relativePath -replace "\\", "/"

    $sarifResults += @{
        ruleId  = $result.RuleName
        level   = if ($result.Severity -eq "Error") { "error" } else { "warning" }
        message = @{ text = $result.Message }
        locations = @(
            @{
                physicalLocation = @{
                    artifactLocation = @{
                        uri       = $relativePath
                        uriBaseId = "%SRCROOT%"
                    }
                    region = @{
                        startLine   = $result.Line
                        startColumn = $result.Column
                    }
                }
            }
        )
    }
}

# -----------------------------------------------------------------------------
# Assemble and write SARIF document
# -----------------------------------------------------------------------------
$analyzerVersion = (Get-Module PSScriptAnalyzer -ListAvailable |
    Select-Object -First 1).Version.ToString()

$sarif = @{
    version  = "2.1.0"
    '$schema' = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
    runs     = @(
        @{
            tool    = @{
                driver = @{
                    name    = "PSScriptAnalyzer"
                    version = $analyzerVersion
                    rules   = @($ruleMap.Values)
                }
            }
            results = $sarifResults
        }
    )
}

$sarif | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutputPath -Encoding utf8
Write-Host "[+] SARIF report written to $OutputPath"

# -----------------------------------------------------------------------------
# Fail the job if any findings exist
# -----------------------------------------------------------------------------
if ($results.Count -gt 0) {
    $results | Format-Table RuleName, Severity, ScriptName, Line, Message -AutoSize
    Write-Error "PSScriptAnalyzer found $($results.Count) issue(s)."
    exit 1
}

Write-Host "[+] PSScriptAnalyzer passed with no issues."