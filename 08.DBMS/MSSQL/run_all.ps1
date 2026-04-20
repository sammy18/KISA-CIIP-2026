# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.1
# @Last Updated: 2026-03-31
# ============================================================================
# MSSQL Database Vulnerability Assessment - All Check Runner
# ============================================================================

#Requires -Version 5.1

$ErrorActionPreference = 'Stop'

# Script information
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$LIB_DIR = Join-Path $SCRIPT_DIR "..\lib"
$CATEGORY = "DBMS"
$PLATFORM = "MSSQL"

# Load library
. "${LIB_DIR}\result_manager.ps1"

# Set environment variable for run_all mode
$env:POWERSHELL_RUNALL_MODE = "1"

# Array to store results
$results = @()
$totalItems = 26
$completedItems = 0
$goodCount = 0
$vulnCount = 0
$manualCount = 0
$naCount = 0

# Function to display progress
function Show-Progress {
    param(
        [int]$Current,
        [int]$Total,
        [string]$ItemId
    )
    $percent = [math]::Round(($Current / $Total) * 100, 1)
    Write-Host "`r[$percent%] 진단 중: $itemId ($Current/$Total)" -NoNewline
}

# Get all check scripts
$checkScripts = Get-ChildItem -Path $SCRIPT_DIR -Filter "D*_check.ps1" | Sort-Object Name

if ($checkScripts.Count -eq 0) {
    Write-Error "점검 스크립트를 찾을 수 없습니다."
    exit 1
}

Write-Host "============================================================"
Write-Host "KISA-CIIP-2026 MSSQL 취약점 진단 - 전체 항목"
Write-Host "============================================================"
Write-Host "카테고리: $CATEGORY"
Write-Host "플랫폼: $PLATFORM"
Write-Host "진단 항목: $($checkScripts.Count)개"
Write-Host "시작 시간: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Host "============================================================"
Write-Host ""

# Initialize text file
$TXT_FILE = Initialize-RunallTextFile -Category $CATEGORY -Platform $PLATFORM -ScriptDir $SCRIPT_DIR

# Run each check script
foreach ($script in $checkScripts) {
    $completedItems++
    Show-Progress -Current $completedItems -Total $totalItems -ItemId $script.Name

    try {
        # Run the script and capture output
        $output = & $script.FullName 2>&1 | Out-String

        # Try to parse JSON from output
        $jsonLine = $output | Select-String -Pattern '^\{.*\}$' | Select-Object -First 1

        if ($jsonLine) {
            try {
                $jsonObj = $jsonLine.Line | ConvertFrom-Json
                $results += $jsonLine.Line

                # Update counters
                switch ($jsonObj.final_result) {
                    "GOOD" { $goodCount++ }
                    "VULNERABLE" { $vulnCount++ }
                    "MANUAL" { $manualCount++ }
                    "N/A" { $naCount++ }
                }

                # Append to text file
                Append-RunallTextResult -JsonObj $jsonLine.Line -TxtFile $TXT_FILE
            }
            catch {
                # JSON parse failed, treat as error
                $naCount++
                $results += "{}"
            }
        }
        else {
            # No JSON output found
            $naCount++
            $results += "{}"
        }
    }
    catch {
        $naCount++
        $results += "{}"
    }
}

Write-Host ""
Write-Host ""

# Generate aggregated results
New-RunallAggregatedResults -Category $CATEGORY -Platform $PLATFORM -ScriptDir $SCRIPT_DIR -TotalItems $totalItems -ResultsJson $results

Write-Host ""
Write-Host "============================================================"
Write-Host "진단 완료"
Write-Host "============================================================"
Write-Host "총 항목: $totalItems"
Write-Host "양호: $goodCount"
Write-Host "취약: $vulnCount"
Write-Host "수동진단: $manualCount"
Write-Host "N/A: $naCount"
if ($totalItems -gt 0) {
    $goodRate = [math]::Round(($goodCount * 100.0) / $totalItems, 1)
    Write-Host "양호율: $goodRate%"
}
Write-Host "종료 시간: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Host "============================================================"

exit 0
