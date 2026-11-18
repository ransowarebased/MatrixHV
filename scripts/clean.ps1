#requires -Version 5.1

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Low')]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ProjectRoot = Split-Path -Parent $PSScriptRoot
$BuildRoot = Join-Path $ProjectRoot 'builds'

if (Test-Path -LiteralPath $BuildRoot -PathType Container) {
    if ($PSCmdlet.ShouldProcess($BuildRoot, 'Remove all build artifacts')) {
        $Directory = Get-Item -LiteralPath $BuildRoot -Force
        if (($Directory.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -or
            (Get-ChildItem -LiteralPath $BuildRoot -Force -Recurse -Attributes ReparsePoint | Select-Object -First 1)) {
            throw "Refusing to clean a build tree with reparse points: $BuildRoot"
        }
        Get-ChildItem -LiteralPath $BuildRoot -Force | ForEach-Object {
            Remove-Item -LiteralPath $_.FullName -Recurse -Force
        }
        Write-Host "Cleaned build artifacts: $BuildRoot"
    }
}
else {
    if ($PSCmdlet.ShouldProcess($BuildRoot, 'Create build root')) {
        New-Item -ItemType Directory -Path $BuildRoot -Force | Out-Null
        Write-Host "Created build root: $BuildRoot"
    }
}
