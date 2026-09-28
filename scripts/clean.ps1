#requires -Version 5.1

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Low')]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$BuildRoot = [System.IO.Path]::GetFullPath('D:\Projetos\MatrixHV\builds')
$ExpectedBuildRoot = [System.IO.Path]::GetFullPath('D:\Projetos\MatrixHV\builds')

if (-not $BuildRoot.Equals($ExpectedBuildRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "Refusing to clean unexpected build root: $BuildRoot"
}

if (Test-Path -LiteralPath $BuildRoot -PathType Container) {
    if ($PSCmdlet.ShouldProcess($BuildRoot, 'Remove all build artifacts')) {
        Get-ChildItem -LiteralPath $BuildRoot -Force | Remove-Item -Recurse -Force
        Write-Host "Cleaned build artifacts: $BuildRoot"
    }
}
else {
    if ($PSCmdlet.ShouldProcess($BuildRoot, 'Create build root')) {
        New-Item -ItemType Directory -Path $BuildRoot -Force | Out-Null
        Write-Host "Created build root: $BuildRoot"
    }
}
