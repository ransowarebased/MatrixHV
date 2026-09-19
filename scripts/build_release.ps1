#requires -Version 5.1

[CmdletBinding()]
param(
    [switch]$SkipImage,

    [switch]$SkipPackage,

    [string]$VeraCryptEfiSource
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$BuildScript = Join-Path $PSScriptRoot 'buildauto.ps1'
& $BuildScript -Configuration Release -SkipImage:$SkipImage -SkipPackage:$SkipPackage -VeraCryptEfiSource $VeraCryptEfiSource
