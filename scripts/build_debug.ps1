#requires -Version 5.1

[CmdletBinding()]
param(
    [switch]$SkipImage,

    [switch]$SkipPackage,

    [string]$VeraCryptEfiSource,

    [string]$VmxFlatEfiSource
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$BuildScript = Join-Path $PSScriptRoot 'buildauto.ps1'
& $BuildScript -Configuration Debug -SkipImage:$SkipImage -SkipPackage:$SkipPackage -VeraCryptEfiSource $VeraCryptEfiSource -VmxFlatEfiSource $VmxFlatEfiSource
