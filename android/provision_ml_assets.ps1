param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string] $AssetDirectory
)

$ErrorActionPreference = 'Stop'
$sourceRoot = (Resolve-Path -LiteralPath $AssetDirectory).Path
$destinationRoot = Join-Path $PSScriptRoot 'app\src\main\assets'
$assetNames = @('phishing_lr_v1.model', 'sms_spam_v1.model')

foreach ($name in $assetNames) {
    $source = Join-Path $sourceRoot $name
    $destination = Join-Path $destinationRoot $name
    if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
        throw "Required local asset is missing: $source"
    }
    if (Test-Path -LiteralPath $destination) {
        throw "Refusing to overwrite existing local asset: $destination"
    }
}

foreach ($name in $assetNames) {
    Copy-Item -LiteralPath (Join-Path $sourceRoot $name) -Destination $destinationRoot
}

Write-Output 'Local-only ML assets provisioned. They are ignored by Git; verify provenance before any redistribution.'
