param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string] $SourcePng,
    [string] $ResourceDirectory = (Join-Path $PSScriptRoot 'app\src\main\res')
)

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing
$sourcePath = (Resolve-Path -LiteralPath $SourcePng).Path
$resRoot = (Resolve-Path -LiteralPath $ResourceDirectory).Path
$source = [System.Drawing.Bitmap]::FromFile($sourcePath)

function New-IconPath {
    $p = [System.Drawing.Drawing2D.GraphicsPath]::new()
    $p.StartFigure()
    $p.AddLine(54, 21, 79, 30)
    $p.AddLine(79, 30, 78, 52)
    $p.AddBezier(78, 52, 77, 67, 68, 80, 54, 87)
    $p.AddBezier(54, 87, 40, 80, 31, 67, 30, 52)
    $p.AddLine(30, 52, 29, 30)
    $p.AddLine(29, 30, 54, 21)
    $p.CloseFigure()
    return $p
}

try {
    if ($source.Width -lt 1000 -or $source.Height -lt 1000) {
        throw "Approved PNG is unexpectedly small ($($source.Width)x$($source.Height)); refusing an imprecise crop."
    }
    $sx = $source.Width / 1254.0
    $sy = $source.Height / 1254.0
    $rect = [System.Drawing.Rectangle]::new(
        [int][Math]::Round(220 * $sx), [int][Math]::Round(802 * $sy),
        [int][Math]::Round(820 * $sx), [int][Math]::Round(190 * $sy))
    $wordmark = $source.Clone($rect, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    try {
        for ($y = 0; $y -lt $wordmark.Height; $y++) {
            for ($x = 0; $x -lt $wordmark.Width; $x++) {
                $px = $wordmark.GetPixel($x, $y)
                $darkBackground = [Math]::Max($px.R, [Math]::Max($px.G, $px.B)) -lt 58
                $outerRingCorner = ($x -gt 790 -and $y -gt 175)
                if ($darkBackground -or $outerRingCorner) {
                    $wordmark.SetPixel($x, $y, [System.Drawing.Color]::Transparent)
                }
            }
        }
        $wordmarkDirectory = Join-Path $resRoot 'drawable-nodpi'
        New-Item -ItemType Directory -Path $wordmarkDirectory -Force | Out-Null
        $wordmark.Save((Join-Path $wordmarkDirectory 'logo_wordmark.png'),
            [System.Drawing.Imaging.ImageFormat]::Png)
    } finally { $wordmark.Dispose() }

    $densities = @(
        @{Name='mipmap-mdpi'; Size=48}, @{Name='mipmap-hdpi'; Size=72},
        @{Name='mipmap-xhdpi'; Size=96}, @{Name='mipmap-xxhdpi'; Size=144},
        @{Name='mipmap-xxxhdpi'; Size=192}
    )
    foreach ($entry in $densities) {
        $size = [int]$entry.Size
        $bitmap = [System.Drawing.Bitmap]::new($size, $size, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
        $g = [System.Drawing.Graphics]::FromImage($bitmap)
        $outer = $null; $inner = $null; $red = $null; $dark = $null; $white = $null; $break = $null
        try {
            $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
            $g.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
            $g.Clear([System.Drawing.Color]::FromArgb(255, 16, 17, 22))
            $g.ScaleTransform($size / 108.0, $size / 108.0)
            $outer = New-IconPath
            $inner = [System.Drawing.Drawing2D.GraphicsPath]::new()
            $inner.StartFigure()
            $inner.AddLine(54, 29, 72, 35); $inner.AddLine(72, 35, 71, 52)
            $inner.AddBezier(71, 52, 70, 63, 63, 73, 54, 78)
            $inner.AddBezier(54, 78, 45, 73, 38, 63, 37, 52)
            $inner.AddLine(37, 52, 36, 35); $inner.AddLine(36, 35, 54, 29); $inner.CloseFigure()
            $red = [System.Drawing.SolidBrush]::new([System.Drawing.Color]::FromArgb(255, 229, 34, 43))
            $dark = [System.Drawing.SolidBrush]::new([System.Drawing.Color]::FromArgb(255, 21, 22, 27))
            $white = [System.Drawing.Pen]::new([System.Drawing.Color]::White, 5.5)
            $white.StartCap = [System.Drawing.Drawing2D.LineCap]::Round
            $white.EndCap = [System.Drawing.Drawing2D.LineCap]::Round
            $white.LineJoin = [System.Drawing.Drawing2D.LineJoin]::Round
            $break = [System.Drawing.Pen]::new([System.Drawing.Color]::FromArgb(255, 229, 34, 43), 5.5)
            $break.StartCap = [System.Drawing.Drawing2D.LineCap]::Round
            $break.EndCap = [System.Drawing.Drawing2D.LineCap]::Round
            $g.FillPath($red, $outer); $g.FillPath($dark, $inner)
            $g.DrawLine($white, 46, 50, 52, 44)
            $g.DrawBezier($white, 52, 44, 56, 40, 62, 40, 66, 44)
            $g.DrawBezier($white, 66, 44, 70, 48, 69, 54, 65, 58)
            $g.DrawLine($white, 65, 58, 61, 62); $g.DrawLine($white, 47, 53, 42, 58)
            $g.DrawBezier($white, 42, 58, 38, 62, 38, 67, 42, 71)
            $g.DrawBezier($white, 42, 71, 46, 75, 52, 74, 56, 70)
            $g.DrawLine($white, 56, 70, 62, 64); $g.DrawLine($break, 51, 51, 58, 59)
            foreach ($fileName in @('ic_launcher.png', 'ic_launcher_round.png')) {
                $bitmap.Save((Join-Path (Join-Path $resRoot $entry.Name) $fileName),
                    [System.Drawing.Imaging.ImageFormat]::Png)
            }
        } finally {
            if ($outer) { $outer.Dispose() }; if ($inner) { $inner.Dispose() }
            if ($red) { $red.Dispose() }; if ($dark) { $dark.Dispose() }
            if ($white) { $white.Dispose() }; if ($break) { $break.Dispose() }
            $g.Dispose(); $bitmap.Dispose()
        }
    }
} finally { $source.Dispose() }

Write-Output "Generated wordmark and launcher PNGs from approved branding into $resRoot"
