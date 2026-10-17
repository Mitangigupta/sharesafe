param(
    [Parameter(Mandatory=$true)]
    [string]$ImagePath
)

try {
    Add-Type -AssemblyName System.Runtime.WindowsRuntime
    [Windows.Media.Ocr.OcrEngine, Windows.Foundation, ContentType = WindowsRuntime] | Out-Null
    [Windows.Graphics.Imaging.BitmapDecoder, Windows.Foundation, ContentType = WindowsRuntime] | Out-Null
    [Windows.Storage.StorageFile, Windows.Foundation, ContentType = WindowsRuntime] | Out-Null

    $asTask = ([System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object { $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1' })[0]
    function Await($asyncOp, $type) {
        $m = $asTask.MakeGenericMethod($type)
        $t = $m.Invoke($null, @($asyncOp))
        $t.Wait()
        return $t.Result
    }

    $fullPath = [System.IO.Path]::GetFullPath($ImagePath)
    $f = Await ([Windows.Storage.StorageFile]::GetFileFromPathAsync($fullPath)) ([Windows.Storage.StorageFile])
    $stream = Await ($f.OpenAsync([Windows.Storage.FileAccessMode]::Read)) ([Windows.Storage.Streams.IRandomAccessStream])
    $dec = Await ([Windows.Graphics.Imaging.BitmapDecoder]::CreateAsync($stream)) ([Windows.Graphics.Imaging.BitmapDecoder])
    $bmp = Await ($dec.GetSoftwareBitmapAsync()) ([Windows.Graphics.Imaging.SoftwareBitmap])
    $engine = [Windows.Media.Ocr.OcrEngine]::TryCreateFromUserProfileLanguages()
    if (-not $engine) {
        $avail = [Windows.Media.Ocr.OcrEngine]::AvailableRecognizerLanguages
        if ($avail -and $avail.Count -gt 0) {
            $engine = [Windows.Media.Ocr.OcrEngine]::TryCreateFromLanguage($avail[0])
        }
    }
    if (-not $engine) {
        Write-Output "[]"
        exit 0
    }
    $ocrRes = Await ($engine.RecognizeAsync($bmp)) ([Windows.Media.Ocr.OcrResult])

    $wordsList = [System.Collections.Generic.List[object]]::new()
    $lineIdx = 1
    foreach ($line in $ocrRes.Lines) {
        foreach ($w in $line.Words) {
            $wordsList.Add(@{
                text = $w.Text
                bbox = @([int][Math]::Round($w.BoundingRect.X), [int][Math]::Round($w.BoundingRect.Y), [int][Math]::Round($w.BoundingRect.Width), [int][Math]::Round($w.BoundingRect.Height))
                conf = 95.0
                line_num = $lineIdx
                block_num = 1
            })
        }
        $lineIdx++
    }
    $wordsList | ConvertTo-Json -Compress
} catch {
    Write-Output "[]"
}
