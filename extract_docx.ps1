Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip = [System.IO.Compression.ZipFile]::OpenRead('d:\freelansing\time pass\chess extention\Formatted_API_Documentation.docx')
$entry = $zip.GetEntry('word/document.xml')
if ($entry) {
    $stream = $entry.Open()
    $reader = New-Object IO.StreamReader($stream)
    $text = $reader.ReadToEnd()
    $reader.Close()
    $stream.Close()
    $clean = $text -replace '<[^>]+>', ' ' -replace '\s+', ' '
    Write-Output $clean
}
$zip.Dispose()
