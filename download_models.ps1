# Download face-api.js model weights from the official GitHub repository.
# Run this script once from the root of your webapp folder:
#   cd F:\projects\QR-based Attendance\webapp
#   .\download_models.ps1

$BASE = "https://raw.githubusercontent.com/justadudewhohacks/face-api.js/master/weights"
$DEST = "public\models"

# Create models directory if it doesn't exist
New-Item -ItemType Directory -Force -Path $DEST | Out-Null
Write-Host "Downloading face-api.js model weights to $DEST ..." -ForegroundColor Cyan

$FILES = @(
    # Tiny Face Detector (fast, lightweight)
    "tiny_face_detector_model-weights_manifest.json",
    "tiny_face_detector_model-shard1",
    # Face Landmark 68 points (needed for blink detection)
    "face_landmark_68_model-weights_manifest.json",
    "face_landmark_68_model-shard1",
    # Face Recognition (128-D descriptor generation)
    "face_recognition_model-weights_manifest.json",
    "face_recognition_model-shard1",
    "face_recognition_model-shard2"
)

$success = $true
foreach ($f in $FILES) {
    $url = "$BASE/$f"
    $out = "$DEST\$f"
    Write-Host "  Downloading $f ..." -NoNewline
    try {
        Invoke-WebRequest -Uri $url -OutFile $out -UseBasicParsing -ErrorAction Stop
        $size = [math]::Round((Get-Item $out).Length / 1KB, 1)
        Write-Host " OK ($size KB)" -ForegroundColor Green
    } catch {
        Write-Host " FAILED: $_" -ForegroundColor Red
        $success = $false
    }
}

if ($success) {
    Write-Host "`nAll models downloaded successfully!" -ForegroundColor Green
    Write-Host "Total size: $([math]::Round((Get-ChildItem $DEST | Measure-Object -Property Length -Sum).Sum / 1MB, 1)) MB"
    Write-Host "`nNext step: Deploy with 'npm run deploy'" -ForegroundColor Cyan
} else {
    Write-Host "`nSome downloads failed. Check your internet connection and try again." -ForegroundColor Yellow
}
