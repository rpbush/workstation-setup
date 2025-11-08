# Quick test script to validate DSC file downloads
# This tests the URLs without running the full installation

Write-Host "Testing DSC Configuration File Downloads..." -ForegroundColor Cyan
Write-Host ""

$dscUri = "https://raw.githubusercontent.com/rpbush/New_Computer_Setup/main/"
$dscNonAdmin = "rpbush.nonAdmin.dsc.yml"
$dscAdmin = "rpbush.dev.dsc.yml"
$dscOffice = "rpbush.office.dsc.yml"

$dscOfficeUri = $dscUri + $dscOffice
$dscNonAdminUri = $dscUri + $dscNonAdmin 
$dscAdminUri = $dscUri + $dscAdmin

$testFiles = @(
    @{Name="Office DSC"; Uri=$dscOfficeUri; File=$dscOffice},
    @{Name="NonAdmin DSC"; Uri=$dscNonAdminUri; File=$dscNonAdmin},
    @{Name="Admin/Dev DSC"; Uri=$dscAdminUri; File=$dscAdmin}
)

$allPassed = $true

foreach ($test in $testFiles) {
    Write-Host "Testing: $($test.Name)" -ForegroundColor Yellow
    Write-Host "  URL: $($test.Uri)"
    
    try {
        $response = Invoke-WebRequest -Uri $test.Uri -Method Head -ErrorAction Stop
        if ($response.StatusCode -eq 200) {
            Write-Host "  ✓ Download successful (Status: $($response.StatusCode))" -ForegroundColor Green
            
            # Try to download and check content
            try {
                $tempFile = [System.IO.Path]::GetTempFileName()
                Invoke-WebRequest -Uri $test.Uri -OutFile $tempFile -ErrorAction Stop
                $content = Get-Content $tempFile -Raw -ErrorAction Stop
                
                # Check if it's valid YAML (starts with # or properties:)
                if ($content -match '^(#|properties:)') {
                    Write-Host "  ✓ File appears to be valid YAML" -ForegroundColor Green
                    $fileSize = (Get-Item $tempFile).Length
                    Write-Host "  ✓ File size: $fileSize bytes" -ForegroundColor Green
                } else {
                    Write-Host "  ⚠ Warning: File may not be valid YAML (could be HTML error page)" -ForegroundColor Yellow
                    Write-Host "    First 200 chars: $($content.Substring(0, [Math]::Min(200, $content.Length)))" -ForegroundColor Gray
                    $allPassed = $false
                }
                
                Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
            } catch {
                Write-Host "  ✗ Failed to download and validate content: $_" -ForegroundColor Red
                $allPassed = $false
            }
        } else {
            Write-Host "  ✗ Unexpected status code: $($response.StatusCode)" -ForegroundColor Red
            $allPassed = $false
        }
    } catch {
        Write-Host "  ✗ Download failed: $_" -ForegroundColor Red
        $allPassed = $false
    }
    Write-Host ""
}

Write-Host "========================================" -ForegroundColor Cyan
if ($allPassed) {
    Write-Host "✓ All DSC file downloads validated successfully!" -ForegroundColor Green
    Write-Host "The script should work correctly." -ForegroundColor Green
} else {
    Write-Host "✗ Some downloads failed. Please check:" -ForegroundColor Red
    Write-Host "  1. Repository exists: https://github.com/rpbush/New_Computer_Setup" -ForegroundColor Yellow
    Write-Host "  2. Files exist in the main branch" -ForegroundColor Yellow
    Write-Host "  3. Repository is public (or you have access)" -ForegroundColor Yellow
}
Write-Host "========================================" -ForegroundColor Cyan

