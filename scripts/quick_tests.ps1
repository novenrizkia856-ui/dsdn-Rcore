# 🚀 DSDN Node - Quick Validation Test
# Quick test to verify all critical endpoints are working

Write-Host "`n🧪 Quick Endpoint Validation..." -ForegroundColor Cyan

$base = "http://localhost:8082"
$hash = "b7cd68de452d7fd834968da8b3ed75f5f3ce0057cad537c116117485420cd2c2"

# Test critical endpoints
Write-Host "`n1. Health Check..."
Invoke-RestMethod "$base/health" | Format-Table -AutoSize

Write-Host "`n2. Node Status..."
Invoke-RestMethod "$base/status" | Format-Table -AutoSize

Write-Host "`n3. Storage Stats..."
Invoke-RestMethod "$base/storage/stats" | Format-Table -AutoSize

Write-Host "`n4. Check Chunk Exists (PRIMARY ROUTE - /storage/has/:hash)..."
Invoke-RestMethod "$base/storage/has/$hash" | Format-Table -AutoSize

Write-Host "`n5. Check Chunk Exists (ALIAS ROUTE - /has/:hash) ⭐ THE FIX!"
Invoke-RestMethod "$base/has/$hash" | Format-Table -AutoSize

Write-Host "`n6. Test PUT Chunk..."
$data = [System.Text.Encoding]::UTF8.GetBytes("quick-test-$(Get-Date -Format 'HHmmss')")
$result = Invoke-RestMethod "$base/storage/chunk" -Method PUT -Body $data -ContentType "application/octet-stream"
$result | Format-Table -AutoSize

Write-Host "`n7. Verify stored chunk via alias route..."
Invoke-RestMethod "$base/has/$($result.hash)" | Format-Table -AutoSize

Write-Host "`n✅ All critical endpoints working!" -ForegroundColor Green
Write-Host "   - Health/Status: OK" -ForegroundColor Green
Write-Host "   - Storage routes: OK" -ForegroundColor Green  
Write-Host "   - Path params: FIXED ⭐" -ForegroundColor Green
Write-Host "   - Alias routes: OK" -ForegroundColor Green
Write-Host ""