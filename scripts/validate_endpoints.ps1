# 🧪 DSDN Node - Comprehensive Endpoint Validation Script
# Run this script to validate all routes are working correctly

Write-Host "`n═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "   DSDN NODE ENDPOINT VALIDATION TEST SUITE" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════════`n" -ForegroundColor Cyan

$baseUrl = "http://localhost:8082"
$testHash = "b7cd68de452d7fd834968da8b3ed75f5f3ce0057cad537c116117485420cd2c2"
$passCount = 0
$failCount = 0

# Test helper function
function Test-Endpoint {
    param(
        [string]$Name,
        [string]$Url,
        [string]$Method = "GET",
        [object]$Body = $null,
        [string]$ContentType = "application/json"
    )
    
    Write-Host "`nTesting: $Name" -ForegroundColor Yellow
    Write-Host "URL: $Url" -ForegroundColor Gray
    
    try {
        if ($Method -eq "GET") {
            $response = Invoke-RestMethod -Uri $Url -Method GET -ErrorAction Stop
        } elseif ($Method -eq "PUT") {
            $response = Invoke-RestMethod -Uri $Url -Method PUT -Body $Body -ContentType $ContentType -ErrorAction Stop
        }
        
        Write-Host "✅ PASS" -ForegroundColor Green
        $script:passCount++
        
        # Show response preview
        if ($response) {
            $json = $response | ConvertTo-Json -Compress
            $preview = if ($json.Length -gt 100) { $json.Substring(0, 100) + "..." } else { $json }
            Write-Host "   Response: $preview" -ForegroundColor Gray
        }
        
        return $true
    } catch {
        Write-Host "❌ FAIL - $($_.Exception.Message)" -ForegroundColor Red
        $script:failCount++
        return $false
    }
}

# ═══════════════════════════════════════════════════════════════════════
# SECTION 1: HEALTH & OBSERVABILITY ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════

Write-Host "`n┌─────────────────────────────────────────────────────────┐" -ForegroundColor Cyan
Write-Host "│ SECTION 1: HEALTH & OBSERVABILITY ENDPOINTS            │" -ForegroundColor Cyan
Write-Host "└─────────────────────────────────────────────────────────┘" -ForegroundColor Cyan

Test-Endpoint -Name "Health Check" -Url "$baseUrl/health"
Test-Endpoint -Name "Readiness Probe" -Url "$baseUrl/ready"
Test-Endpoint -Name "Node Info" -Url "$baseUrl/info"
Test-Endpoint -Name "Node Status" -Url "$baseUrl/status"

# ═══════════════════════════════════════════════════════════════════════
# SECTION 2: STATE INSPECTION ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════

Write-Host "`n┌─────────────────────────────────────────────────────────┐" -ForegroundColor Cyan
Write-Host "│ SECTION 2: STATE INSPECTION ENDPOINTS                  │" -ForegroundColor Cyan
Write-Host "└─────────────────────────────────────────────────────────┘" -ForegroundColor Cyan

Test-Endpoint -Name "Node State" -Url "$baseUrl/state"
Test-Endpoint -Name "Fallback Status" -Url "$baseUrl/state/fallback"
Test-Endpoint -Name "Chunk Assignments" -Url "$baseUrl/state/assignments"

# ═══════════════════════════════════════════════════════════════════════
# SECTION 3: DA STATUS & METRICS
# ═══════════════════════════════════════════════════════════════════════

Write-Host "`n┌─────────────────────────────────────────────────────────┐" -ForegroundColor Cyan
Write-Host "│ SECTION 3: DA STATUS & METRICS                          │" -ForegroundColor Cyan
Write-Host "└─────────────────────────────────────────────────────────┘" -ForegroundColor Cyan

Test-Endpoint -Name "DA Status" -Url "$baseUrl/da/status"
Test-Endpoint -Name "JSON Metrics" -Url "$baseUrl/metrics"
Test-Endpoint -Name "Prometheus Metrics" -Url "$baseUrl/metrics/prometheus"

# ═══════════════════════════════════════════════════════════════════════
# SECTION 4: STORAGE ENDPOINTS (PRIMARY ROUTES)
# ═══════════════════════════════════════════════════════════════════════

Write-Host "`n┌─────────────────────────────────────────────────────────┐" -ForegroundColor Cyan
Write-Host "│ SECTION 4: STORAGE ENDPOINTS (PRIMARY ROUTES)           │" -ForegroundColor Cyan
Write-Host "└─────────────────────────────────────────────────────────┘" -ForegroundColor Cyan

Test-Endpoint -Name "Storage Stats" -Url "$baseUrl/storage/stats"
Test-Endpoint -Name "Check Chunk Exists (/storage/has/:hash)" -Url "$baseUrl/storage/has/$testHash"

# Test GET chunk (will 404 if chunk doesn't exist, that's OK)
Write-Host "`nTesting: Get Chunk (/storage/chunk/:hash)" -ForegroundColor Yellow
Write-Host "URL: $baseUrl/storage/chunk/$testHash" -ForegroundColor Gray
try {
    $response = Invoke-RestMethod -Uri "$baseUrl/storage/chunk/$testHash" -Method GET -ErrorAction Stop
    Write-Host "✅ PASS - Chunk retrieved" -ForegroundColor Green
    $script:passCount++
} catch {
    if ($_.Exception.Response.StatusCode.value__ -eq 404) {
        Write-Host "⚠️  PASS - Route works (chunk not found is expected)" -ForegroundColor Yellow
        $script:passCount++
    } else {
        Write-Host "❌ FAIL - $($_.Exception.Message)" -ForegroundColor Red
        $script:failCount++
    }
}

# Test PUT chunk
Write-Host "`nTesting: Store Chunk (PUT /storage/chunk)" -ForegroundColor Yellow
Write-Host "URL: $baseUrl/storage/chunk" -ForegroundColor Gray
try {
    $testData = [System.Text.Encoding]::UTF8.GetBytes("test-validation-data-$(Get-Date -Format 'yyyyMMddHHmmss')")
    $response = Invoke-RestMethod -Uri "$baseUrl/storage/chunk" -Method PUT -Body $testData -ContentType "application/octet-stream" -ErrorAction Stop
    Write-Host "✅ PASS - Chunk stored" -ForegroundColor Green
    Write-Host "   Hash: $($response.hash)" -ForegroundColor Gray
    Write-Host "   Size: $($response.size) bytes" -ForegroundColor Gray
    $script:passCount++
    
    # Store hash for alias tests
    $global:storedHash = $response.hash
} catch {
    Write-Host "❌ FAIL - $($_.Exception.Message)" -ForegroundColor Red
    $script:failCount++
}

# ═══════════════════════════════════════════════════════════════════════
# SECTION 5: STORAGE ENDPOINTS (ALIAS ROUTES - BACKWARD COMPATIBILITY)
# ═══════════════════════════════════════════════════════════════════════

Write-Host "`n┌─────────────────────────────────────────────────────────┐" -ForegroundColor Cyan
Write-Host "│ SECTION 5: STORAGE ALIASES (BACKWARD COMPATIBILITY)     │" -ForegroundColor Cyan
Write-Host "└─────────────────────────────────────────────────────────┘" -ForegroundColor Cyan

# Test alias routes with the hash we just stored
if ($global:storedHash) {
    Test-Endpoint -Name "Check Chunk Exists (/has/:hash) - ALIAS" -Url "$baseUrl/has/$global:storedHash"
    Test-Endpoint -Name "Get Chunk (/chunks/:hash) - ALIAS" -Url "$baseUrl/chunks/$global:storedHash"
} else {
    # Use existing hash if PUT failed
    Test-Endpoint -Name "Check Chunk Exists (/has/:hash) - ALIAS" -Url "$baseUrl/has/$testHash"
    
    Write-Host "`nTesting: Get Chunk (/chunks/:hash) - ALIAS" -ForegroundColor Yellow
    Write-Host "URL: $baseUrl/chunks/$testHash" -ForegroundColor Gray
    try {
        $response = Invoke-RestMethod -Uri "$baseUrl/chunks/$testHash" -Method GET -ErrorAction Stop
        Write-Host "✅ PASS - Chunk retrieved via alias" -ForegroundColor Green
        $script:passCount++
    } catch {
        if ($_.Exception.Response.StatusCode.value__ -eq 404) {
            Write-Host "⚠️  PASS - Alias route works (chunk not found is expected)" -ForegroundColor Yellow
            $script:passCount++
        } else {
            Write-Host "❌ FAIL - $($_.Exception.Message)" -ForegroundColor Red
            $script:failCount++
        }
    }
}

# Test PUT via alias
Write-Host "`nTesting: Store Chunk (PUT /chunks) - ALIAS" -ForegroundColor Yellow
Write-Host "URL: $baseUrl/chunks" -ForegroundColor Gray
try {
    $testData2 = [System.Text.Encoding]::UTF8.GetBytes("test-alias-data-$(Get-Date -Format 'yyyyMMddHHmmss')")
    $response = Invoke-RestMethod -Uri "$baseUrl/chunks" -Method PUT -Body $testData2 -ContentType "application/octet-stream" -ErrorAction Stop
    Write-Host "✅ PASS - Chunk stored via alias" -ForegroundColor Green
    Write-Host "   Hash: $($response.hash)" -ForegroundColor Gray
    Write-Host "   Size: $($response.size) bytes" -ForegroundColor Gray
    $script:passCount++
} catch {
    Write-Host "❌ FAIL - $($_.Exception.Message)" -ForegroundColor Red
    $script:failCount++
}

# ═══════════════════════════════════════════════════════════════════════
# SECTION 6: PATH PARAMETER VALIDATION (FIXED ROUTES)
# ═══════════════════════════════════════════════════════════════════════

Write-Host "`n┌─────────────────────────────────────────────────────────┐" -ForegroundColor Cyan
Write-Host "│ SECTION 6: PATH PARAMETER VALIDATION (THE FIX!)         │" -ForegroundColor Cyan
Write-Host "└─────────────────────────────────────────────────────────┘" -ForegroundColor Cyan

# Test various hash formats to ensure path parameter extraction works
$testHashes = @(
    "abc123",
    "test123",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    $testHash
)

foreach ($hash in $testHashes) {
    Test-Endpoint -Name "Path Param Test: /has/$($hash.Substring(0, [Math]::Min(8, $hash.Length)))..." -Url "$baseUrl/has/$hash"
}

# ═══════════════════════════════════════════════════════════════════════
# FINAL SUMMARY
# ═══════════════════════════════════════════════════════════════════════

Write-Host "`n═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "   TEST RESULTS SUMMARY" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan

$totalTests = $passCount + $failCount
$successRate = if ($totalTests -gt 0) { [math]::Round(($passCount / $totalTests) * 100, 2) } else { 0 }

Write-Host "`nTotal Tests:  $totalTests" -ForegroundColor White
Write-Host "Passed:       " -NoNewline -ForegroundColor White
Write-Host "$passCount" -ForegroundColor Green
Write-Host "Failed:       " -NoNewline -ForegroundColor White
if ($failCount -eq 0) {
    Write-Host "$failCount" -ForegroundColor Green
} else {
    Write-Host "$failCount" -ForegroundColor Red
}
Write-Host "Success Rate: " -NoNewline -ForegroundColor White
if ($successRate -eq 100) {
    Write-Host "$successRate%" -ForegroundColor Green
} elseif ($successRate -ge 80) {
    Write-Host "$successRate%" -ForegroundColor Yellow
} else {
    Write-Host "$successRate%" -ForegroundColor Red
}

Write-Host "`n" -NoNewline
if ($failCount -eq 0) {
    Write-Host "🎉 ALL TESTS PASSED! Node is working perfectly!" -ForegroundColor Green
} elseif ($successRate -ge 80) {
    Write-Host "⚠️  Most tests passed. Check failed endpoints above." -ForegroundColor Yellow
} else {
    Write-Host "❌ Multiple failures detected. Review logs above." -ForegroundColor Red
}

Write-Host "`n═══════════════════════════════════════════════════════════`n" -ForegroundColor Cyan

# Return exit code based on test results
if ($failCount -eq 0) {
    exit 0
} else {
    exit 1
}