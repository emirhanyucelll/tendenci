# Şifreleme scripti - Save as: encrypt.ps1
$desktopPath = [Environment]::GetFolderPath("Desktop")
$inputFile = Join-Path $desktopPath "test.txt"
$outputFile = Join-Path $desktopPath "test_encrypted.txt"

# Şifre belirle
$password = "selamlar"

# Dosya var mı kontrol et
if (-not (Test-Path $inputFile)) {
    Write-Host "HATA: $inputFile bulunamadı!" -ForegroundColor Red
    Write-Host "Lütfen Desktop'ta test.txt dosyası oluşturun." -ForegroundColor Yellow
    exit
}

try {
    # 1. Dosya içeriğini oku
    $fileContent = Get-Content $inputFile -Raw -Encoding UTF8
    
    # 2. AES şifreleme için gerekli ayarlar
    $salt = [byte[]]::new(16)
    [Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($salt)
    
    # 3. Password'den key türet (PBKDF2)
    $key = New-Object Security.Cryptography.Rfc2898DeriveBytes(
        $password, 
        $salt, 
        10000,  # iteration count
        [Security.Cryptography.HashAlgorithmName]::SHA256
    )
    
    $aesKey = $key.GetBytes(32)  # 256-bit key
    $aesIV = $key.GetBytes(16)   # 128-bit IV
    
    # 4. AES şifreleme
    $aes = [Security.Cryptography.Aes]::Create()
    $aes.Key = $aesKey
    $aes.IV = $aesIV
    
    $encryptor = $aes.CreateEncryptor()
    $memoryStream = New-Object IO.MemoryStream
    $cryptoStream = New-Object Security.Cryptography.CryptoStream(
        $memoryStream, 
        $encryptor, 
        [Security.Cryptography.CryptoStreamMode]::Write
    )
    
    # 5. Şifrele
    $streamWriter = New-Object IO.StreamWriter($cryptoStream)
    $streamWriter.Write($fileContent)
    $streamWriter.Close()
    $cryptoStream.Close()
    
    $encryptedData = $memoryStream.ToArray()
    $memoryStream.Close()
    
    # 6. Salt + şifreli veriyi birleştir
    $finalData = $salt + $encryptedData
    
    # 7. Base64'e çevir ve kaydet
    $base64Encrypted = [Convert]::ToBase64String($finalData)
    $base64Encrypted | Out-File $outputFile -Encoding UTF8
    
    Write-Host "✓ Şifreleme başarılı!" -ForegroundColor Green
    Write-Host "Orijinal dosya: $inputFile" -ForegroundColor Cyan
    Write-Host "Şifreli dosya: $outputFile" -ForegroundColor Cyan
    Write-Host "Şifre: selamlar" -ForegroundColor Yellow
    Write-Host "" -ForegroundColor Yellow
    Write-Host "NOT: Orijinal test.txt dosyası silinmedi." -ForegroundColor Gray
    
} catch {
    Write-Host "HATA: $_" -ForegroundColor Red
}
