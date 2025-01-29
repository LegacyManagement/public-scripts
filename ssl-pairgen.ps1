<#
.SYNOPSIS
  Generate a self-signed "Root CA" and an end-entity user certificate
  for mTLS authentication, using only built-in Windows PowerShell commands.

.DESCRIPTION
  This script:
    1. Prompts for Organization Name and Username.
    2. Generates a self-signed root CA certificate in the current user's store.
    3. Generates a user (child) certificate, signed by that CA.
    4. Exports:
        - Root CA cert as <username>-ca.crt
        - User cert (public key) as <username>.cer and <username>.pem
        - PKCS#12 file <username>.p12 containing the user cert + private key
          (password-protected).
    5. Places all exported files into a directory under your user profile:
         %UserProfile%\sslpair

#>

Param(
    [string]$OrgName,
    [string]$UserName
)

Write-Host "-----------------------------------------------------------"
Write-Host " Windows mTLS Certificate Generator"
Write-Host "-----------------------------------------------------------`n"

# Prompt for Organization Name if not supplied
if (-not $OrgName) {
    $OrgName = Read-Host "Please enter your Organization Name (e.g., the name of your company)"
    while ([string]::IsNullOrWhiteSpace($OrgName)) {
        Write-Host "Organization Name cannot be empty. Please try again."
        $OrgName = Read-Host "Please enter your Organization Name (e.g., the name of your company)"
    }
}

# Prompt for Username if not supplied
if (-not $UserName) {
    $UserName = Read-Host "Please enter your Username (e.g., the first part of your email address)"
    while ([string]::IsNullOrWhiteSpace($UserName)) {
        Write-Host "Username cannot be empty. Please try again."
        $UserName = Read-Host "Please enter your Username (e.g., the first part of your email address)"
    }
}

# Force Username to lowercase
$UserName = $UserName.ToLower()

# Determine the destination folder for output
$HomeDir = [Environment]::GetFolderPath("UserProfile")
$SslPairDir = Join-Path $HomeDir "sslpair"

# If the directory already exists, prompt user whether to remove it
if (Test-Path $SslPairDir) {
    Write-Host "Directory '$SslPairDir' already exists."
    $response = Read-Host "Do you want to remove it and continue? (yes/no)"
    if ($response -match '^(yes|y)$') {
        Remove-Item -Recurse -Force $SslPairDir
        Write-Host "Removed existing directory '$SslPairDir'."
    } else {
        Write-Host "Exiting without making changes."
        exit 0
    }
}

# Create the output directory
New-Item -ItemType Directory -Path $SslPairDir | Out-Null

Write-Host "`nGenerating Root CA certificate..."
# Create a self-signed Root CA certificate
$rootCA = New-SelfSignedCertificate `
    -Subject "CN=$($UserName)-privateCA, O=$OrgName" `
    -FriendlyName "$($UserName)-privateCA" `
    -CertStoreLocation "Cert:\CurrentUser\My" `
    -KeyAlgorithm RSA -KeyLength 3072 -HashAlgorithm SHA256 `
    -KeyUsageProperty All `
    -KeyUsage CertSign, CRLSign, DigitalSignature `
    -NotAfter (Get-Date).AddDays(365)  # 1 year validity

# Export the root CA as <username>-ca.crt
$rootCAPath = Join-Path $SslPairDir "$UserName-ca.crt"
Export-Certificate -Cert $rootCA -FilePath $rootCAPath | Out-Null

Write-Host "`nGenerating User certificate (signed by our new Root CA)..."
# Create the user/child certificate, signed by the Root CA
$userCert = New-SelfSignedCertificate `
    -Subject "CN=$UserName, O=$OrgName" `
    -FriendlyName "$UserName" `
    -CertStoreLocation "Cert:\CurrentUser\My" `
    -KeyAlgorithm RSA -KeyLength 2048 -HashAlgorithm SHA256 `
    -KeyUsageProperty All `
    -KeyUsage DigitalSignature, KeyEncipherment `
    -NotAfter (Get-Date).AddDays(365) `
    -Signer $rootCA `
    # Extended Key Usage: clientAuth => 1.3.6.1.5.5.7.3.2
    -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.2")

# Export the user certificate (public key only) to <username>.cer
$userCertCerPath = Join-Path $SslPairDir "$UserName.cer"
Export-Certificate -Cert $userCert -FilePath $userCertCerPath | Out-Null

# Also export the user certificate in PEM format (public key only)
$userCertPemPath = Join-Path $SslPairDir "$UserName.pem"

Write-Host "`nExporting user certificate to PEM (public cert only)..."
$rawCert = [System.Convert]::ToBase64String($userCert.RawData)
# Insert newlines after every 64 characters for PEM formatting
$certText = "-----BEGIN CERTIFICATE-----`r`n"
$certText += ($rawCert -split ".{1,64}" -join "`r`n")
$certText += "`r`n-----END CERTIFICATE-----`r`n"
Set-Content -Path $userCertPemPath -Value $certText

Write-Host "`nNow creating the PKCS#12 (.p12) file which includes your private key."
Write-Host "You will be prompted for a password to protect the .p12 file."
$pfxPassword = Read-Host "Enter the password to protect the PFX (.p12) file" -AsSecureString

$userCertP12Path = Join-Path $SslPairDir "$UserName.p12"
Export-PfxCertificate -Cert $userCert -FilePath $userCertP12Path -Password $pfxPassword -ChainOption BuildChain | Out-Null

Write-Host "`nAll done! Here’s what we created in '$SslPairDir':"
Write-Host "1. $($UserName)-ca.crt   - Root CA certificate"
Write-Host "2. $($UserName).cer       - User certificate (public key only, DER-based .cer)"
Write-Host "3. $($UserName).pem       - User certificate (public key only, in PEM format)"
Write-Host "4. $($UserName).p12       - PKCS#12 file containing the user's private key + cert"
Write-Host "                              (encrypted with the password you chose)."

Write-Host "`nUsage instructions:"
Write-Host " - Upload '$($UserName)-ca.crt' to your Kubernetes secret for ingress-nginx (auth-tls-secret)."
Write-Host " - Import '$($UserName).p12' into your browser or application (it will ask for your password)."
Write-Host " - Make sure your server side is configured to trust the CA from '$($UserName)-ca.crt'."

exit 0
