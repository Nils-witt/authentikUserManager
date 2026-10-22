#Requires -Version 5.1
using namespace System.Security.Cryptography
using namespace System.Security.Cryptography.X509Certificates

<#
.SYNOPSIS
    Keeps a client certificate of an authentik-manager service account in Cert:\LocalMachine\My.

.DESCRIPTION
    Uses the service API of authentik-manager with an API key of the service account:

    1. Looks in Cert:\LocalMachine\My for a certificate of the service account issued by the
       authentik-manager CA. Without one, it continues with step 3.
    2. Keeps that certificate while more than RenewThresholdPercent (default 10) percent of its
       lifetime remains; otherwise it continues with step 3.
    3. Creates a new non-exportable key in the machine key store, requests a certificate for it
       and stores the certificate with the key in Cert:\LocalMachine\My. Only then it revokes the
       old certificates of the service account found in the store and deletes them with their keys.

    A certificate counts as the service account's when it chains to the CA served at /pki/ca.pem
    and its serial number is among the service account's certificates on the server. Other
    certificates, including other certificates of the same CA, are never touched.

    Run it elevated (or as SYSTEM, e.g. from a scheduled task): it writes to the machine store.
    Requires Windows PowerShell 5.1 with .NET Framework 4.7.2 or later, or PowerShell 7.

.PARAMETER BaseUrl
    The URL of authentik-manager, e.g. https://am.example.com.

.PARAMETER ApiKey
    The API key (amk_...). Defaults to the AUTHENTIK_MANAGER_API_KEY environment variable.
    Prefer ApiKeyFile or the variable over the command line, which other users may see.

.PARAMETER ApiKeyFile
    A file holding the API key, e.g. readable by SYSTEM and Administrators only.

.PARAMETER RenewThresholdPercent
    The certificate is renewed once no more than this percentage of its lifetime remains.

.PARAMETER KeyAlgorithm
    The algorithm of new keys: ECDSA_P256 (default), RSA_2048 or RSA_3072.

.PARAMETER Force
    Renews the certificate even when enough of its lifetime remains.

.EXAMPLE
    .\Update-ServiceCertificate.ps1 -BaseUrl https://am.example.com -ApiKeyFile C:\ProgramData\am\api-key.txt

.EXAMPLE
    .\Update-ServiceCertificate.ps1 -BaseUrl https://am.example.com -WhatIf
    Shows what would be done, without requesting, revoking or deleting anything.
#>
[CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'Key')]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^https?://')]
    [string] $BaseUrl,

    [Parameter(ParameterSetName = 'Key')]
    [string] $ApiKey = $env:AUTHENTIK_MANAGER_API_KEY,

    [Parameter(Mandatory, ParameterSetName = 'KeyFile')]
    [string] $ApiKeyFile,

    [ValidateRange(1, 99)]
    [int] $RenewThresholdPercent = 10,

    [ValidateSet('ECDSA_P256', 'RSA_2048', 'RSA_3072')]
    [string] $KeyAlgorithm = 'ECDSA_P256',

    [switch] $Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$StorePath = 'Cert:\LocalMachine\My'

function Write-Log([string] $Message) {
    Write-Host ('{0:yyyy-MM-dd HH:mm:ss} {1}' -f (Get-Date), $Message)
}

# Invokes the service API and returns the decoded JSON response. HTTP errors become exceptions
# naming the status and the server's error message; the status is in the exception's Data.
function Invoke-ServiceApi([string] $Method, [string] $Path, $Body) {
    $request = @{
        Method          = $Method
        Uri             = $script:BaseUrl + $Path
        Headers         = @{ Authorization = "Bearer $script:ApiKey" }
        UseBasicParsing = $true
    }
    if ($null -ne $Body) {
        $request.Body = ConvertTo-Json -InputObject $Body -Compress
        $request.ContentType = 'application/json'
    }
    try {
        return Invoke-RestMethod @request
    } catch {
        $status = 0
        if ($_.Exception.PSObject.Properties['Response'] -and $_.Exception.Response) {
            $status = [int] $_.Exception.Response.StatusCode
        }
        $detail = $_.Exception.Message
        if ($_.ErrorDetails -and $_.ErrorDetails.Message) {
            try { $detail = (ConvertFrom-Json $_.ErrorDetails.Message).error } catch { $detail = $_.ErrorDetails.Message }
        }
        $err = [System.Exception]::new("$Method $Path failed ($status): $detail", $_.Exception)
        $err.Data['Status'] = $status
        throw $err
    }
}

# Returns the DER encodings of the PEM blocks labelled $Label in $Text.
function ConvertFrom-Pem([string] $Text, [string] $Label) {
    $pattern = "-----BEGIN $Label-----(.+?)-----END $Label-----"
    foreach ($m in [regex]::Matches($Text, $pattern, 'Singleline')) {
        , [Convert]::FromBase64String(($m.Groups[1].Value -replace '\s', ''))
    }
}

function ConvertTo-Pem([byte[]] $Der, [string] $Label) {
    $base64 = [Convert]::ToBase64String($Der, [Base64FormattingOptions]::InsertLineBreaks)
    "-----BEGIN $Label-----`n$base64`n-----END $Label-----`n"
}

# Returns the serial number as the server writes it: lowercase hex without leading zeros.
function Get-SerialText([X509Certificate2] $Certificate) {
    $Certificate.SerialNumber.ToLowerInvariant().TrimStart('0')
}

# Reports whether $Certificate chains to one of $CaCertificates, whether trusted or not.
function Test-IssuedBy([X509Certificate2] $Certificate, [X509Certificate2[]] $CaCertificates) {
    $chain = [X509Chain]::new()
    try {
        $chain.ChainPolicy.RevocationMode = [X509RevocationMode]::NoCheck
        $chain.ChainPolicy.VerificationFlags = [X509VerificationFlags]::AllowUnknownCertificateAuthority
        foreach ($ca in $CaCertificates) { [void] $chain.ChainPolicy.ExtraStore.Add($ca) }
        # Build fails for expired certificates too, yet still fills ChainElements.
        [void] $chain.Build($Certificate)
        $caThumbprints = $CaCertificates | ForEach-Object Thumbprint
        foreach ($element in @($chain.ChainElements) | Select-Object -Skip 1) {
            if ($caThumbprints -contains $element.Certificate.Thumbprint) { return $true }
        }
        return $false
    } finally {
        if ($chain -is [IDisposable]) { $chain.Dispose() }
    }
}

# Creates a persisted, non-exportable machine key and returns it as RSACng or ECDsaCng.
function New-MachineKey([string] $Algorithm) {
    $params = [CngKeyCreationParameters]::new()
    $params.KeyCreationOptions = [CngKeyCreationOptions]::MachineKey
    $params.ExportPolicy = [CngExportPolicies]::None
    $params.Provider = [CngProvider]::MicrosoftSoftwareKeyStorageProvider
    $name = 'authentik-manager-' + [guid]::NewGuid().ToString()
    if ($Algorithm -eq 'ECDSA_P256') {
        $params.KeyUsage = [CngKeyUsages]::Signing
        return [ECDsaCng]::new([CngKey]::Create([CngAlgorithm]::ECDsaP256, $name, $params))
    }
    $bits = [int] $Algorithm.Substring(4)
    $params.KeyUsage = [CngKeyUsages]::AllUsages
    $params.Parameters.Add([CngProperty]::new('Length', [BitConverter]::GetBytes($bits), [CngPropertyOptions]::None))
    return [RSACng]::new([CngKey]::Create([CngAlgorithm]::Rsa, $name, $params))
}

# Returns a PEM certificate signing request for $Key. The server ignores its subject.
function New-SigningRequest($Key) {
    $subject = "CN=$env:COMPUTERNAME"
    if ($Key -is [RSA]) {
        $request = [CertificateRequest]::new($subject, $Key, [HashAlgorithmName]::SHA256, [RSASignaturePadding]::Pkcs1)
    } else {
        $request = [CertificateRequest]::new($subject, $Key, [HashAlgorithmName]::SHA256)
    }
    ConvertTo-Pem $request.CreateSigningRequest() 'CERTIFICATE REQUEST'
}

# Stores $Certificate with $Key in the machine store and returns it as stored there.
function Add-CertificateWithKey([X509Certificate2] $Certificate, $Key) {
    if ($Key -is [RSA]) {
        $withKey = [RSACertificateExtensions]::CopyWithPrivateKey($Certificate, $Key)
    } else {
        $withKey = [ECDsaCertificateExtensions]::CopyWithPrivateKey($Certificate, $Key)
    }
    $withKey.FriendlyName = 'authentik-manager ' + (Get-SerialText $Certificate)
    $store = [X509Store]::new([StoreName]::My, [StoreLocation]::LocalMachine)
    $store.Open([OpenFlags]::ReadWrite)
    try { $store.Add($withKey) } finally { $store.Close() }

    # The store entry must reference the persisted key; check before old certificates go.
    $stored = Get-Item "$StorePath\$($Certificate.Thumbprint)"
    if (-not $stored.HasPrivateKey) {
        throw "the certificate $($Certificate.Thumbprint) was stored without its private key"
    }
    return $stored
}

function Remove-KeyQuietly($Key) {
    try { $Key.Key.Delete() } catch { Write-Warning "Deleting the unused key failed: $($_.Exception.Message)" }
}

# --- main -----------------------------------------------------------------------------------

if ($PSCmdlet.ParameterSetName -eq 'KeyFile') {
    $ApiKey = (Get-Content -LiteralPath $ApiKeyFile -Raw).Trim()
}
if (-not $ApiKey) {
    throw 'No API key: pass -ApiKey or -ApiKeyFile, or set AUTHENTIK_MANAGER_API_KEY.'
}
if (-not ('System.Security.Cryptography.X509Certificates.CertificateRequest' -as [type])) {
    throw 'This script needs .NET Framework 4.7.2 or later, or PowerShell 7.'
}
$BaseUrl = $BaseUrl.TrimEnd('/')
# Windows PowerShell 5.1 may not offer TLS 1.2 by default.
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

try {
    # Served as application/x-pem-file, which PowerShell may return as bytes.
    $caPem = (Invoke-WebRequest -Uri "$BaseUrl/pki/ca.pem" -UseBasicParsing).Content
    if ($caPem -is [byte[]]) { $caPem = [Text.Encoding]::ASCII.GetString($caPem) }
    $caCertificates = @(ConvertFrom-Pem $caPem 'CERTIFICATE' | ForEach-Object { [X509Certificate2]::new([byte[]] $_) })
    if ($caCertificates.Count -eq 0) { throw "$BaseUrl/pki/ca.pem holds no certificate" }

    $records = @{}
    foreach ($record in @((Invoke-ServiceApi GET '/service-api/v1/certificates').certificates)) {
        $records[$record.serial] = $record
    }

    # Step 1: the service account's certificates in the store.
    $owned = @(Get-ChildItem $StorePath | Where-Object {
            $records.ContainsKey((Get-SerialText $_)) -and (Test-IssuedBy $_ $caCertificates)
        })
    $now = Get-Date
    $usable = @($owned | Where-Object {
            $record = $records[(Get-SerialText $_)]
            $_.HasPrivateKey -and -not $record.revoked_at -and $_.NotBefore -le $now -and $_.NotAfter -gt $now
        } | Sort-Object NotAfter -Descending)

    # Step 2: keep the newest usable certificate while enough of its lifetime remains.
    if ($usable.Count -gt 0) {
        $current = $usable[0]
        $lifetime = ($current.NotAfter - $current.NotBefore).TotalSeconds
        $remainingPercent = 100 * ($current.NotAfter - $now).TotalSeconds / $lifetime
        $summary = 'Certificate {0} (serial {1}) is valid until {2:u}, {3:N1}% of its lifetime remains.' -f
        $current.Thumbprint, (Get-SerialText $current), $current.NotAfter.ToUniversalTime(), $remainingPercent
        Write-Log $summary
        if ($remainingPercent -gt $RenewThresholdPercent -and -not $Force) {
            Write-Log 'Nothing to do.'
            exit 0
        }
    } else {
        Write-Log 'No usable certificate of the service account in the store.'
    }

    # Step 3: request a new certificate, then revoke and delete the old ones.
    if (-not $PSCmdlet.ShouldProcess($StorePath, "Request a new $KeyAlgorithm certificate")) {
        foreach ($old in $owned) {
            [void] $PSCmdlet.ShouldProcess($old.Thumbprint, 'Revoke the certificate and delete it with its key')
        }
        exit 0
    }
    $key = New-MachineKey $KeyAlgorithm
    try {
        $issued = Invoke-ServiceApi POST '/service-api/v1/certificates' @{ csr = (New-SigningRequest $key) }
        $der = @(ConvertFrom-Pem $issued.certificate_pem 'CERTIFICATE')[0]
        $stored = Add-CertificateWithKey ([X509Certificate2]::new([byte[]] $der)) $key
    } catch {
        Remove-KeyQuietly $key
        throw
    }
    Write-Log ('Stored certificate {0} (serial {1}), valid until {2:u}.' -f
        $stored.Thumbprint, (Get-SerialText $stored), $stored.NotAfter.ToUniversalTime())

    $failed = $false
    foreach ($old in $owned) {
        $serial = Get-SerialText $old
        if (-not $PSCmdlet.ShouldProcess($old.Thumbprint, 'Revoke the certificate and delete it with its key')) { continue }
        try {
            if (-not $records[$serial].revoked_at) {
                try {
                    [void] (Invoke-ServiceApi POST "/service-api/v1/certificates/$serial/revoke")
                    Write-Log "Revoked certificate $serial."
                } catch {
                    # 409: it was revoked meanwhile.
                    if ($_.Exception.Data['Status'] -ne 409) { throw }
                }
            }
            Remove-Item -LiteralPath "$StorePath\$($old.Thumbprint)" -DeleteKey
            Write-Log "Deleted certificate $($old.Thumbprint) with its key."
        } catch {
            # Keep going: the new certificate is in place; the next run retries.
            Write-Warning "Removing the old certificate $serial failed: $($_.Exception.Message)"
            $failed = $true
        }
    }
    if ($failed) { exit 2 }
    exit 0
} catch {
    Write-Error -ErrorRecord $_ -ErrorAction Continue
    exit 1
}
