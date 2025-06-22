<#
.SYNOPSIS
    A PowerShell script containing functions to interact with a PrivateBin instance.

.DESCRIPTION
    This script provides a set of tools for creating and deleting pastes on a PrivateBin server.
    It includes functions for sending text as a new paste and for deleting an existing paste using its deletion token.
    The script handles the necessary client-side encryption (AES-256-GCM) required by the PrivateBin API (v2).

    It can use native .NET cryptographic libraries (PowerShell 7.0+) or fall back to the BouncyCastle library
    for older PowerShell versions.

.USAGE
    To use the functions in your current PowerShell session, you can "dot-source" the script file:
    . .\Send-ToPrivateBin.ps1

    After dot-sourcing, the following functions will be available:
    - Send-ToPrivateBin: Creates a new encrypted paste.
    - Remove-PrivateBinPaste: Deletes a paste.
    - ConvertTo-Base58: A helper function for URL key encoding (generally not called directly).

    Example of creating a paste:
    Send-ToPrivateBin -PrivateBinUrl "https://privatebin.net" -PasteText "This is a secret message."

    Example of creating and then deleting a paste:
    $myPaste = Send-ToPrivateBin -PrivateBinUrl "https://privatebin.net" -PasteText "This will be deleted."
    $myPaste.RemovePaste()

.NOTES
    License: This script is released under the GNU General Public License (GPL).
    Inspiration: This implementation is heavily inspired by the proposal from user lyra-edmundson
    on the PrivateBin GitHub issue: https://github.com/PrivateBin/PrivateBin/issues/827
    A warm thank you to them for their valuable contribution!
#>

function ConvertTo-Base58 {
    <#
    .SYNOPSIS
        Converts a byte array to a Base58 encoded string.
    .DESCRIPTION
        This function takes a byte array as input and converts it into a Base58 encoded string,
        which is used by PrivateBin to encode the URL secret. This is a helper function and is
        not typically called directly by the user.
    .PARAMETER v
        The byte array to be converted.
    .EXAMPLE
        PS C:\> $bytes = [System.Text.Encoding]::UTF8.GetBytes("hello")
        PS C:\> ConvertTo-Base58 -v $bytes
        Cn8eVZg
    #>
    [cmdletbinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [byte[]]$v
    )
    $alphabet = [char[]]'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    [System.Numerics.BigInteger]$x = 0
    $c = 0 # Counter for bit shifting
    for ($i = $v.Count - 1; $i -ge 0 ; $i--) {
        $x += [bigint]$v[$i] -shl (8 * $c)
        $c++
    }
    $string = ''
    while ($x -ne 0) {
        $idx = $x % $alphabet.Length # Get remainder for current Base58 digit
        $x = [System.Numerics.BigInteger]::Divide($x, $alphabet.Length) # Divide by 58 for next iteration
        $string = $alphabet[$idx] + $string
    }
    return $string
}


function Send-ToPrivateBin {
    <#
    .SYNOPSIS
        Creates a new encrypted paste on a PrivateBin instance.
    .DESCRIPTION
        This function encrypts the provided text client-side and sends it to a specified PrivateBin server.
        It handles all the necessary cryptographic operations (key derivation, encryption) according to the
        PrivateBin API v2 specification.

        The function returns a custom object containing the URL to view the paste, the deletion token,
        and other metadata. The returned object also includes helpful methods like `RemovePaste()` to easily
        delete the created paste.
    .PARAMETER PrivateBinUrl
        The base URL of the PrivateBin instance (e.g., "https://privatebin.net").
    .PARAMETER PasteText
        The text content to be encrypted and sent as a paste.
    .PARAMETER PasteSecret
        An optional password to further protect the paste. This password is combined with the
        randomly generated URL key and is never sent to the server.
    .PARAMETER PasteFormat
        The format of the paste. This determines how the content is rendered in the browser.
        Defaults to 'plaintext'.
    .PARAMETER OpenDiscussion
        If specified, enables the discussion/comment feature for the paste.
    .PARAMETER BurnAfterReading
        If specified, the paste will be deleted from the server immediately after it is read for the first time.
    .PARAMETER Expire
        Sets the expiration period for the paste. Defaults to '1hour'.
        The 'never' option creates a paste that does not expire automatically.
    .PARAMETER BouncyCastleDllPath
        For PowerShell versions older than 7.0, this parameter is required.
        It specifies the full path to the BouncyCastle.Crypto.dll file, which is used for the
        cryptographic operations. For PowerShell 7.0 and newer, native .NET libraries are used by default.
    .OUTPUTS
        [PSCustomObject]
        A custom object with the following properties:
        - ViewUrl: The full URL to view the paste, including the decryption key.
        - PrivateBinUrl: The base URL of the PrivateBin instance used.
        - deletetoken: The token required to delete the paste.
        - id: The unique identifier of the paste on the server.
        - ExpirationDateTime: A [DateTime] object indicating when the paste will expire.
        - And other metadata about the paste.

        The object also includes two methods:
        - IsExpired(): A script method that returns $true if the paste has expired.
        - RemovePaste(): A script method that calls `Remove-PrivateBinPaste` on the object itself.
    .EXAMPLE
        PS C:\> Send-ToPrivateBin -PrivateBinUrl "https://privatebin.net" -PasteText "My secret message" -Expire "1day"

        Description
        -----------
        Creates a paste with the text "My secret message" on privatebin.net that will expire in one day.
    .EXAMPLE
        PS C:\> $paste = Get-Content C:\log.txt | Out-String | Send-ToPrivateBin -PrivateBinUrl "https://myprivatebin.example.com" -PasteSecret "s3cur3Pa$$w0rd!" -BurnAfterReading

        Description
        -----------
        Takes the content of C:\log.txt, creates a burn-after-reading paste protected with a password on a custom PrivateBin instance.
        The resulting object is stored in the $paste variable.
    .EXAMPLE
        PS C:\> $paste = Send-ToPrivateBin -PrivateBinUrl "https://privatebin.net" -PasteText "This will be deleted soon."
        PS C:\> $paste.RemovePaste()

        Description
        -----------
        Creates a paste and then immediately deletes it using the RemovePaste() method on the returned object.
    .LINK
        Remove-PrivateBinPaste
    #>
    param(
        [Parameter(Mandatory)][string]
        [ValidatePattern('^https?://.+')]
        $PrivateBinUrl,
        [Parameter(Mandatory)][string]
        $PasteText,
        [Parameter()][string]
        $PasteSecret,
        [Parameter()][string]
        [ValidateSet('plaintext', 'syntaxhighlighting', 'markdown')]
        $PasteFormat = 'plaintext',
        [Parameter()][Switch]
        $OpenDiscussion,
        [Parameter()][Switch]
        $BurnAfterReading,
        [Parameter()][String]
        [ValidateSet('5min', '10min', '1hour', '1day', '1week', '1month', 'never')]
        $Expire = '1hour',
        [Parameter()][string]
        [ValidateScript({
            if (-not (Test-Path $_ -PathType Leaf)) {
                throw "The specified BouncyCastle DLL file was not found at the location: $_"
            }
            return $true
        })]
        $BouncyCastleDllPath
    )

    if ($PrivateBinUrl -notmatch '/$') {
        Write-Verbose "Adding a trailing slash to the PrivateBin URL: $PrivateBinUrl"
        $PrivateBinUrl += '/'
    }

    # --- Cryptographic Engine Selection ---
    $useBouncyCastle = $PSBoundParameters.ContainsKey('BouncyCastleDllPath')
    $minPSVersion = [Version]"7.0.0"

    if ($useBouncyCastle) {
        Write-Verbose "Using BouncyCastle library from: $BouncyCastleDllPath"
        try {
            $null = [System.Reflection.Assembly]::LoadFrom($BouncyCastleDllPath)
        }
        catch {
            throw "Could not load the BouncyCastle DLL from path '$BouncyCastleDllPath'. Error: $($_.Exception.Message)"
        }
    }
    else {
        Write-Verbose "Using native .NET cryptographic libraries."
        if ($PSVersionTable.PSVersion -lt $minPSVersion) {
            throw "This command requires PowerShell $minPSVersion or higher to use native .NET libraries. For older versions, please provide the path to the BouncyCastle DLL via the -BouncyCastleDllPath parameter."
        }
    }


    # --- Common Cryptographic Parameter Preparation ---
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create() # Random number generator

    # Generate URL secret (32 bytes)
    $urlSecret = [byte[]]::new(32)
    $null = $rng.GetBytes($urlSecret)

    # Build the passphrase (secret + password)
    if ([string]::IsNullOrEmpty($PasteSecret)) {
        $pastePassphrase = $urlSecret
    } else {
        $pwBytes = [System.Text.Encoding]::UTF8.GetBytes($PasteSecret)
        $pastePassphrase = New-Object byte[] ($urlSecret.Length + $pwBytes.Length)
        [System.Array]::Copy($urlSecret, 0, $pastePassphrase, 0, $urlSecret.Length)
        [System.Array]::Copy($pwBytes, 0, $pastePassphrase, $urlSecret.Length, $pwBytes.Length)
    }

    # Common cryptographic parameters
    $kdfIterations = 100000
    $kdfKeysize = 32 # in bytes (256 bits)
    $kdfSalt = [byte[]]::new(8)
    $null = $rng.GetBytes($kdfSalt) # Salt for PBKDF2

    $nonceSize = 12 # in bytes
    $cipherIv = [byte[]]::new($nonceSize)
    $null = $rng.GetBytes($cipherIv) # Nonce (IV) for AES-GCM

    $rng.Dispose()

    $cipherAlgo = 'aes'
    $cipherMode = 'gcm'
    $cipherTagSize = 128 # in bits
    $compressionType = 'none'
    $_openDiscussion = if ($OpenDiscussion) { 1 } else { 0 }
    $_burnAfterReading = if ($BurnAfterReading) { 1 } else { 0 }

    
    # Dérivation de la clé (PBKDF2)
    $kdfKey = $null
    if ($useBouncyCastle) {
        # --- BouncyCastle Implementation ---
        Write-Verbose "Deriving key with BouncyCastle (PBKDF2)..."
        $pdb = [Org.BouncyCastle.Crypto.Generators.Pkcs5S2ParametersGenerator]::new([Org.BouncyCastle.Crypto.Digests.Sha256Digest]::new())
        $pdb.Init($pastePassphrase, $kdfSalt, $kdfIterations)
        $kdfKey = $pdb.GenerateDerivedMacParameters($kdfKeysize * 8).GetKey() # BouncyCastle expects size in bits

    } else {

        Write-Verbose "Deriving key with .NET (PBKDF2)..."
        $pbkdf2 = [System.Security.Cryptography.Rfc2898DeriveBytes]::new($pastePassphrase, $kdfSalt, $kdfIterations, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
        $kdfKey = $pbkdf2.GetBytes($kdfKeysize) # .NET expects size in bytes
        $pbkdf2.Dispose()

    }

    # --- Paste Content (Text) Processing ---
    $pasteTextEncrypted = $null
    $pasteTextAdata = $null

    Write-Verbose "Preparing the paste text content."
    $pasteDataJson = ConvertTo-Json -Compress @{ paste = $PasteText }
    $pasteDataBytes = [System.Text.Encoding]::UTF8.GetBytes($pasteDataJson)

    # Create metadata (adata) for the text
    $pasteTextAdataObj = @(
        ,@(
            [System.Convert]::ToBase64String($cipherIv),
            [System.Convert]::ToBase64String($kdfSalt),
            $kdfIterations,
            ($kdfKeysize * 8), # keysize in bits
            $cipherTagSize,    # tagsize in bits
            $cipherAlgo,
            $cipherMode,
            $compressionType
        )
        $PasteFormat,
        $_openDiscussion,
        $_burnAfterReading
    )
    $pasteTextAdataJson = ConvertTo-Json -Compress $pasteTextAdataObj
    $pasteTextAdata = [System.Text.Encoding]::UTF8.GetBytes($pasteTextAdataJson)

    if ($UseBouncyCastle) {
        Write-Verbose "Encrypting with BouncyCastle (AES-GCM)..."
        $cipher = [Org.BouncyCastle.Crypto.Modes.GcmBlockCipher]::new([Org.BouncyCastle.Crypto.Engines.AesEngine]::new())
        $parameters = [Org.BouncyCastle.Crypto.Parameters.AeadParameters]::new(
            [Org.BouncyCastle.Crypto.Parameters.KeyParameter]::new($kdfKey),
            $cipherTagSize,
            $cipherIv,
            $pasteTextAdata)
        $cipher.Init($true, $parameters) # true for encryption
        
        $outputBuffer = [byte[]]::new($cipher.GetOutputSize($pasteDataBytes.Length))
        $len = $cipher.ProcessBytes($pasteDataBytes, 0, $pasteDataBytes.Length, $outputBuffer, 0)
        $cipher.DoFinal($outputBuffer, $len)
        $pasteTextEncrypted = $outputBuffer
    } else {
        Write-Verbose "Encrypting with .NET (AES-GCM)..."
        $aes = [System.Security.Cryptography.AesGcm]::new($kdfKey)
        $cipherText = [byte[]]::new($pasteDataBytes.Length)
        $tag = [byte[]]::new($cipherTagSize / 8)
        $aes.Encrypt($cipherIv, $pasteDataBytes, $cipherText, $tag, $pasteTextAdata)
        $aes.Dispose()
        $pasteTextEncrypted = $cipherText + $tag
    }

    # --- Request Creation and Sending (Common) ---
    $bodyParams = [ordered]@{ # Use ordered dictionary to maintain order for debugging/readability
        v    = 2
        meta = @{ expire = $Expire }
        adata = $pasteTextAdataObj
        ct   = [System.Convert]::ToBase64String($pasteTextEncrypted)
    }

    
    $params = @{
        Uri         = $PrivateBinUrl
        Method      = 'Post'
        Headers     = @{'X-Requested-With' = 'JSONHttpRequest' }
        ContentType = 'application/json; charset=UTF-8' # Ensure correct content type
        # Add -Depth to ConvertTo-Json to prevent truncation of nested objects (like attachment adata)
        # A depth of 5 should be sufficient for the current PrivateBin API structure (v -> attachments -> adata -> crypto params)
        Body        = ConvertTo-Json -InputObject $bodyParams -Compress -Depth 10 # Increased depth for safety
    }
    Write-Verbose "JSON request body sent to the server: $($bodyParams | ConvertTo-Json -Compress -Depth 10)"

    try {
        $response = Invoke-RestMethod @params -ErrorAction Stop # Use -ErrorAction Stop to catch WebExceptions
    }
    catch [System.Net.WebException] {
        $exceptionMessage = $_.Exception.Message
        if ($_.Exception.Response -is [System.Net.HttpWebResponse]) {
            $httpResponse = $_.Exception.Response
            $statusCode = $httpResponse.StatusCode
            $statusDescription = $httpResponse.StatusDescription

            if ($statusCode -eq [System.Net.HttpStatusCode]::NotFound) {
                Write-Error "The specified path on the PrivateBin server ('$($PrivateBinUrl)') was not found (HTTP Error 404: $statusDescription). Check the URL. Details: $exceptionMessage"
            } elseif (($statusCode -as [int]) -ge 400 -and ($statusCode -as [int]) -lt 500) {
                Write-Error "Client error during the request to the PrivateBin server ('$($PrivateBinUrl)') (HTTP Error $($statusCode -as [int]): $statusDescription). Check the parameters and the URL. Details: $exceptionMessage"
            } elseif (($statusCode -as [int]) -ge 500 -and ($statusCode -as [int]) -lt 600) {
                Write-Error "Internal server error from PrivateBin ('$($PrivateBinUrl)') (HTTP Error $($statusCode -as [int]): $statusDescription). Details: $exceptionMessage"
            } else {
                # Other HTTP errors
                Write-Error "HTTP Error $($statusCode -as [int]) ($statusDescription) during communication with the PrivateBin server ('$($PrivateBinUrl)'). Details: $exceptionMessage"
            }
        } else {
            # No HTTP response, likely a network/DNS issue
            Write-Error "Network error when trying to connect to '$($PrivateBinUrl)': $exceptionMessage"
        }
         return $null
     }
     catch {
         Write-Error "An unexpected error occurred while sending the paste: $($_.Exception.Message)"
         return $null
     }

    if ($null -eq $response) {
         Write-Error "An unexpected error occurred while sending the paste, the server returned a null value!"
        # This condition is mainly an additional safeguard,
        # as the catch blocks should already handle errors and return $null.
        # If Invoke-RestMethod returns $null without an exception, it's an unexpected case.
        return $null 
    }

    # Check if the response looks like a valid PrivateBin response
    $isPSCustomObject = $response -is [PSCustomObject]
    $hasStatusProperty = $null -ne ($response | Get-Member -Name 'status' -MemberType NoteProperty -ErrorAction SilentlyContinue)
    
    $isValidPrivateBinResponse = $isPSCustomObject -and $hasStatusProperty

    if (-not $isValidPrivateBinResponse) {
        $responsePreview = if ($isPSCustomObject) { $response | ConvertTo-Json -Depth 5 -Compress } elseif ($response -is [String]) { ($response.Substring(0, [System.Math]::Min($response.Length, 200))) + (if ($response.Length -gt 200) { "..." } else { "" }) } else { "Type: $($response.GetType().FullName)" }
        
        Write-Error "The server response from URL '$PrivateBinUrl' does not seem to come from a valid PrivateBin instance or the operation failed."
        Write-Error "Verify that the URL points to a functional PrivateBin API and that the server responds as expected (status: 0 and presence of an 'id')."
        Write-Error "Preview of the received response: $responsePreview"
        return $null
    } elseif ($response.status -ne 0) {
        Write-Error "The PrivateBin server returned an error status: $($response.status). Check the server response."
        Write-Error "Preview of the received response: $($response | ConvertTo-Json -Depth 5 -Compress)"
        return $null
    }

    $PasteDateTime = (Get-Date)
    switch ($Expire) {
        '5min'   { $expirationDateTime = $PasteDateTime.AddMinutes(5) }
        '10min'  { $expirationDateTime = $PasteDateTime.AddMinutes(10) }
        '1hour'  { $expirationDateTime = $PasteDateTime.AddHours(1) }
        '1day'   { $expirationDateTime = $PasteDateTime.AddDays(1) }
        '1week'  { $expirationDateTime = $PasteDateTime.AddDays(7) }
        '1month' { $expirationDateTime = $PasteDateTime.AddMonths(1) }
        default {
            Write-Warning "Unknown expiration period '$expirationPeriod'. Cannot determine expiration."
            $expirationDateTime = $PasteDateTime.AddYears(100)
        }
    }
    # Create output
    $encodedSecret = ConvertTo-Base58 $urlSecret
    $ResultObject = [PSCustomObject]@{
        ViewUrl        = ($PrivateBinUrl + "?$($response.id)#$encodedSecret")
        PrivateBinUrl = $PrivateBinUrl
        PasteSecret  = $PasteSecret
        OpenDiscussion = $OpenDiscussion
        BurnAfterReading = $BurnAfterReading
        PasteDateTime = $PasteDateTime
        Expire = $Expire
        ExpirationDateTime = $expirationDateTime
        deletetoken    = $response.deletetoken
        id = $response.id
        url = $response.url
        status = $response.status
    }

    # Add the IsExpired method to the PSCustomObject
    $ResultObject | Add-Member -MemberType ScriptMethod -Name 'IsExpired' -Value {
        param()
        return ( (Get-Date) -ge $This.ExpirationDateTime )
    }

    $ResultObject | Add-Member -MemberType ScriptMethod -Name 'RemovePaste' -Value {
        param()
        Remove-PrivateBinPaste -PasteObject $this
    }
    #Configure a default display set
    $defaultDisplaySet = 'ViewUrl','ExpirationDateTime'

    #Create the default property display set
    $defaultDisplayPropertySet = New-Object System.Management.Automation.PSPropertySet(‘DefaultDisplayPropertySet’,[string[]]$defaultDisplaySet)
    $PSStandardMembers = [System.Management.Automation.PSMemberInfo[]]@($defaultDisplayPropertySet)
    #Give this object a unique typename
    $ResultObject.PSObject.TypeNames.Insert(0,'User.Information')
    $ResultObject | Add-Member MemberSet PSStandardMembers $PSStandardMembers


    return $ResultObject
}


function Remove-PrivateBinPaste {
    <#
    .SYNOPSIS
        Deletes a paste from a PrivateBin server.
    .DESCRIPTION
        This function sends a deletion request to the PrivateBin server for a specific paste.
        It requires the object returned by `Send-ToPrivateBin`, which contains the necessary
        paste ID and deletion token.
    .PARAMETER PasteObject
        The custom object returned by the `Send-ToPrivateBin` function. This object must contain
        the `id`, `deletetoken`, and `PrivateBinUrl` properties.
    .OUTPUTS
        [bool]
        Returns $true if the deletion was successful, and $false otherwise.
    .EXAMPLE
        PS C:\> $myPaste = Send-ToPrivateBin -PrivateBinUrl "https://privatebin.net" -PasteText "Temporary information"
        PS C:\> Remove-PrivateBinPaste -PasteObject $myPaste

        Description
        -----------
        First, a new paste is created and the result is stored in the $myPaste variable.
        Then, the paste is deleted by passing this object to `Remove-PrivateBinPaste`.
    .EXAMPLE
        PS C:\> Send-ToPrivateBin -PrivateBinUrl "https://privatebin.net" -PasteText "Another temp paste" | Remove-PrivateBinPaste

        Description
        -----------
        Creates a paste and immediately pipes the resulting object to `Remove-PrivateBinPaste` to delete it.
    .LINK
        Send-ToPrivateBin
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateScript({
            $requiredProperties = 'ViewUrl', 'id', 'deletetoken'
            foreach ($prop in $requiredProperties) {
                if (-not ($_.PSObject.Properties.Name -contains $prop)) {
                    throw "The input object must contain the '$prop' property."
                }
            }
            return $true
        })]
        [PSCustomObject]$PasteObject
    )

    $deleteToken = $PasteObject.deletetoken
    $pasteId = $PasteObject.id
    
    $baseUrl = $PasteObject.PrivateBinUrl
    $apiUrl = "$($baseUrl)?$($pasteId)"

    Write-Verbose "Attempting to delete paste ID '$pasteId' on URL '$baseUrl'."

    $body = @{
        deletetoken = $deleteToken
    } | ConvertTo-Json -Compress

    $params = @{
        Uri         = $apiUrl
        Method      = 'POST'
        Headers     = @{'X-Requested-With' = 'JSONHttpRequest'}
        ContentType = 'application/json; charset=UTF-8'
        Body        = $body
        ErrorAction = 'Stop'
    }

    try {
        $response = Invoke-RestMethod @params

        if ($response.status -eq 0) {
            Write-Verbose "Paste ID '$pasteId' was successfully deleted."
            return $true
        }
        else {
            $errorMessage = if ($response.PSObject.Properties.Exists('message')) { $response.message } else { "Raison inconnue." }
            Write-Error "Failed to delete paste ID '$pasteId'. The server responded with status $($response.status): $errorMessage"
            return $false
        }
    }
    catch [System.Net.WebException] {
        $exceptionMessage = $_.Exception.Message
        if ($_.Exception.Response) {
            $httpResponse = $_.Exception.Response
            $statusCode = $httpResponse.StatusCode
            $statusDescription = $httpResponse.StatusDescription
            Write-Error "HTTP Error $($statusCode -as [int]) ($statusDescription) while attempting to delete the paste. The paste may have already expired or been deleted. Details: $exceptionMessage"
        }
        else {
            Write-Error "Network error when trying to connect to '$apiUrl': $exceptionMessage"
        }
        return $false
    }
    catch {
        Write-Error "An unexpected error occurred while deleting the paste: $($_.Exception.Message)"
        return $false
    }
}
