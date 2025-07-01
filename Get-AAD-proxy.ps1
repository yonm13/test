# To import in your PowerShell runspace, run one of below commands:
# iex ([System.Net.WebClient]@{}).DownloadString('https://gist.githubusercontent.com/keystroke/5d54c3db4fe02ef6507daf97b9cc7bd8/raw')
# irm https://gist.githubusercontent.com/keystroke/5d54c3db4fe02ef6507daf97b9cc7bd8/raw | iex

# To import in remote scriptblock, use below syntax:
# . ([scriptblock]::Create(([System.Net.WebClient]@{}).DownloadString('https://gist.githubusercontent.com/keystroke/5d54c3db4fe02ef6507daf97b9cc7bd8/raw')))

<#
.Synopsis
   Gets an OAuth context, including tokens, from AAD or ADFS.
#>
function Get-ADContext
{
    [CmdletBinding(DefaultParameterSetName='ByEnviromentAndInteraction')]
    [OutputType([pscustomobject])]
    param
    (
        # The target resource identifier for which to acquire a token. If not provided, will default to Microsoft Graph service.
        [Parameter(ParameterSetName='ByAuthorityAndSecret')]
        [Parameter(ParameterSetName='ByAuthorityAndCertificate')]
        [Parameter(ParameterSetName='ByAuthorityAndCertificateReference')]
        [Parameter(ParameterSetName='ByAuthorityAndCredential')]
        [Parameter(ParameterSetName='ByAuthorityAndInteraction')]
        [Parameter(ParameterSetName='ByAuthorityAndRefreshToken')]
        [Parameter(ParameterSetName='ByEnviromentAndSecret')]
        [Parameter(ParameterSetName='ByEnviromentAndCertificate')]
        [Parameter(ParameterSetName='ByEnviromentAndCertificateReference')]
        [Parameter(ParameterSetName='ByEnviromentAndCredential')]
        [Parameter(ParameterSetName='ByEnviromentAndInteraction')]
        [Parameter(ParameterSetName='ByEnviromentAndRefreshToken')]
        [ValidateNotNullOrEmpty()]
        [string] $Resource = $null,

        # The target identity system environment.
        [Parameter(ParameterSetName='ByEnviromentAndSecret')]
        [Parameter(ParameterSetName='ByEnviromentAndCertificate')]
        [Parameter(ParameterSetName='ByEnviromentAndCertificateReference')]
        [Parameter(ParameterSetName='ByEnviromentAndCredential')]
        [Parameter(ParameterSetName='ByEnviromentAndInteraction')]
        [Parameter(ParameterSetName='ByEnviromentAndRefreshToken')]
        [ValidateNotNullOrEmpty()]
        [ValidateSet('ADFS', 'AzureChinaCloud', 'AzureCloud', 'AzureGermanCloud', 'AzureUSGovernment')]
        [string] $IdentitySystem = 'AzureCloud',

        # The directory tenant name, identifier, or verified domain.
        [Parameter(Mandatory=$true, ParameterSetName='ByEnviromentAndSecret')]
        [Parameter(Mandatory=$true, ParameterSetName='ByEnviromentAndCertificate')]
        [Parameter(Mandatory=$true, ParameterSetName='ByEnviromentAndCertificateReference')]
        [Parameter(ParameterSetName='ByEnviromentAndCredential')]
        [Parameter(ParameterSetName='ByEnviromentAndInteraction')]
        [Parameter(ParameterSetName='ByEnviromentAndRefreshToken')]
        [ValidateNotNullOrEmpty()]
        [string] $DirectoryTenant = 'Common',

        # The authority URI of the AD or ADFS identity system from which to acquire a token or authorization code.
        [Parameter(Mandatory=$true, ParameterSetName='ByAuthorityAndSecret')]
        [Parameter(Mandatory=$true, ParameterSetName='ByAuthorityAndCertificate')]
        [Parameter(Mandatory=$true, ParameterSetName='ByAuthorityAndCertificateReference')]
        [Parameter(Mandatory=$true, ParameterSetName='ByAuthorityAndCredential')]
        [Parameter(Mandatory=$true, ParameterSetName='ByAuthorityAndInteraction')]
        [Parameter(Mandatory=$true, ParameterSetName='ByAuthorityAndRefreshToken')]
        [ValidateNotNull()]
        [ValidateScript({ $_.IsAbsoluteUri -and $_.Scheme -ieq 'https' })]
        [Uri] $AuthorityUri = $null,

        # A user credential for which to acquire a token. Must support a non-interactive login flow.
        [Parameter(Mandatory=$true, ParameterSetName='ByAuthorityAndCredential')]
        [Parameter(Mandatory=$true, ParameterSetName='ByEnviromentAndCredential')]
        [ValidateNotNull()]
        [pscredential] $Credential = $null,

        # The refresh token to use to acquire an access token targeting the specified resource.
        [Parameter(Mandatory=$true, ParameterSetName='ByAuthorityAndRefreshToken')]
        [Parameter(Mandatory=$true, ParameterSetName='ByEnviromentAndRefreshToken')]
        [ValidateNotNull()]
        [SecureString] $RefreshToken = $null,

        # The identifier of the client identity application which is used to acquire a token.
        [Parameter(Mandatory=$true, ParameterSetName='ByAuthorityAndSecret')]
        [Parameter(Mandatory=$true, ParameterSetName='ByAuthorityAndCertificate')]
        [Parameter(Mandatory=$true, ParameterSetName='ByAuthorityAndCertificateReference')]
        [Parameter(ParameterSetName='ByAuthorityAndCredential')]
        [Parameter(ParameterSetName='ByAuthorityAndInteraction')]
        [Parameter(ParameterSetName='ByAuthorityAndRefreshToken')]
        [Parameter(Mandatory=$true, ParameterSetName='ByEnviromentAndSecret')]
        [Parameter(Mandatory=$true, ParameterSetName='ByEnviromentAndCertificate')]
        [Parameter(Mandatory=$true, ParameterSetName='ByEnviromentAndCertificateReference')]
        [Parameter(ParameterSetName='ByEnviromentAndCredential')]
        [Parameter(ParameterSetName='ByEnviromentAndInteraction')]
        [Parameter(ParameterSetName='ByEnviromentAndRefreshToken')]
        [ValidateNotNullOrEmpty()]
        [string] $ClientId = '1950a258-227b-4e31-a9cf-717495945fc2',

        [Parameter(Mandatory=$true, ParameterSetName='ByAuthorityAndSecret')]
        [Parameter(Mandatory=$true, ParameterSetName='ByEnviromentAndSecret')]
        [ValidateNotNullOrEmpty()]
        [SecureString] $ClientSecret = $null,

        # The certificate to use when authenticating as a service principal to acquire a token.
        [Parameter(Mandatory=$true, ParameterSetName='ByAuthorityAndCertificate')]
        [Parameter(Mandatory=$true, ParameterSetName='ByEnviromentAndCertificate')]
        [ValidateNotNull()]
        [ValidateScript({ $_.HasPrivateKey })]
        [System.Security.Cryptography.X509Certificates.X509Certificate2] $Certificate = $null,

        # The thumbprint of the certificate to use when authenticating as a service principal to acquire a token.
        # Used in conjunction with the 'CertificateStoreLocation' and 'CertificateStoreName' parameters to locate the certificate.
        [Parameter(Mandatory=$true, ParameterSetName='ByAuthorityAndCertificateReference')]
        [Parameter(Mandatory=$true, ParameterSetName='ByEnviromentAndCertificateReference')]
        [ValidateNotNullOrEmpty()]
        [string] $CertificateThumbprint = $null,

        # The certificate store location of the certificate to use when authenticating as a service principal to acquire a token.
        # Used in conjunction with the 'CertificateThumbprint' and 'CertificateStoreName' parameters to locate the certificate.
        [Parameter(ParameterSetName='ByAuthorityAndCertificateReference')]
        [Parameter(ParameterSetName='ByEnviromentAndCertificateReference')]
        [ValidateNotNull()]
        [System.Security.Cryptography.X509Certificates.StoreLocation] $CertificateStoreLocation = [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine,

        # The certificate store name of the certificate to use when authenticating as a service principal to acquire a token.
        # Used in conjunction with the 'CertificateThumbprint' and 'CertificateStoreLocation' parameters to locate the certificate.
        [Parameter(ParameterSetName='ByAuthorityAndCertificateReference')]
        [Parameter(ParameterSetName='ByEnviromentAndCertificateReference')]
        [ValidateNotNull()]
        [System.Security.Cryptography.X509Certificates.StoreName] $CertificateStoreName = [System.Security.Cryptography.X509Certificates.StoreName]::My,

        # Indicates that the 'X5C' parameter should be sent in the assertion of the token request.
        [Parameter(ParameterSetName='ByAuthorityAndCertificate')]
        [Parameter(ParameterSetName='ByEnviromentAndCertificate')]
        [Parameter(ParameterSetName='ByAuthorityAndCertificateReference')]
        [Parameter(ParameterSetName='ByEnviromentAndCertificateReference')]
        [switch] $IncludeX5C,

        # The redirect URI to use with an interactive authentication session.
        [Parameter(ParameterSetName='ByAuthorityAndInteraction')]
        [Parameter(ParameterSetName='ByEnviromentAndInteraction')]
        [ValidateNotNullOrEmpty()]
        [string] $RedirectUri = 'urn:ietf:wg:oauth:2.0:oob',

        # The prompt to use with an interactive authentication session. Some values are not valid in certain circumstances.
        # login:          The user should be prompted to reauthenticate.
        # select_account: The user is prompted to select an account, interrupting single sign on. The user may select an existing signed-in account, enter their credentials for a remembered account, or choose to use a different account altogether.
        # consent:        User consent has been granted, but needs to be updated. The user should be prompted to consent.
        # admin_consent:  An administrator should be prompted to consent on behalf of all users in their organization
        [Parameter(ParameterSetName='ByAuthorityAndInteraction')]
        [Parameter(ParameterSetName='ByEnviromentAndInteraction')]
        [ValidateNotNullOrEmpty()]
        [ValidateSet('login', 'select_account', 'consent', 'admin_consent', 'none')]
        [string] $Prompt = 'select_account',

        # A login hint to use with an interactive authentication session to pre-fill the username/email address field of the sign-in page.
        [Parameter(ParameterSetName='ByAuthorityAndInteraction')]
        [Parameter(ParameterSetName='ByEnviromentAndInteraction')]
        [ValidateNotNullOrEmpty()]
        [string] $LoginHint = $null,

        # A login hint to use with an interactive authentication session to suggest to the user which domain credential they should use to authenticate.
        [Parameter(ParameterSetName='ByAuthorityAndInteraction')]
        [Parameter(ParameterSetName='ByEnviromentAndInteraction')]
        [ValidateNotNullOrEmpty()]
        [string] $DomainHint = $null,

        # The scope value to use in the token requests.
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string] $Scope = 'openid',

        # Indicates that the 'resource' parameter should not be sent token requests.
        [Parameter()]
        [switch] $ExcludeResource,
        
        # Indicates that the 'PKCE' parameters should be sent in the token request.
        [Parameter(ParameterSetName='ByAuthorityAndInteraction')]
        [Parameter(ParameterSetName='ByEnviromentAndInteraction')]
        [switch] $PKCE
    )
    begin
    {
        $originalErrorActionPreference = $ErrorActionPreference
        $ErrorActionPreference         = 'Stop'
        $defaultWebRequestParams       = @{ UseBasicParsing = $true; TimeoutSec = 15 }
        $token                         = $null
        try
        {
            # Resolve target identity system endpoints and properties
            if (-not $AuthorityUri)
            {
                $AuthorityUri = switch ($IdentitySystem)
                {
                    'AzureChinaCloud'   {"https://login.chinacloudapi.cn/$DirectoryTenant"}
                    'AzureCloud'        {"https://login.microsoftonline.com/$DirectoryTenant"}
                    'AzureGermanCloud'  {"https://login.microsoftonline.de/$DirectoryTenant"}
                    'AzureUSGovernment' {"https://login.microsoftonline.us/$DirectoryTenant"}
                    'ADFS'              { throw [System.NotSupportedException]"To retrieve a token for ADFS, please use the 'AuthorityUri' parameter to provide the correct endpoint." }
                    Default             { throw [System.NotSupportedException]"Identity system '$IdentitySystem' is not supported." }
                }
                $params = @{ Message = "'AuthorityUri' not provided; resolved to: $AuthorityUri" }
                if ($DirectoryTenant -eq 'Common') { $params += @{ Verbose = $true } }
                Write-Verbose @params
            }
            try
            {
                $endpoint     = "$("$AuthorityUri".TrimEnd('/'))/.well-known/openid-configuration"
                $response     = Invoke-WebRequest @defaultWebRequestParams -Uri $endpoint -Proxy "http://127.0.0.1:8080"
                $openIdConfig = ConvertFrom-Json $response.Content
                Write-Debug "Identity System openid-configuration: $([ordered]@{ endpoint = "$endpoint"; response = $openIdConfig } | ConvertTo-Json -Depth 1)"
            }
            catch
            {
                $errorOut = $_.Exception.Response | Select Method,ResponseUri,StatusCode,StatusDescription,IsFromCache,LastModified | ConvertTo-Json
                $errorOut = "Failed to retrieve openid-configuration at endpoint '$endpoint': $_`r`n`r`nAdditional details: $errorOut"
                throw [System.InvalidOperationException]$errorOut
            }
            if (-not $Resource -and -not $ExcludeResource)
            {
                # Note - ADFS does not include this claim
                if (-not $openIdConfig.cloud_graph_host_name)
                {
                    throw [System.InvalidOperationException]"'Resource' not provided, and no suitable default was resolved. Please try again by providing an explicit value for the 'Resource' parameter."
                }

                $Resource = "https://$($openIdConfig.cloud_graph_host_name)"
                Write-Verbose "'Resource' not provided; resolved to: $Resource" -Verbose
            }

            # Prepare to retrieve token
            $dependantAssembly = 'System.Web'
            if (-not [System.Reflection.Assembly]::LoadWithPartialName($dependantAssembly))
            {
                throw [System.NotSupportedException]"Unable to load required assembly '$dependantAssembly' for processing query string parameters and performing URL encoding."
            }

            function ConvertTo-QueryString([HashTable]$QueryParameters=@{})
            {
                $query = [System.Web.HttpUtility]::ParseQueryString("?")
                $QueryParameters.GetEnumerator() | ForEach { $query.Add($_.Key, $_.Value) }
                return $query.ToString()
            }

            function Get-TokenNonInteractive([Uri]$Uri, [HashTable]$Body)
            {
                $requestParams = $defaultWebRequestParams + @{
                    Method      = [Microsoft.PowerShell.Commands.WebRequestMethod]::Post
                    Uri         = $openIdConfig.token_endpoint
                    ContentType = "application/x-www-form-urlencoded"
                }
                if ($Body)
                {
                    $requestParams['Body'] = $Body
                    Write-Verbose "Non-Interactive Token Request: $($Body.Keys | ConvertTo-Json -Compress)"
                }
                try
                {
                    
                    $response = Invoke-WebRequest @requestParams -Proxy "http://127.0.0.1:8080"
                    $token    = ConvertFrom-Json $response.Content

                    # save the tokens as secure strings and add methods to retrieve plain-text tokens in various forms
                    foreach ($tokenType in @('Access', 'Refresh', 'Id'))
                    {
                        $propName = "${tokenType}_token"
                        if ($token.$propName)
                        {
                            $token.$propName = [System.Net.NetworkCredential]::new($tokenType, $token.$propName).SecurePassword
                        }
                        $getToken = [scriptblock]::Create("[System.Net.NetworkCredential]::new('$tokenType', `$this.$propName).Password")
                        $token | Add-Member -MemberType ScriptMethod -Name "Get${tokenType}Token" -Value $getToken

                        $getJson = [scriptblock]::Create("if (-not `$this.${tokenType}_token) { return `$null };try{ `$claimsBase64 = `$this.Get${tokenType}Token().Split('.')[1].Replace('-','+').Replace('_','/'); return [System.Text.UTF32Encoding]::UTF8.GetString(([System.Convert]::FromBase64String(""`$(`$claimsBase64)`$([string]::new('=',@{0=0;2=2;3=1;1=0}[`$claimsBase64.Length % 4]))""))); }catch{return ""`$_""}")
                        $token | Add-Member -MemberType ScriptMethod -Name "Get${tokenType}TokenJson" -Value $getJson

                        $getClaims = [scriptblock]::Create("if (-not `$this.${tokenType}_token) { return `$null };try{ return (ConvertFrom-Json `$this.Get${tokenType}TokenJson().Replace('`"AppId`"','`"AppId2`"')); }catch{return ""`$_""}")
                        $token | Add-Member -MemberType ScriptMethod -Name "Get${tokenType}TokenClaims" -Value $getClaims
                    }

                    # add method to build authorization header for use in subsequent web requests
                    $token | Add-Member -MemberType ScriptMethod -Name GetAuthorizationHeader -Value { return '{0} {1}' -f $this.token_type, $this.GetAccessToken() }

                    # add properties for certain claims in the access token and other metadata
                    $claims = if ($claims=$token.GetIdTokenClaims()) {$claims} else {$token.GetAccessTokenClaims()}
                    $props  = [ordered]@{
                        open_id        = $openIdConfig
                        tenant         = $claims.tid
                        issuer         = $claims.iss
                        authority      = $AuthorityUri.AbsoluteUri
                        issued_at      = [DateTime]::Now
                        issued_at_utc  = [DateTime]::UtcNow
                        expires_at     = [DateTime]::Now.AddSeconds($token.expires_in)
                        expires_at_utc = [DateTime]::UtcNow.AddSeconds($token.expires_in)
                    }
                    if ($openIdConfig.cloud_graph_host_name)
                    {
                        $props += @{ graph_endpoint = 'https://{0}/{1}' -f $openIdConfig.cloud_graph_host_name.TrimEnd('/'), $claims.tid }
                    }
                    $token | Add-Member -NotePropertyMembers $props
                    $token | Add-Member -MemberType ScriptProperty -Name expired -Value {
                        return [DateTime]::UtcNow -ge $this.expires_at_utc
                    }

                    Write-Output $token
                }
                catch
                {
                    $errorOut = $_.Exception.Response | Select Method,ResponseUri,StatusCode,StatusDescription,IsFromCache,LastModified | ConvertTo-Json
                    $errorOut = "Failed to retrieve token: $_`r`n`r`nAdditional details: $errorOut"
                    throw [System.InvalidOperationException]$errorOut
                }
            }

            function ConvertTo-Base64UrlEncode([byte[]]$bytes)
            {
                return [System.Convert]::ToBase64String($bytes).Replace('/','_').Replace('+','-').Trim('=')
            }

            function Modify($hashtable=@{})
            {
                if ($ExcludeResource){$hashtable.Remove('Resource')}
                return $hashtable
            }
            
            $nonce = [guid]::NewGuid().ToString()

            $bytes = [byte[]]::new(32)
            [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
            $codeVerifier = ConvertTo-Base64UrlEncode $bytes
            $codeChallenge = ConvertTo-Base64UrlEncode ([System.Security.Cryptography.sha256]::Create().ComputeHash([System.Text.Encoding]::ASCII.GetBytes($codeVerifier)))

            # Retrieve the token
            if ($Credential)
            {
                # User credential non-interactive flow
                $token = Get-TokenNonInteractive -Uri $openIdConfig.token_endpoint -Body (Modify @{
                    resource   = $Resource
                    client_id  = $ClientId
                    grant_type = 'password'
                    scope      = $Scope
                    username   = $Credential.UserName
                    password   = $Credential.GetNetworkCredential().Password
                })
                Write-Output $token
            }
            elseif ($RefreshToken)
            {
                # Refresh token non-interactive flow
                $token = Get-TokenNonInteractive -Uri $openIdConfig.token_endpoint -Body (Modify @{
                    resource      = $Resource
                    client_id     = $ClientId
                    grant_type    = 'refresh_token'
                    scope         = $Scope
                    refresh_token = [System.Net.NetworkCredential]::new('refreshToken', $RefreshToken).Password
                })
                Write-Output $token
            }
            elseif ($Certificate -or $CertificateThumbprint)
            {
                # Service Principal non-interactive flow with certificate
                if (-not $Certificate)
                {
                    $path         = "Cert:\$CertificateStoreLocation\$CertificateStoreName\$CertificateThumbprint"
                    $certificates = @(Get-Item -Path $path)
                    if ($certificates.Count -eq 0)
                    {
                        throw [InvalidOperationException]"Unable to find referenced certificate '$path'."
                    }
                    elseif ($certificates.Count -gt 1)
                    {
                        Write-Warning "More than one certificate found at '$path'; using first one."
                    }
                    $Certificate = $certificates[0]
                    if (-not $Certificate.HasPrivateKey)
                    {
                        throw [System.InvalidOperationException]"Certificate found at '$path' does not have associated private key installed."
                    }
                }

                $currentUtcDateTimeInSeconds    = ([datetime]::UtcNow - [datetime]'1970-01-01 00:00:00').TotalSeconds
                $notBeforeSecondsRelativeToNow  = -90
                $expirationSecondsRelativeToNow = 3600

                $tokenHeaders = [ordered]@{
                    alg = 'RS256'
                    x5t = ConvertTo-Base64UrlEncode $Certificate.GetCertHash()
                }

                if ($IncludeX5C)
                {
                    $tokenHeaders += @{ x5c = [System.Convert]::ToBase64String($Certificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)) }
                }

                $tokenClaims = [ordered]@{
                    aud = $openIdConfig.token_endpoint
                    exp = [long]($currentUtcDateTimeInSeconds + $expirationSecondsRelativeToNow)
                    iss = $ClientId
                    jti = [guid]::NewGuid().ToString()
                    nbf = [long]($currentUtcDateTimeInSeconds + $notBeforeSecondsRelativeToNow)
                    sub = $ClientId
                }

                Write-Debug "Preparing client assertion with token header: '$(ConvertTo-Json $tokenHeaders -Compress)' and claims: $(ConvertTo-Json $tokenClaims)"

                $tokenParts = @()
                $tokenParts += ConvertTo-Base64UrlEncode ([System.Text.Encoding]::UTF8.GetBytes((ConvertTo-Json $tokenHeaders -Depth 10 -Compress)))
                $tokenParts += ConvertTo-Base64UrlEncode ([System.Text.Encoding]::UTF8.GetBytes((ConvertTo-Json $tokenClaims -Depth 10 -Compress)))

                $sha256Hash = ''
                $sha256 = [System.Security.Cryptography.SHA256]::Create()
                try
                {
                    $sha256Hash = $sha256.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($tokenParts -join '.'))
                }
                finally
                {
                    if ($sha256) { $sha256.Dispose(); $sha256 = $null }
                }

                if ($Certificate.PrivateKey)
                {
                    # Note - the default instance of the RSACryptoServiceProvider instantiated on the client certificate may only support SHA1.
                    # E.g. Even when "$($ClientCertificate.SignatureAlgorithm.FriendlyName)" evaluates to "sha256RSA", the value of
                    # "$($ClientCertificate.PrivateKey.SignatureAlgorithm)" may evaulate to "http://www.w3.org/2000/09/xmldsig#rsa-sha1".
                    # Furthermore, the private key is likely not marked as exportable, so we cannot "simply" instantiate a new RSACryptoServiceProvider instance.
                    # We must first create new CSP parameters with a "better" cryptographic service provider that supports SHA256, and use those parameters
                    # to instantiate a "better" RSACryptoServiceProvider which also supports SAH256. Failure to do this will result in the following error:
                    # "Exception calling "CreateSignature" with "1" argument(s): "Invalid algorithm specified."
                    # It may be possible to bypass this issue of the certificate is generated with the "correct" cryptographic service provider, but if the certificate
                    # was created by a CA or if the provider type was not the "correct" type, then this workaround must be used.
                    # Note - this assumes certificate is installed in the local machine store.
                    try
                    {
                        $csp = [System.Security.Cryptography.CspParameters]::new(
                            ($providerType=24),
                            ($providerName='Microsoft Enhanced RSA and AES Cryptographic Provider'),
                            ($keyContainerName=$Certificate.PrivateKey.CspKeyContainerInfo.KeyContainerName))
                        $csp.Flags = [System.Security.Cryptography.CspProviderFlags]::UseMachineKeyStore # TODO support other key location
                    }
                    catch
                    {
                        throw "An error occurred trying to load the '$providerName' using the specified certificate '$($Certificate.Thumbprint)'. Please ensure the certificate is installed into the local machine certificate store, and is accessible to the windows identity calling this function. You may also need to run this function in an elevated context to access the certificate private key."
                    }
                
                    $sigBytes = $null
                    $rsa      = [System.Security.Cryptography.RSACryptoServiceProvider]::new($csp)
                    try
                    {
                        $sigBytes = $rsa.SignHash($sha256Hash, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
                    }
                    finally
                    {
                        if ($rsa) { $rsa.Dispose(); $rsa = $null }
                    }
                }
                else
                {
                    $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
                    $sigBytes = $rsa.SignHash($sha256Hash, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
                }

                $tokenParts += ConvertTo-Base64UrlEncode $sigBytes

                $clientAssertion = $tokenParts -join '.'

                $token = Get-TokenNonInteractive -Uri $openIdConfig.token_endpoint -Body (Modify @{
                    resource              = $Resource
                    client_id             = $ClientId
                    grant_type            = 'client_credentials'
                    client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
                    client_assertion      = $clientAssertion
                    scope                 = $Scope
                })
                Write-Output $token
            }
            elseif ($ClientSecret)
            {
                # Service Principal non-interactive flow with secret
                $token = Get-TokenNonInteractive -Uri $openIdConfig.token_endpoint -Body (Modify @{
                    resource      = $Resource
                    client_id     = $ClientId
                    client_secret = [System.Net.NetworkCredential]::new('clientSecret', $ClientSecret).Password
                    grant_type    = 'client_credentials'
                    scope         = $Scope
                })
                Write-Output $token
            }
            else
            {
                # User interactive flow
                $dependantAssembly = 'System.Windows.Forms'
                if (-not [System.Reflection.Assembly]::LoadWithPartialName($dependantAssembly))
                {
                    throw [System.NotSupportedException]"Unable to load required assembly '$dependantAssembly' for an interactive login."
                }

                # https://docs.microsoft.com/en-us/azure/active-directory/develop/v1-protocols-oauth-code#request-an-authorization-code
                $params = @{
                    resource      = $Resource
                    client_Id     = $ClientId
                    redirect_uri  = $RedirectUri
                    response_type = 'code'
                    response_mode = 'query'
                    state         = ($state = (New-Guid).ToString())
                    scope         = $Scope
                    nonce         = $nonce
                }
                if ($Prompt -ne 'none')
                {
                    $params += @{ prompt = $Prompt }
                }
                if ($PKCE)
                {
                    $params += @{
                        code_challenge_method = 'S256'
                        code_challenge        = $codeChallenge
                    }
                }
                if ($LoginHint)
                {
                    $params['login_hint'] = $LoginHint
                }
                if ($DomainHint)
                {
                    $params['domain_hint'] = $DomainHint
                }
                $authorizationEndpointUri = '{0}?{1}' -f $openIdConfig.authorization_endpoint.TrimEnd(), (ConvertTo-QueryString (Modify $params))
                Write-Verbose "Interactive Authorization URI: '$authorizationEndpointUri'"

                try
                {
                    $size = @{ Width = 700; Height = 800 }
                    $form = [Windows.Forms.Form]@{
                        Text          = $title = "PS C:\> $($MyInvocation.MyCommand.Name)"
                        StartPosition = 'CenterScreen'
                        Icon          = $(try { [System.Drawing.Icon]::ExtractAssociatedIcon($PSHOME + "\powershell.exe") } catch {})
                        AutoScroll    = $true
                        AutoSize      = $true
                        AutoSizeMode  = 'GrowAndShrink'
                        SizeGripStyle = 'Hide'
                        MinimizeBox   = $false
                        MaximizeBox   = $false
                        ShowInTaskbar = $true
                    }
                    $browser  = [System.Windows.Forms.WebBrowser]@{ Width = 700; Height = 800; Margin = 0; Padding = 0; }
                    $form.Controls.Add($browser)

                    $result = @{}
                    $browser.Add_Navigated({
                        Write-Debug "Navigated: '$($browser.Url.GetLeftPart([System.UriPartial]::Path))'"
                        if ($browser.Url.AbsoluteUri.StartsWith($RedirectUri))
                        {
                            if ($browser.Url.Fragment -like '*error=*')
                            {
                                $result['error'] = [System.InvalidOperationException]"An error occurred while processing an interactive login session: $($browser.Url.Fragment)"
                                $form.Close()
                                return
                            }
                            $data  = @{}
                            $query = [System.Web.HttpUtility]::ParseQueryString($browser.Url.Query)
                            $query.AllKeys | ForEach { $data[$_] = $query[$_] }
                            if ($data.error)
                            {
                                $result['error'] = [System.InvalidOperationException]"An error occurred while processing an interactive login session: $(ConvertTo-Json $data -Depth 2)"
                                $form.Close()
                                return
                            }
                            elseif ($data.state -and ($data.state -ne $state))
                            {
                                $result['error'] = [System.InvalidOperationException]"Unexpected state! Authentication requests were expected to contain state flag '$state' but instead contained '$($data.state)'; someone may be trying to intefere with your communication!"
                                $form.Close()
                                return
                            }
                            elseif ($data.code)
                            {
                                $result['code'] = $data.code
                                $form.Close()
                                return
                            }
                        }
                    })
                    
                    Write-Host "Please authenticate interactively using the launched window with title: '$title'"
                    $form.BringToFront()
                    $browser.Navigate($authorizationEndpointUri)
                    [System.Windows.Forms.Application]::Run($form) # This is a blocking call!
                    Write-Debug "Authentication window closed."
                    
                    if ($result.code)
                    {
                        # https://docs.microsoft.com/en-us/azure/active-directory/develop/v1-protocols-oauth-code#use-the-authorization-code-to-request-an-access-token
                        $params = @{
                            tenant       = $DirectoryTenant
                            client_id    = $ClientId
                            grant_type   = 'authorization_code'
                            code         = $result.code
                            redirect_uri = $RedirectUri
                            resource     = $Resource
                            scope        = $Scope
                        }
                        if ($PKCE)
                        {
                            $params += @{ code_verifier = $codeVerifier }
                        }
                        $token = Get-TokenNonInteractive -Uri $openIdConfig.token_endpoint -Body (Modify $params)
                        Write-Output $token
                    }
                    elseif ($result.error)
                    {
                        throw $result.error
                    }
                    else
                    {
                        throw [System.InvalidOperationException]"The interactive authentication session was cancelled or failed with an unknown error."
                    }
                }
                finally
                {
                    if ($browser) { $browser.Dispose(); $browser = $null }
                    if ($form)    { $form.Dispose();    $form    = $null }
                }
            }
        }
        catch
        {
            Write-Error -ErrorAction $originalErrorActionPreference -Exception $_.Exception
        }
        finally
        {
            $ErrorActionPreference = $originalErrorActionPreference
        }
    }
}
