#requires -version 2

<##################
.DESCRIPTION
    install-chain adds or verifies that root and intermediate certificates are installed in the proper CAPI stores  
.PARAMETER chain
    An ArrayList of X509Certificate2 objects which comprise the full chain of trust for the certificate being provisioned
##################>
function install-chain( [System.Collections.ArrayList]$chain )
{	
    foreach ($cert in $chain)
    {
        # verify this is CA certificate	
        $is_ca_cert = $false
        
        foreach ($ext in $cert.Extensions)
        {
            if ($ext.GetType().Name -eq "X509BasicConstraintsExtension")
            {
                $is_ca_cert = $ext.CertificateAuthority
            }
        }

        if ($is_ca_cert)
        {
            # check to see if it is a root certificate
            if ($cert.Issuer -eq $cert.Subject)
            {
                $store = "Root"
                if (Test-Path "Cert:\LocalMachine\$store\$($cert.Thumbprint)")
                {
                    continue;  # already in the CAPI store
                }
            }
            else # it is an intermediate certificate
            {
                $store = "CA"
                if (Test-Path "Cert:\LocalMachine\$store\$($cert.Thumbprint)")
                {
                    continue;  # already in the CAPI store
                }
            }
        }
        else
        {
            throw "Unexpected certificate encountered in the chain - $($cert.Subject)"
        }

        $capi = Get-Item "Cert:\LocalMachine\$store"
        $capi.Open("ReadWrite")
        $capi.Add($cert)
        $capi.Close()

        # wait two seconds before checking to see the installation was successful
        Start-Sleep -s 2
        
        if (!(Test-Path "Cert:\LocalMachine\$store\$($cert.Thumbprint)"))
        {
            throw "Failed to install chain certificate on target system - $($cert.Subject)"
        }
    }
}

<##################
.DESCRIPTION
    install-cert adds or verifies an end-entity certificate is installed in the Personal CAPI store  
.PARAMETER certBytes
    The byte array equivalent of a PKCS#12 which contains the end-entity certificate and private key
.PARAMETER friendlyName
    A text string that is used to identify the certificate when extracting it from the CAPI store
.PARAMETER isNonExportable
    A boolean that controls whether or not the certificate should be exportable after it has been installed into the CAPI store
.PARAMETER password
    The SecureString password that was used to encrypt the private key
##################>
function install-cert( [byte[]]$certBytes, [string]$friendlyName, [bool]$isNonExportable, [System.Security.SecureString]$password )
{
    $pfx = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2

    if ($isNonExportable)
    {
        $pfx.Import($certBytes, $password, "MachineKeySet,PersistKeySet")
    }
    else
    {
        $pfx.Import($certBytes, $password, "Exportable,MachineKeySet,PersistKeySet")
    }
    
    if (!(Test-Path "Cert:\LocalMachine\My\$($pfx.Thumbprint)")) 
    {
        $pfx.FriendlyName = $friendlyName
        
        $store = Get-Item "Cert:\LocalMachine\My"
        $store.Open("ReadWrite")
        $store.Add($pfx)
        $store.Close()
        
        # wait two seconds before checking to see the installation was successful
        Start-Sleep -s 2

        if (!(Test-Path "Cert:\LocalMachine\My\$($pfx.Thumbprint)"))
        {
            throw "Could not install certificate on target system"
        }
    }
    else
    {
        $cert = Get-Item "Cert:\LocalMachine\My\$($pfx.Thumbprint)"

        if ($cert.FriendlyName -ne $friendlyName)
        {
            throw "Certificate already installed but FriendlyName does not match - $($cert.FriendlyName)"	
        }
    }
}

<##################
.DESCRIPTION
    grant-private-key-access grants a security principal access to the private key associated with a certificate  
.PARAMETER thumprint
    A text string that represents the public key hash of the certificate
.PARAMETER trustee
    A text string that represents the identity that is to be granted read permission to the private key
##################>
function grant-private-key-access( [string]$thumbprint, [string]$trustee )
{
    $key_dir = $Env:ProgramData + "\Microsoft\Crypto\RSA\MachineKeys\"
    $cert = (Get-ChildItem "Cert:\LocalMachine\My" | Where-Object {$_.Thumbprint -eq $thumbprint})
    $key_path = $key_dir + $cert.PrivateKey.CspKeyContainerInfo.UniqueKeyContainerName
   
    if (Test-Path $key_path)
    {
        try 
        {
            $key_acl = Get-Acl -Path $key_path
            $perm = $trustee, "Read", "Allow"
            $rule = new-object System.Security.AccessControl.FileSystemAccessRule $perm
            $key_acl.AddAccessRule($rule)
            Set-Acl -Path $key_path -AclObject $key_acl
        }
        catch [Exception]
        {
            throw $_.Exception.Message
        }
    }
    else
    {
        throw "Failed to locate private key to grant read permission"
    }
}

<##################
.DESCRIPTION
    bind-cert creates or updates an IIS web site binding to use the certificate  
.PARAMETER siteName
    The name of the IIS web site (required)
.PARAMETER ipAddress
    A text string that represents a specific IP address to which the web site is bound; null or 0.0.0.0 indicates it is bound to all IP addresses
.PARAMETER port
    A integer that represents the TCP port to which the web site is bound; defaults to 443
.PARAMETER thumprint
    A text string that represents the public key hash of the certificate being bound to the web site
.PARAMETER createBinding
    A boolean that controls whether a new binding is created if one does not already exist
##################>
function bind-cert( [string]$siteName, [string]$ipAddress, [int]$port, [string]$thumbprint, [bool]$createBinding )
{
    $execpol = Get-ExecutionPolicy
    if ( $execpol -eq "Restricted" -or $execpol -eq "AllSigned" )
    {
        throw 'PowerShell Execution Policy must be at least RemoteSigned when binding to IIS'
    }

    if (!(Test-Path "Cert:\LocalMachine\My\$thumbprint")) 
    {
        throw "Certificate not found in CAPI store"
    }
        
    if ( (Get-Command Get-Website -ErrorAction SilentlyContinue) -eq $null )
    {
        $iisVersion = Get-ItemProperty "HKLM:\Software\Microsoft\InetStp"
    
        if ($iisVersion.MajorVersion -eq 7 -and $iisVersion.MinorVersion -lt 5)
        {
            # Windows PowerShell Snap-In for IIS 7.0 add-on required
            if (-not (Get-PSSnapIn | where {$_.Name -eq "WebAdministration";})) 
            {
                Add-PSSnapIn "WebAdministration"
            }
      
            # the following is to workaround a rare issue where IIS 7.0 bindings may be incomplete
            $regkey = 'HKLM:\SYSTEM\CurrentControlSet\Services\HTTP\Parameters\SslBindingInfo'

            foreach ($sslBinding in (Get-ChildItem $regkey))
            {
                $needsFix = $false  
                $binding = $sslBinding.PSChildName  

                $loc = $regkey + '\' + $binding

                $isMissing = (Get-Item -Path $loc).GetValue("SslCertStoreName",$null) -eq $null

                if ($isMissing) # confirm that the binding belongs to IIS
                { 
                    foreach ($iisBinding in (Get-Website | Select-Object Bindings))
                    {
                        $where = ($iisBinding.bindings.Collection | ? {$_.Protocol -eq "https"})

                        foreach ($item in $where)
                        {
                            $needsFix = $item.BindingInformation.Contains($binding.Replace('0.0.0.0','*'))
                            if ($needsFix) { break }
                        }

                        if ($needsFix) { break }
                    }

                    if ($needsFix) # add the SslCertStoreName value to the registry key
                    {
                        Set-ItemProperty -Path $loc -Name "SslCertStoreName" -Value "My" -Type string
                    }
                }
            }
        }
        else
        {
            Import-Module "WebAdministration"
        }           
        
        if ( (Get-Command Get-Website -ErrorAction SilentlyContinue) -eq $null )
        {
            throw "PowerShell unable to load WebAdministration extensions for managing IIS"
        }
    }
        
    if ($ipAddress -eq $null -or $ipAddress.Length -eq 0)
    {
        $ipAddress = "0.0.0.0"
    }

    if ($port -eq $null)
    {
        $port = 443
    }

    $site_name = (Get-Website | ? { $_.Name -eq $siteName }).Name
        
    if ($site_name -ne $null) 
    {
        $exists = $(dir IIS:\SslBindings | ? {$_.IPAddress -eq $ipAddress -and $_.Port -eq $port}) -ne $null
            
        if (-not $exists) # bind the certificate to the IP and port
        {
            if ($createBinding)
            {
                $null = Get-Item "Cert:\LocalMachine\My\$thumbprint" | New-Item -Path "IIS:\SslBindings\$ipAddress!$port"
                
                if ($ipAddress -eq "0.0.0.0")
                {
                    New-WebBinding -Name $site_name -IP "*" -Port $port -Protocol https
                }
                else
                {
                    New-WebBinding -Name $site_name -IP $ipAddress -Port $port -Protocol https
                }

                return "IIS Web Site Binding successfully created"
            }
            else
            {
                throw "The requested binding does not exist; creation not permitted"
            }
        }
        else
        {
            $binding = dir IIS:\SslBindings | ? {$_.Sites -eq $site_name -and $_.IPAddress -eq $ipAddress -and $_.Port -eq $port}
            
            if ($binding -ne $null) # an SSL binding already exists for this site so update it
            {		
                Remove-Item "IIS:\Sslbindings\$ipAddress!$port"
                $null = Get-Item "Cert:\LocalMachine\My\$thumbprint" | New-Item -Path "IIS:\SslBindings\$ipAddress!$port"
                return "IIS Web Site Binding successfully updated"
            } 
            else
            {
                throw "The requested binding is in use by a different web site"
            }
        }
    } 
    else 
    {
        throw "Unable to locate IIS web site named $siteName"
    }
}

<##################
.DESCRIPTION
    extract-capi extracts certificate and private key from the Personal CAPI store  
.PARAMETER certOnly
    A boolean that controls whether or not the private key is included in the byte array which is returned
.PARAMETER friendlyName
    A text string that identifies the certificate in the Personal CAPI store; if more than one certificate share the same friendlyName the most recently issued of them is returned
.PARAMETER password
    The SecureString password that should be used to encrypt the private key in the PKCS#12 that is returned
.NOTES
    Used by Extract and Onboard Validation
##################>
function extract-capi( [bool]$certOnly, [string]$friendlyName, [System.Security.SecureString]$password )
{
    # if there are multiple certs with the same friendly name use the most recently issued
    $capi = Get-ChildItem Cert:\LocalMachine\My | Where-Object {$_.FriendlyName -match $friendlyName} | Sort-Object NotBefore -Descending | Select-Object -First 1

    if ($capi -ne $null -and $capi.Thumbprint -ne $null) 
    {
        $cert = Get-Item "Cert:\LocalMachine\My\$($capi.Thumbprint)"

        if ($certOnly)
        {
            return $cert.GetRawCertData()
        }
        else
        {			
            if ($cert.PrivateKey -ne $null)
            {
                $privKey = [System.Security.Cryptography.RSACryptoServiceProvider]$cert.PrivateKey
                if ($privKey.CspKeyContainerInfo.Exportable)
                {
                    $p12bytes = $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType] "Pfx", $password)
                    return $p12bytes
                }
                else
                {
                    throw "Private key is non-exportable"
                }
            }
            else
            {
                throw "Private key is not installed" 
            }
        }
    }
    else
    {
        throw "No certificate found with a FriendlyName of: $friendlyName"	
    }
}

<##################
.DESCRIPTION
    extract-iis extracts certificate and private key from CAPI identifying it by an IIS web site binding 
.PARAMETER certOnly
    A boolean that controls whether or not the private key is included in the byte array which is returned
.PARAMETER siteName
    The name of the IIS web site (required)
.PARAMETER ipAddress
    A text string that represents a specific IP address to which the web site is bound; null or 0.0.0.0 indicates it is bound to all IP addresses
.PARAMETER port
    A integer that represents the TCP port to which the web site is bound; defaults to 443
.PARAMETER password
    The SecureString password that should be used to encrypt the private key in the PKCS#12 that is returned
.NOTES
    Used by Extract and Onboard Validation
##################>
function extract-iis( [bool]$certOnly, [string]$siteName, [string]$ipAddress, [int]$port, [System.Security.SecureString]$password )
{   
    $execpol = Get-ExecutionPolicy
    if ( $execpol -eq "Restricted" -or $execpol -eq "AllSigned" )
    {
        throw 'PowerShell Execution Policy must be at least RemoteSigned when binding to IIS'
    }

    if ( (Get-Command Get-Website -ErrorAction SilentlyContinue) -eq $null )
    {
        $iisVersion = Get-ItemProperty "HKLM:\Software\Microsoft\InetStp"
        
        if ($iisVersion.MajorVersion -eq 7 -and $iisVersion.MinorVersion -lt 5)
        {
            # Windows PowerShell Snap-In for IIS 7.0 add-on required
            if (-not (Get-PSSnapIn | where {$_.Name -eq "WebAdministration";})) 
            {
                Add-PSSnapIn "WebAdministration"
            }
        }
        else
        {
            Import-Module "WebAdministration"
        }           
        
        if ( (Get-Command Get-Website -ErrorAction SilentlyContinue) -eq $null )
        {
            throw "PowerShell unable to load WebAdministration extensions for managing IIS"
        }
    }

    if ($ipAddress -eq $null -or $ipAddress.Length -eq 0)
    {
        $ipAddress = "0.0.0.0"
    }

    if ($port -eq $null)
    {
        $port = 443
    }

    $site_name = (Get-Website | ? { $_.Name -eq $siteName }).Name

    if ($site_name -ne $null) 
    {
        $binding = dir IIS:\SslBindings | ? {$_.Sites -eq $site_name -and $_.IPAddress -eq $ipAddress -and $_.Port -eq $port }

        if ($binding.Thumbprint -ne $null)
        {
            $cert = Get-Item "Cert:\LocalMachine\My\$($binding.Thumbprint)"

            if ($certOnly)
            {
                return $cert.GetRawCertData()
            }
            else
            {
                if ($cert.PrivateKey -ne $null)
                {
                    $privKey = [System.Security.Cryptography.RSACryptoServiceProvider]$cert.PrivateKey
                    if ($privKey.CspKeyContainerInfo.Exportable)
                    {
                        $p12bytes = $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType] "Pfx", $password)
                        return $p12bytes
                    }
                    else
                    {
                        throw "Private key is non-exportable"
                    }
                }
                else
                {
                    throw "Private key is not installed" 
                }
            }
        }
        else
        {
            throw "No certificate is currently bound to the site named $site_name"	
        }
    }
    else
    {
        throw "Unable to locate IIS web site named $site_name"	
    }
}