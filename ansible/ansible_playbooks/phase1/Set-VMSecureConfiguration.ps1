# Update HV Server Firmware   **THIS WILL BE LEFT OFF FOR NOW, WORKING WITH HPE FOR AUTOMATION**
    # ISO file from "\\stp-it227\it\Server Software\HP\HP SPP\"

#Write-Host "Looking for AD Powershell Module."
#if (!(Get-Command 'Get-ADGroupMember' -ErrorAction SilentlyContinue)) {
#    try {
#        Write-Host "AD Powershell module not installed."
#        Import-Module ServerManager -ErrorAction Stop
#        Install-WindowsFeature "RSAT-AD-PowerShell" -IncludeAllSubFeature -ErrorAction Stop
#    } catch {
#        Write-Error "AD Powershell module install failed."
#        break
#    }
#} else {
#    Write-Host "The AD Powershell Module is installed."
#}

# Install Crowdstrike
# If Crowdstrike is installed
#if ($true) {
    # Decrypt the authorization token
    # Uninstall Crowdstrike
    #.\CsUninstallTool.exe /quiet MAINTENANCE_TOKEN=2a3a405fbb99491174febbf9d5690727cfe9eaaccf43c32daed0ed96e6b43eb8 #Update this with the correct token.
#}
Function Initialize-Neo {
    param (
        [string]$assetPath
        )
        
    # Loads the list of configuration settings.

    # Load the variables from a csv file
    $variables = Import-Csv "$($assetPath)neo.csv"

    Write-Host "Loading Neo..."
    $neo = @{}

    foreach ($item in $variables) {
        # Split arrays by comma.
        if ($item.Type -eq "array") {
            $neo[$item.name] = $item.Value.Split(',')
        # Set False values to null since [bool]"False" = $true
        } elseif ($item.Type -eq "bool") {
            if ($item.Value -eq "false") {
                $item.Value = ""
            }    
            $neo[$item.Name] = [bool]$item.Value
        # No need to touch integers or strings
        } else {
            $neo[$item.Name] = $item.Value
        }
        Write-Host "Loaded $($item.Description) of type $($item.Type) and value $($neo[$item.Name])"
    }
    $Global:Neo=$neo
}

# Select time zone using $tzselect variable.
function Set-StoreTimeZone {
    Switch ($storeTz) {
        1 {
            $tz = "Eastern Standard Time"
            $utc = "5"
        }
        2 {
            $tz = "Central Standard Time"
            $utc = "6"
        }
        3 {
            $tz = "Mountain Standard Time"
            $utc = "7"
        }
        4 {
            $tz = "US Mountain Standard Time"
            $utc = "7"
        }
        5 {
            $tz = "Pacific Standard Time"
            $utc = "8"
        }
        6 {
            $tz = "Alaskan Standard Time"
            $utc = "9"
        }
        7 {
            $tz = "Hawaiian Standard Time"
            $utc = "10"
        }
        default {
            Write-Error "Time zone selection not valid.
            Defaulting to Eastern Time"

            $tz = "Eastern Standard Time"
            $utc = "5"
        }
    }

    Set-TimeZone -Id $tz
    $tznew = (Get-TimeZone).Id

    if ($tz -eq $tznew) {
        Write-Host "Time zone set."
    } else {
        Write-Warning "Time zone settings do not match.
        Check settings manually."
    }
}

$assetPath = "\\stp-it227\IT\Retail Stores\Powershell_Scripts\Assets\"

Initialize-Neo $assetPath

$storeTz = $neo.tzSelect

Set-StoreTimeZone

Copy-Item "\\stp-it227\App Installs\Crowdstrike\WindowsSensor.exe" "C:\temp\WindowsSensor.exe"
Set-Location C:\Temp
.\WindowsSensor.exe /install /quiet /norestart CID=FAA122281AE74AC99A41598A35C684B2-18

# Disable NetBIOS over TCP/IP on all NICs
    # Check NetBIOS over TCP\IP
    # Get list of NetBIOS GUIDs
$nbGUIDs = @()
$key = "HKLM:SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces"
$keys = Get-ChildItem $key

foreach ($object in $keys) {
    $nbGUIDs += (($object.pschildname).TrimStart("Tcpip_"))
}

    # Get list of interface GUIDs.
$ifinfo = Get-NetAdapterAdvancedProperty -AllProperties -IncludeHidden -RegistryKeyword NetCfgInstanceId

    # Find set of all GUIDs in NetBIOS\interface

foreach ($object in $ifinfo) {

    if (($object.RegistryValue) -in $nbGUIDs) {
        $GUID = "Tcpip_" + ([string]$object.RegistryValue)
        $NetBIOSstate = (Get-ItemProperty "$key\$GUID").NetbiosOptions
        
        if (($NetBIOSstate -ne 2) -or ($null -eq $NetBIOSstate)) {
            Set-ItemProperty -Path "$key\$GUID" -Name "NetbiosOptions" -Value 2
            Write-Host "NetBios over TCP\IP is now disabled."
        } else {
            Write-Host "NetBios over TCP\IP has already been disabled."
        }
    }
}

# Apply Sierra Default template to IIS Crypto
#Invoke-Command "\\stp-it227\IT\Retail Stores\Powershell_Scripts\Assets\cryptoCli.exe"
Copy-Item "\\stp-it227\IT\Retail Stores\Powershell_Scripts\Assets\cryptoCli.exe" "C:\temp\cryptoCli.exe"
Set-Location C:\Temp
.\cryptoCli.exe /template "\\stp-it227\IT\Retail Stores\Powershell_Scripts\Assets\SierraDefaults.ictpl"

# Mitigation Keys 
$path = "\\stp-it227\IT\Retail Stores\Powershell_Scripts\Assets"

    # Load XML config file.
$mitigate = New-Object -TypeName XML
$mitigate.Load("$path\mitigate.xml")

$list = ("software","system")

foreach ($object in $list) {
    #$hierarchy = ".mitigate.values.$object.reg"
    $group = $mitigate.mitigate.values.$object.reg

    foreach ($object in $group) {
        # Check each registry value to see if it matches expected.
        $returnValue = [string](Get-ItemPropertyValue "Registry::$($object.key)" -Name $object.name -ErrorAction SilentlyContinue)

        if (!($returnValue)) {
            $key = Get-Item -Path "Registry::$($object.key)" -ErrorAction SilentlyContinue

            if (!($key)) {
                Write-Host "Key does not exist. Creating."
                New-Item "Registry::$($object.Key)" -Force
            }
            
            New-ItemProperty "Registry::$($object.key)" -Name $object.name -Value $object.value
            Write-Host "Mitigation key, $($object.name), has been created and set."
        
        } elseif ($returnvalue -ne $object.value) {
            # Set-ItemPropertyValue to $object.value
            Set-ItemProperty "Registry::$($object.key)" -Name $object.name -Value $object.value
            Write-Host "Mitigation key, $($object.name), has been set."

        } else {
            Write-Host "Mitigation keys have already been set."
        }
    }
}

# Disable SMB1
    # Verify SMB1 disabled
    # Expected Value is False
$status = (Get-SmbServerConfiguration).EnableSMB1Protocol

if (!($status -eq $false)) {
    Set-SmbServerConfiguration -EnableSMB1Protocol $false
    Write-Host "SMB1 is now disabled."
} else {
    Write-Host "SMB1 has already been disabled."
}

# Add SCCM to ALL servers from "\\stp-it227\it\Retail Stores\Documentation\SCCM"
# CCMSETUP.exe /mp:stp-sccmmp81.stp.local SMSMP= sccmmp81.stp.local SMSSITECODE=STP
Copy-Item "\\stp-it227\IT\Retail Stores\Documentation\SCCM\CCMSETUP.exe" "C:\temp\CCMSETUP.exe"
Set-Location C:\Temp
.\CCMSETUP.exe /mp:stp-sccmmp81.stp.local SMSMP= sccmmp81.stp.local SMSSITECODE=STP
    # Once SCCM is added, create a ticket to let Cognizant and all others know it has been added
Write-Host "SCCM successfully installed. Be sure to create a ticket notifying Cognizant and others that SCCM has been added."


# Add the Security Group "WSUS_Excluded" to the Server Object in Active Directory to disable WSUS Updates
    # Add to WSUS_exclude group
    # get-adcomputer then get-adgroupmembership, decide if it's already part of the group WSUS and if not, set-adgroupmember ensure ad-powershell module is installed
#if (!(Get-ADGroup -filter {Name -eq "WSUS_Excluded"})) {
#    Set-ADGroup -Server stp-dc4 -Identity "CN=WSUS_Excluded,OU=Sierra Security Groups,DC=STP,DC=LOCAL" -PassThru
#} else {
#    Write-Host "This server is already part of the AD Group 'WSUS_Excluded'."
#}
# Commented out the WSUS_excluded portion of this script as the Group policy pushing WSUS is gone (According to James O'Dell)

# .\shutdown.exe \r \t 0