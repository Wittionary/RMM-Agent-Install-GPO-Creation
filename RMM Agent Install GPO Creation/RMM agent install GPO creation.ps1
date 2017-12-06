﻿Param(
    #[Parameter(Mandatory=$True,Position=1)]
    [string]$organizationID, # The organization's ID that you've defined in Kaseya (System > Orgs/Groups/Depts/Staff > Manage)

    [switch]$servers, # Pick only ONE of these switches.
    [switch]$workstations,
    [switch]$both 
)
# TODO: Exit script if more than one switch is selected

<# --------------------------------------------------------------------------------------------------------------
'Kaseya Agent Deployment GPO' creation
Version: 0.0.1
Made by: Witt Allen
Objective: Create a GPO that installs a Kaseya agent based on filters on a WMI query (servers, workstations, both)

DEPENDANCIES & ASSUMPTIONS:
- Script will be ran as Administrator
- Script will be ran on a Domain Controller
- Server's OS can use WMI filtering
- Imported modules are supported on Server's OS
- Server has .NET installed
- Assumes there are only two DC objects (ex. DC=CONTOSO,DC=COM). See Set-GPRegistryValue section
- At least one domain controller in the domain is running Microsoft Windows Server 2003 or later

NOTES:
- WMI Filters are not evaluated on Microsoft Windows® 2000. The filter is ignored.
    A GPO targeted to a Windows 2000 machine will always apply the GPO regardless of the WMI query.
    Source: https://technet.microsoft.com/en-us/library/cc770562(v=ws.11).aspx  

GENERAL TODO:
- Create event log entries when stuff happens
# --------------------------------------------------------------------------------------------------------------
#>
import-module GroupPolicy
# import-module SDM-GPMC    #To reduce dependancy on a third party, try to not use this module if possible 


$agentInstallScript = "RMM Agent Install.ps1"
$vsaURL = "https://vsa.data-blue.com"
$agentEXE = "KcsSetup.exe"
$agentSwitches = " /e /g=root." + $organizationID + " /c /j /s" # Switches: http://help.kaseya.com/WebHelp/EN/VSA/9040000/#493.htm
$gpoName = "RMM Agent Install"
$gpoComment = "Used by Data Blue to deploy RMM agent."
$gpoDomain = (Get-WmiObject win32_computersystem).Domain
$gpoServer = (Get-WmiObject win32_computersystem).DNSHostName+"."+(Get-WmiObject win32_computersystem).Domain #FQDN
$companyName = "Data Blue"
$regkeyPath = "HKLM:\System\CurrentControlSet\Services\NTDS\Parameters"
$execPolicy = Get-ExecutionPolicy
$DC = $gpoDomain -split "\." # Subdivide domain into DC objects
$scriptFilePath = "\\"
$scriptFilePath += $gpoDomain
$scriptFilePath += "\NETLOGON\"
$scriptFilePath += $agentInstallScript

# TODO: Add this execution policy check on the Kaseya side so this script will run
# Check execution policy, set to RemoteSigned, and revert to prior setting at end of script
Set-ExecutionPolicy RemoteSigned -Force


# Get parameter passed to script to know what to create WMI filter against (srv, wks, both)
# https://stackoverflow.com/questions/5592531/how-to-pass-an-argument-to-a-powershell-script
# https://technet.microsoft.com/en-us/library/jj554301.aspx

 

# ------------------------ Check for WMI Filters existing. If they don't exist, create them. ------------------------------------------------
# TODO: Test section
if (!(Get-GPWmiFilter -Name 'Servers') -or !(Get-GPWmiFilter -Name 'Workstations')) {
    $key = get-item -literalpath $regkeyPath

    #If regkey that let's us create WMI filters doesn't exist, create it and set value to 1
    if ($Key.GetValue("Allow System Only Change", $null) -eq $null) { 
        new-itemproperty $regkeyPath -name "Allow System Only Change" -value 1 -propertyType dword

    #If regkey that let's us create WMI filters exists with a non-one value, set value to 1
    } elseIf ($Key.GetValue("Allow System Only Change", $null) -ne 1) { 
        set-itemproperty -Path $regkeyPath -Name "Allow System Only Change" -value 1

    }

    # Create-WMIFilters 

    New-GPWmiFilter -Name 'Servers' -Expression 'Select * from WIN32_OperatingSystem where (ProductType=3 or ProductType=2)' `
        -Description 'All server operating systems. Used by '+$companyName+' to deploy RMM agents.' 
    New-GPWmiFilter -Name 'Workstations' -Expression 'Select * from WIN32_OperatingSystem where ProductType=1' `
        -Description 'All non-server operating systems. Used by '+$companyName+' to deploy RMM agents.' 
}

# ------------------------------------------------------ Create script that GPO will run ------------------------------------------------
# TODO: Dynamically install delegated agent for specific org
# Check if agent installer exists in NETLOGON (KcsSetup.exe)
if (Test-Path \\$gpoDomain\NETLOGON\$agentEXE){
    # If installer is more than 1 month old, delete it and download new one
} else { # Agent installer doesn't exist
    # Download agent installer
}

# https://blog.jourdant.me/post/3-ways-to-download-files-with-powershell
# Download appropriate agent installer for the org (datablue.root)
# https://vsa.data-blue.com:443/deploy/#/<org>.root



# Check if agent installer exists in NETLOGON (KcsSetup.exe) and there's no install script already
if (Test-Path \\$gpoDomain\NETLOGON\$agentEXE -and !(Test-Path \\$gpoDomain\NETLOGON\$agentInstallScript)) {
    # Creates an agent install powershell script in C:\ in case of permission issues and then move it to NETLOGON
    New-Item C:\$agentInstallScript  -ItemType file -Value "& \\$gpoDomain\NETLOGON\$agentEXE+$agentSwitches"
    Move-Item -Path C:\$agentInstallScript -Destination \\$gpoDomain\NETLOGON\$agentInstallScript
    
    # New-Item \\$gpoDomain\NETLOGON\$agentInstallScript -ItemType file -Value "& \\$gpoDomain\NETLOGON\$agentEXE"
}
else {
    # Throw error
    # Write to event log
}

# ------------------------------------------------------ Create GPO ------------------------------------------------

# This will allow us to deploy updated versions of this GPO from Kaseya without having to edit each one manually
if (Get-GPO -name $gpoName) { # Check if a RMM Agent Install GPO already exists
    Remove-GPO -name $gpoName -Domain $gpoDomain -Server $gpoServer # Delete it if yes
}

New-GPO -Name $gpoName -Comment $gpoComment -Domain $gpoDomain -Server $gpoServer
& repadmin /syncall #Sync the new GPO across all DCs
$gpo = Get-GPO -Name $gpoName 

# TODO: Allow for more than two DC objects (Ex: DC=blog,DC=contoso,DC=com)
$objDC = "DC="
$objDC += $DC[0]
$objDC += ",DC="
$objDC += $DC[1]

$gpoID = "{"
$gpoID += $gpo.id
$gpoID += "}"

$regGpoId = "cn="
$regGpoId += $gpoID
$regGpoId += ",cn=policies,cn=system,"
$regGpoId += $objDC

$fileSysPath = "\\"
$fileSysPath += $gpoDomain
$fileSysPath += "\SysVol\"
$fileSysPath += $gpoDomain
$fileSysPath += "\Policies\"
$fileSysPath += $gpoID
$fileSysPath += "\Machine"

New-GPLink -guid $gpo.ID -Target $objDC

$regkeyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine\Scripts\Startup\"
# $regkeyPath9 = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine\Scripts\Startup\9"
# $regkeyPath99 = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine\Scripts\Startup\9\9"
$key = get-item -literalpath $regkeyPath
#If regkey that let's us prioritize Startup scripts doesn't exist, create it

<#
# This would set the startup script locally. 
# Instead, we want to tell the GPO which regkeys need to have what values.
new-item $regkeyPath -name 9 #...\Startup\9
new-itemproperty $regkeyPath9 -name "DisplayName" -value $gpoName -propertyType string
new-itemproperty $regkeyPath9 -name "FileSysPath" -value $fileSysPath -propertyType string
new-itemproperty $regkeyPath9 -name "GPO-ID" -value $regGpoId -propertyType string
new-itemproperty $regkeyPath9 -name "GPOName" -value $gpoID -propertyType string
new-itemproperty $regkeyPath9 -name "PSScriptOrder" -value 1 -propertyType DWORD
new-itemproperty $regkeyPath9 -name "SOM-ID" -value $objDC -propertyType string

new-item $regkeyPath9 -name 9 #...\Startup\9\9
new-itemproperty $regkeyPath99 -name "ErrorCode" -value 0 -propertyType DWORD
new-itemproperty $regkeyPath99 -name "ExecTime" -value 0 -propertyType QWORD
new-itemproperty $regkeyPath99 -name "Parameters" -value "0" -propertyType string #Not 100% sure what this guy is doing
New-ItemProperty $regkeyPath99 -Name "IsPowershell" -Value 1 -PropertyType DWORD
new-itemproperty $regkeyPath99 -name "Script" -value $scriptFilePath -propertyType string
#>

# TODO: Check for other scripts with same priority. Currently it will be creating a low-priority Startup script
# Cmdlet documentation: https://technet.microsoft.com/en-us/library/hh967458(v=wps.630).aspx
# ---------------------- STRING regkeys for 9 path
Set-GPRegistryValue -guid $gpo.ID -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine\Scripts\Startup\9" -Domain $gpoDomain -Server $gpoServer `
    -ValueName "DisplayName", "FileSysPath", "GPO-ID", "GPOName", "SOM-ID" -Type string `
    -Value $gpoName, $fileSysPath, $regGpoId, $gpoID, $objDC -Additive

# ---------------------- DWORD regkey for 9 path
Set-GPRegistryValue -guid $gpo.ID -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine\Scripts\Startup\9" -Domain $gpoDomain -Server $gpoServer `
    -ValueName "PSScriptOrder" -Type dword `
    -Value 9 -Additive

# ---------------------- STRING regkeys for 9\9 path
Set-GPRegistryValue -guid $gpo.ID -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine\Scripts\Startup\9\9" -Domain $gpoDomain -Server $gpoServer `
    -ValueName "Parameters", "Script" -Type string `
    -Value "0", $scriptFilePath -Additive

# ---------------------- DWORD regkey for 9\9 path
Set-GPRegistryValue -guid $gpo.ID -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine\Scripts\Startup\9\9" -Domain $gpoDomain -Server $gpoServer `
    -ValueName "ErrorCode" -Type dword `
    -Value 0 -Additive

# ---------------------- QWORD regkey for 9\9 path
Set-GPRegistryValue -guid $gpo.ID -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine\Scripts\Startup\9\9" -Domain $gpoDomain -Server $gpoServer `
    -ValueName "ExecTime" -Type qword `
    -Value 0 -Additive
    







# ------------------------------------------------------ End of Script ------------------------------------------------
# Reverting execution policy to whatever it was
Set-ExecutionPolicy $execPolicy -Force

# ------------------------------------------------------------ Functions -------------------------------------------------------

# --------------------------------------------------- Start of WMI Filter Function ---------------------------------------------
# Based on function from https://gallery.technet.microsoft.com/scriptcenter/f1491111-9f5d-4c83-b436-537eca9e8d94
Function Create-WMIFilters { 
    # Importing or adding a WMI Filter object into AD is a system only operation.  
    # You need to enable system only changes on a domain controller for a successful import.  
    # To do this, on the domain controller you are using for importing, open the registry editor and create the following registry value. 
    # 
    # Key: HKLM\System\CurrentControlSet\Services\NTDS\Parameters  
    # Value Name: Allow System Only Change  
    # Value Type: REG_DWORD  
    # Value Data: 1 (Binary) 
    # 
    # Put this somewhere in your master code: new-itemproperty "HKLM:\System\CurrentControlSet\Services\NTDS\Parameters" -name "Allow System Only Change" -value 1 -propertyType dword 


    # Name,Query,Description 
    $WMIFilters = @(   ('Workstations', 'Select * from WIN32_OperatingSystem where ProductType=1', 'All non-server operating systems. Used by Data Blue to deploy RMM agents.'), 
        ('Servers', 'Select * from WIN32_OperatingSystem where (ProductType=3 or ProductType=2)', 'All server operating systems. Used by Data Blue to deploy RMM agents.') 
    ) # TODO: Replace 'Data Blue' with $companyName in WMI filter descriptions. It will take some funky concatenation
 
    $defaultNamingContext = (get-adrootdse).defaultnamingcontext  
    $configurationNamingContext = (get-adrootdse).configurationNamingContext  
    $msWMIAuthor = "Administrator@" + [System.DirectoryServices.ActiveDirectory.Domain]::getcurrentdomain().name 
     
    for ($i = 0; $i -lt $WMIFilters.Count; $i++) { 
        $WMIGUID = [string]"{" + ([System.Guid]::NewGuid()) + "}"    
        $WMIDN = "CN=" + $WMIGUID + ",CN=SOM,CN=WMIPolicy,CN=System," + $defaultNamingContext 
        $WMICN = $WMIGUID 
        $WMIdistinguishedname = $WMIDN 
        $WMIID = $WMIGUID 
 
        $now = (Get-Date).ToUniversalTime() 
        $msWMICreationDate = ($now.Year).ToString("0000") + ($now.Month).ToString("00") + ($now.Day).ToString("00") + ($now.Hour).ToString("00") + ($now.Minute).ToString("00") + ($now.Second).ToString("00") + "." + ($now.Millisecond * 1000).ToString("000000") + "-000" 
 
        $msWMIName = $WMIFilters[$i][0] 
        $msWMIParm1 = $WMIFilters[$i][2] + " " 
        $msWMIParm2 = "1;3;10;" + $WMIFilters[$i][1].Length.ToString() + ";WQL;root\CIMv2;" + $WMIFilters[$i][1] + ";" 
 
        $Attr = @{"msWMI-Name" = $msWMIName; "msWMI-Parm1" = $msWMIParm1; "msWMI-Parm2" = $msWMIParm2; "msWMI-Author" = $msWMIAuthor; "msWMI-ID" = $WMIID; "instanceType" = 4; "showInAdvancedViewOnly" = "TRUE"; "distinguishedname" = $WMIdistinguishedname; "msWMI-ChangeDate" = $msWMICreationDate; "msWMI-CreationDate" = $msWMICreationDate} 
        $WMIPath = ("CN=SOM,CN=WMIPolicy,CN=System," + $defaultNamingContext) 
     
        New-ADObject -name $WMICN -type "msWMI-Som" -Path $WMIPath -OtherAttributes $Attr 
    } 
 
}
# --------------------------------------------------- End of WMI Filter Function ---------------------------------------------

# --------------------------------------------------- Start of GPWmiFilter.psm1 ------------------------------------------------
# Source: https://gallery.technet.microsoft.com/scriptcenter/Group-Policy-WMI-filter-38a188f3#content
# Copyright (C)2012 Microsoft Corporation. All rights reserved.
# For personal use only.  Provided AS IS and WITH ALL FAULTS.  
#
# GPWmiFilter module v1.0.1
#
# binyi@microsoft.com

Import-Module ActiveDirectory
Import-Module GroupPolicy

function New-GPWmiFilter {
    <#
.SYNOPSIS
Create a new WMI filter for Group Policy with given name, WQL query and description.

.DESCRIPTION
The New-GPWmiFilter function create an AD object for WMI filter with specific name, WQL query expressions and description.
With -PassThru switch, it output the WMIFilter instance which can be assigned to GPO.WMIFilter property.

.PARAMETER Name
The name of new WMI filter.

.PARAMETER Expression
The expression(s) of WQL query in new WMI filter. Pass an array to this parameter if multiple WQL queries applied.

.PARAMETER Description
The description text of the WMI filter (optional). 

.PARAMETER PassThru
Output the new WMI filter instance with this switch.

.EXAMPLE
New-GPWmiFilter -Name 'Virtual Machines' -Expression 'SELECT * FROM Win32_ComputerSystem WHERE Model = "Virtual Machine"' -Description 'Only apply on virtual machines'

Create a WMI filter to apply GPO only on virtual machines

.EXAMPLE 
$filter = New-GPWmiFilter -Name 'Workstation 32-bit' -Expression 'SELECT * FROM WIN32_OperatingSystem WHERE ProductType=1', 'SELECT * FROM Win32_Processor WHERE AddressWidth = "32"' -PassThru
$gpo = New-GPO -Name "Test GPO"
$gpo.WmiFilter = $filter

Create a WMI filter for 32-bit work station and link it to a new GPO named "Test GPO".

.NOTES
Domain administrator priviledge is required for executing this cmdlet

#>
    [CmdletBinding()] 
    Param
    (
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, Position = 0)]
        [ValidateNotNull()]
        [string] $Name,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, Position = 1)]
        [ValidateNotNull()]
        [string[]] $Expression,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 2)]
        [string] $Description,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 3)]
        [switch] $PassThru
    )
    if ($Expression.Count -lt 1) {
        Write-Error "At least one Expression Method is required to create a WMI Filter."
        return
    }

    $Guid = [System.Guid]::NewGuid()
    $defaultNamingContext = (Get-ADRootDSE).DefaultNamingContext 
    $msWMIAuthor = Get-Author
    $msWMICreationDate = (Get-Date).ToUniversalTime().ToString("yyyyMMddhhmmss.ffffff-000")
    $WMIGUID = "{$Guid}"
    $WMIDistinguishedName = "CN=$WMIGUID,CN=SOM,CN=WMIPolicy,CN=System,$defaultNamingContext"
    $msWMIParm1 = "$Description "
    $msWMIParm2 = $Expression.Count.ToString() + ";"
    $Expression | ForEach-Object {
        $msWMIParm2 += "3;10;" + $_.Length + ";WQL;root\CIMv2;" + $_ + ";"
    }

    $Attr = @{
        "msWMI-Name"             = $Name;
        "msWMI-Parm1"            = $msWMIParm1;
        "msWMI-Parm2"            = $msWMIParm2;
        "msWMI-Author"           = $msWMIAuthor;
        "msWMI-ID"               = $WMIGUID;
        "instanceType"           = 4;
        "showInAdvancedViewOnly" = "TRUE";
        "distinguishedname"      = $WMIDistinguishedName;
        "msWMI-ChangeDate"       = $msWMICreationDate; 
        "msWMI-CreationDate"     = $msWMICreationDate
    }
    
    $WMIPath = ("CN=SOM,CN=WMIPolicy,CN=System,$defaultNamingContext")

    Enable-ADSystemOnlyChange

    $ADObject = New-ADObject -Name $WMIGUID -Type "msWMI-Som" -Path $WMIPath -OtherAttributes $Attr -PassThru

    if ($PassThru) {
        ConvertTo-WmiFilter $ADObject | Write-Output
    }
}

function Get-GPWmiFilter {
    <#
.SYNOPSIS
Get a WMI filter in current domain

.DESCRIPTION
The Get-GPWmiFilter function query WMI filter(s) in current domain with specific name or GUID.

.PARAMETER Guid
The guid of WMI filter you want to query out.

.PARAMETER Name
The name of WMI filter you want to query out.

.PARAMETER All
Query all WMI filters in current domain With this switch.

.EXAMPLE
Get-GPWmiFilter -Name 'Virtual Machines'

Get WMI filter(s) with the name 'Virtual Machines'

.EXAMPLE 
Get-GPWmiFilter -All

Get all WMI filters in current domain

#>
    Param
    (
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, Position = 0, ParameterSetName = "ByGUID")]
        [ValidateNotNull()]
        [Guid[]] $Guid,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, Position = 0, ParameterSetName = "ByName")]
        [ValidateNotNull()]
        [string[]] $Name,
        
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, Position = 0, ParameterSetName = "GetAll")]
        [ValidateNotNull()]
        [switch] $All
    )
    if ($Guid) {
        $ADObject = Get-WMIFilterInADObject -Guid $Guid
    }
    elseif ($Name) {
        $ADObject = Get-WMIFilterInADObject -Name $Name
    }
    elseif ($All) {
        $ADObject = Get-WMIFilterInADObject -All
    }
    ConvertTo-WmiFilter $ADObject | Write-Output
}

function Remove-GPWmiFilter {
    <#
.SYNOPSIS
Remove a WMI filter from current domain

.DESCRIPTION
The Remove-GPWmiFilter function remove WMI filter(s) in current domain with specific name or GUID.

.PARAMETER Guid
The guid of WMI filter you want to remove.

.PARAMETER Name
The name of WMI filter you want to remove.

.EXAMPLE
Remove-GPWmiFilter -Name 'Virtual Machines'

Remove the WMI filter with name 'Virtual Machines'

.NOTES
Domain administrator priviledge is required for executing this cmdlet

#>
    [CmdletBinding(DefaultParametersetName = "ByGUID")] 
    Param
    (
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, Position = 0, ParameterSetName = "ByGUID")]
        [ValidateNotNull()]
        [Guid[]] $Guid,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, Position = 0, ParameterSetName = "ByName")]
        [ValidateNotNull()]
        [string[]] $Name
    )
    if ($Guid) {
        $ADObject = Get-WMIFilterInADObject -Guid $Guid
    }
    elseif ($Name) {
        $ADObject = Get-WMIFilterInADObject -Name $Name
    }
    $ADObject | ForEach-Object {
        if ($_.DistinguishedName) {
            Remove-ADObject $_ -Confirm:$false
        }
    }
}

function Set-GPWmiFilter {
    <#
.SYNOPSIS
Get a WMI filter in current domain and update the content of it

.DESCRIPTION
The Set-GPWmiFilter function query WMI filter(s) in current domain with specific name or GUID and then update the content of it.

.PARAMETER Guid
The guid of WMI filter you want to query out.

.PARAMETER Name
The name of WMI filter you want to query out.

.PARAMETER Expression
The expression(s) of WQL query in new WMI filter. Pass an array to this parameter if multiple WQL queries applied.

.PARAMETER Description
The description text of the WMI filter (optional). 

.PARAMETER PassThru
Output the updated WMI filter instance with this switch.

.EXAMPLE
Set-GPWmiFilter -Name 'Workstations' -Expression 'SELECT * FROM Win32_OperatingSystem WHERE ProductType = "1"'

Set WMI filter named with "Workstations" to specific WQL query

.NOTES
Domain administrator priviledge is required for executing this cmdlet.
Either -Expression or -Description should be assigned when executing.

#>
    Param
    (
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, Position = 0, ParameterSetName = "ByGUID")]
        [ValidateNotNull()]
        [Guid[]] $Guid,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, Position = 0, ParameterSetName = "ByName")]
        [ValidateNotNull()]
        [string[]] $Name,
        
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 1)]
        [ValidateNotNull()]
        [string[]] $Expression,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 2)]
        [string] $Description,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 3)]
        [switch] $PassThru

    )
    if ($Guid) {
        $ADObject = Get-WMIFilterInADObject -Guid $Guid
    }
    elseif ($Name) {
        $ADObject = Get-WMIFilterInADObject -Name $Name
    }
    $msWMIAuthor = Get-Author
    $msWMIChangeDate = (Get-Date).ToUniversalTime().ToString("yyyyMMddhhmmss.ffffff-000")
    $Attr = @{
        "msWMI-Author"     = $msWMIAuthor;
        "msWMI-ChangeDate" = $msWMIChangeDate;
    }
    if ($Expression) {
        $msWMIParm2 = $Expression.Count.ToString() + ";"
        $Expression | ForEach-Object {
            $msWMIParm2 += "3;10;" + $_.Length + ";WQL;root\CIMv2;" + $_ + ";"
        }
        $Attr.Add("msWMI-Parm2", $msWMIParm2);
    }
    elseif ($Description) {
        $msWMIParm1 = $Description + " "
        $Attr.Add("msWMI-Parm2", $msWMIParm2);
    }
    else {
        Write-Warning "No content need to be set. Please set either Expression or Description."
        return
    }

    Enable-ADSystemOnlyChange

    $ADObject | ForEach-Object {
        if ($_.DistinguishedName) {
            Set-ADObject -Identity $_ -Replace $Attr
            if ($PassThru) {
                ConvertTo-WmiFilter $ADObject | Write-Output
            }
        }
    }
}

function Rename-GPWmiFilter {
    <#
.SYNOPSIS
Get a WMI filter in current domain and rename it

.DESCRIPTION
The Rename-GPWmiFilter function query WMI filter in current domain with specific name or GUID and then change it to a new name.

.PARAMETER Guid
The guid of WMI filter you want to query out.

.PARAMETER Name
The name of WMI filter you want to query out.

.PARAMETER TargetName
The new name of WMI filter.

.PARAMETER PassThru
Output the renamed WMI filter instance with this switch.

.EXAMPLE
Rename-GPWmiFilter -Name 'Workstations' -TargetName 'Client Machines'

Rename WMI filter "Workstations" to "Client Machines"

.NOTES
Domain administrator priviledge is required for executing this cmdlet.

#>
    Param
    (
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, Position = 0, ParameterSetName = "ByGUID")]
        [ValidateNotNull()]
        [Guid[]] $Guid,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, Position = 0, ParameterSetName = "ByName")]
        [ValidateNotNull()]
        [string[]] $Name,
        
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, Position = 1)]
        [ValidateNotNull()]
        [string] $TargetName,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 3)]
        [switch] $PassThru
    )
    if ($Guid) {
        $ADObject = Get-WMIFilterInADObject -Guid $Guid
    }
    elseif ($Name) {
        $ADObject = Get-WMIFilterInADObject -Name $Name
    }

    if (!$Name) {
        $Name = $ADObject."msWMI-Name"
    }
    if ($TargetName -eq $Name) {
        return
    }

    $msWMIAuthor = Get-Author
    $msWMIChangeDate = (Get-Date).ToUniversalTime().ToString("yyyyMMddhhmmss.ffffff-000")
    $Attr = @{
        "msWMI-Author"     = $msWMIAuthor;
        "msWMI-ChangeDate" = $msWMIChangeDate; 
        "msWMI-Name"       = $TargetName;
    }

    Enable-ADSystemOnlyChange

    $ADObject | ForEach-Object {
        if ($_.DistinguishedName) {
            Set-ADObject -Identity $_ -Replace $Attr
            if ($PassThru) {
                ConvertTo-WmiFilter $ADObject | Write-Output
            }
        }
    }
}

####################################################################### Helper functions #####################################################################

function ConvertTo-WmiFilter([Microsoft.ActiveDirectory.Management.ADObject[]] $ADObject) {
    $gpDomain = New-Object -Type Microsoft.GroupPolicy.GPDomain
    $ADObject | ForEach-Object {
        $path = 'MSFT_SomFilter.Domain="' + $gpDomain.DomainName + '",ID="' + $_.Name + '"'
        try {
            $filter = $gpDomain.GetWmiFilter($path)
        }
        catch { }
        if ($filter) {
            [Guid]$Guid = $_.Name.Substring(1, $_.Name.Length - 2)
            $filter | Add-Member -MemberType NoteProperty -Name Guid -Value $Guid -PassThru | Add-Member -MemberType NoteProperty -Name Content -Value $_."msWMI-Parm2" -PassThru | Write-Output
        }
    }
}

function ConvertTo-ADObject([Microsoft.GroupPolicy.WmiFilter[]] $WmiFilter) {
    $wmiFilterAttr = "msWMI-Name", "msWMI-Parm1", "msWMI-Parm2", "msWMI-Author", "msWMI-ID"
    $WmiFilter | ForEach-Object {
        $match = $_.Path | Select-String -Pattern 'ID=\"\{(?<id>[\-|a-f|0-9]+)\}\"' | Select-Object -Expand Matches | ForEach-Object { $_.Groups[1] }
        [Guid]$Guid = $match.Value
        $ldapFilter = "(&(objectClass=msWMI-Som)(Name={$Guid}))"
        Get-ADObject -LDAPFilter $ldapFilter -Properties $wmiFilterAttr | Write-Output
    }
}

function Enable-ADSystemOnlyChange([switch] $disable) {
    $valueData = 1
    if ($disable) {
        $valueData = 0
    }
    $key = Get-Item HKLM:\System\CurrentControlSet\Services\NTDS\Parameters -ErrorAction SilentlyContinue
    if (!$key) {
        New-Item HKLM:\System\CurrentControlSet\Services\NTDS\Parameters -ItemType RegistryKey | Out-Null
    }
    $kval = Get-ItemProperty HKLM:\System\CurrentControlSet\Services\NTDS\Parameters -Name "Allow System Only Change" -ErrorAction SilentlyContinue
    if (!$kval) {
        New-ItemProperty HKLM:\System\CurrentControlSet\Services\NTDS\Parameters -Name "Allow System Only Change" -Value $valueData -PropertyType DWORD | Out-Null
    }
    else {
        Set-ItemProperty HKLM:\System\CurrentControlSet\Services\NTDS\Parameters -Name "Allow System Only Change" -Value $valueData | Out-Null
    }
}

function Get-WMIFilterInADObject {
    Param(
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, Position = 0, ParameterSetName = "ByGUID")]
        [ValidateNotNull()]
        [Guid[]] $Guid,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, Position = 0, ParameterSetName = "ByName")]
        [ValidateNotNull()]
        [string[]] $Name,
        
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, Position = 0, ParameterSetName = "GetAll")]
        [ValidateNotNull()]
        [switch] $All

    )
    $wmiFilterAttr = "msWMI-Name", "msWMI-Parm1", "msWMI-Parm2", "msWMI-Author", "msWMI-ID"
    if ($Guid) {
        $Guid | ForEach-Object {
            $ldapFilter = "(&(objectClass=msWMI-Som)(Name={$_}))"
            Get-ADObject -LDAPFilter $ldapFilter -Properties $wmiFilterAttr | Write-Output
        }
    }
    elseif ($Name) {
        $Name | ForEach-Object {
            $ldapFilter = "(&(objectClass=msWMI-Som)(msWMI-Name=$_))"
            Get-ADObject -LDAPFilter $ldapFilter -Properties $wmiFilterAttr | Write-Output
        }
    }
    elseif ($All) {
        $ldapFilter = "(objectClass=msWMI-Som)"
        Get-ADObject -LDAPFilter $ldapFilter -Properties $wmiFilterAttr | Write-Output
    }
}

function Get-Author {
    $author = (Get-ADUser $env:USERNAME).UserPrincipalName
    if (!$author) {
        $author = (Get-ADUser $env:USERNAME).Name
    }
    if (!$author) {
        $author = $env:USERNAME
    }
    return $author
}


Export-ModuleMember -Function New-GPWmiFilter, Get-GPWmiFilter, Remove-GPWmiFilter, Set-GPWmiFilter, Rename-GPWmiFilter 
# --------------------------------------------------- End of GPWmiFilter.psm1 ------------------------------------------------