Param(
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

WMI Filters is only available if at least one domain controller in the domain is running Microsoft Windows Server™ 2003.
 The same is true for WMI Filtering on the Scope tab for Group Policy Objects .
 WMI Filters are not evaluated on Microsoft Windows® 2000.
  A GPO targeted to a Windows 2000 machine will always apply the GPO regardless of the query associated with the WMI Filter (the filter is ignored)
  Source: https://technet.microsoft.com/en-us/library/cc770562(v=ws.11).aspx  

GENERAL TODO:
- Create event log entries when stuff happens
# --------------------------------------------------------------------------------------------------------------
#>
import-module GroupPolicy
import-module SDM-GPMC    #To reduce dependancy on a third party, try to not use this module if possible 


$agentInstallScript = "RMM Agent Install.ps1"
$vsaURL = "https://vsa.data-blue.com"
$agentEXE = "KcsSetup.exe"
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

# Check execution policy, set to RemoteSigned, and revert to prior setting at end of script
Set-ExecutionPolicy RemoteSigned -Force


# Get parameter passed to script to know what to create WMI filter against (srv, wks, both)
# https://stackoverflow.com/questions/5592531/how-to-pass-an-argument-to-a-powershell-script
# https://technet.microsoft.com/en-us/library/jj554301.aspx



# ------------------------------------------------------ WMI Filter Function ------------------------------------------------

# Based on function from https://gallery.technet.microsoft.com/scriptcenter/f1491111-9f5d-4c83-b436-537eca9e8d94
Function Create-WMIFilters 
{ 
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
     
    for ($i = 0; $i -lt $WMIFilters.Count; $i++)  
    { 
        $WMIGUID = [string]"{"+([System.Guid]::NewGuid())+"}"    
        $WMIDN = "CN="+$WMIGUID+",CN=SOM,CN=WMIPolicy,CN=System,"+$defaultNamingContext 
        $WMICN = $WMIGUID 
        $WMIdistinguishedname = $WMIDN 
        $WMIID = $WMIGUID 
 
        $now = (Get-Date).ToUniversalTime() 
        $msWMICreationDate = ($now.Year).ToString("0000") + ($now.Month).ToString("00") + ($now.Day).ToString("00") + ($now.Hour).ToString("00") + ($now.Minute).ToString("00") + ($now.Second).ToString("00") + "." + ($now.Millisecond * 1000).ToString("000000") + "-000" 
 
        $msWMIName = $WMIFilters[$i][0] 
        $msWMIParm1 = $WMIFilters[$i][2] + " " 
        $msWMIParm2 = "1;3;10;" + $WMIFilters[$i][1].Length.ToString() + ";WQL;root\CIMv2;" + $WMIFilters[$i][1] + ";" 
 
        $Attr = @{"msWMI-Name" = $msWMIName;"msWMI-Parm1" = $msWMIParm1;"msWMI-Parm2" = $msWMIParm2;"msWMI-Author" = $msWMIAuthor;"msWMI-ID"=$WMIID;"instanceType" = 4;"showInAdvancedViewOnly" = "TRUE";"distinguishedname" = $WMIdistinguishedname;"msWMI-ChangeDate" = $msWMICreationDate; "msWMI-CreationDate" = $msWMICreationDate} 
        $WMIPath = ("CN=SOM,CN=WMIPolicy,CN=System,"+$defaultNamingContext) 
     
        New-ADObject -name $WMICN -type "msWMI-Som" -Path $WMIPath -OtherAttributes $Attr 
    } 
 
} 

# Check for WMI Filters existing. If they don't exist, create them. ------------------------------------------------
if (WMIfilters not exist) {
    $key = get-item -literalpath $regkeyPath

    #If regkey that let's us create WMI filters doesn't exist, create it and set value to 1
    if ($Key.GetValue("Allow System Only Change", $null) -eq $null) { 
        new-itemproperty $regkeyPath -name "Allow System Only Change" -value 1 -propertyType dword

    #If regkey that let's us create WMI filters exists with a non-one value, set value to 1
    } elseIf ($Key.GetValue("Allow System Only Change", $null) -ne 1) { 
        set-itemproperty -Path $regkeyPath -Name "Allow System Only Change" -value 1

    }

    Create-WMIFilters 
}

# ------------------------------------------------------ Create script that GPO will run ------------------------------------------------
<# TODO: Dynamically install delegated agent for specific org
# Check if agent installer exists in NETLOGON (KcsSetup.exe)
if (Test-Path \\$gpoDomain\NETLOGON\$agentEXE){
    # If installer is more than 1 month old, delete it and download new one
} else { # Agent installer doesn't exist
    # Download agent installer
}

https://blog.jourdant.me/post/3-ways-to-download-files-with-powershell
# Download appropriate agent installer for the org (datablue.root)
# https://vsa.data-blue.com:443/deploy/#/<org>.root
#>

# Check if agent installer exists in NETLOGON (KcsSetup.exe) and there's no install script already
if (Test-Path \\$gpoDomain\NETLOGON\$agentEXE -and !(Test-Path \\$gpoDomain\NETLOGON\$agentInstallScript)) {
    # TODO: Create it somewhere that won't have permission issues and then move it to NETLOGON 
    # Creates an agent install powershell script in NETLOGON
    New-Item \\$gpoDomain\NETLOGON\$agentInstallScript -ItemType file -Value "& \\$gpoDomain\NETLOGON\$agentEXE"
} else {
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