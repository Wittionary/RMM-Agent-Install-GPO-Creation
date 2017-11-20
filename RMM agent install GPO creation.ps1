﻿Param(
    #[Parameter(Mandatory=$True,Position=1)]
    [string]$organizationID, # The organization's ID that you've defined in Kaseya (System > Orgs/Groups/Depts/Staff > Manage

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

GENERAL TODO:
- Create event log entries when stuff happens
# --------------------------------------------------------------------------------------------------------------
#>
import-module GroupPolicy
import-module SDM-GPMC    #To reduce dependancy on a third party, try to not use this module if possible 

$vsaURL = "https://vsa.data-blue.com"
$agentEXE = "KcsSetup.exe"
$gpoName = "RMM Agent Install"
$gpoComment = "Used by Data Blue to deploy RMM agent."
$gpoDomain = (Get-WmiObject win32_computersystem).Domain
$gpoServer = (Get-WmiObject win32_computersystem).DNSHostName+"."+(Get-WmiObject win32_computersystem).Domain #FQDN
$companyName = "Data Blue"
$regkeyPath = "HKLM:\System\CurrentControlSet\Services\NTDS\Parameters"
$execPolicy = Get-ExecutionPolicy

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

# Check for WMI Filters existing. If they don't exist, create them.
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

# Check if agent installer exists in NETLOGON (KcsSetup.exe)
if (Test-Path \\$gpoDomain\NETLOGON\$agentEXE){
    # If installer is more than 1 month old, delete it and download new one
} else {
    # Throw error
    # Write to event log
}

# ------------------------------------------------------ Create GPO ------------------------------------------------
# Check if a RMM Agent Install GPO already exists
# Delete it if yes
# This will allow us to deploy updated versions of this GPO from Kaseya without having to edit each one manually

New-GPO -Name $gpoName -Comment $gpoComment -Domain $gpoDomain -Server $gpoServer

Set-GPPrefRegistryValue -name $gpoName


# ------------------------------------------------------ End of Script ------------------------------------------------
# Reverting execution policy to whatever it was
Set-ExecutionPolicy $execPolicy -Force