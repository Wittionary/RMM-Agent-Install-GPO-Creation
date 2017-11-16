<# 
'Kaseya Agent Deployment GPO' creation
Version: 0.0.1
Made by: Witt Allen
Objective: Create a GPO that installs a Kaseya agent based on filters on a WMI query (servers, workstations, both)

DEPENDANCIES & ASSUMPTIONS:
- This script is being run on a Domain Controller
- Server's OS can use WMI filtering
- Imported modules are supported on Server's OS

#>
$gpoName = "RMM Agent Install"
$companyName = "Data Blue"

# Check execution policy, set to remotesigned and revert to prior setting at end of script
# Check if a Kaseya Agent Deployment GPO already exists
# Delete it if yes
# This will allow us to deploy updated versions of this GPO from Kaseya without having to edit each one manually


# Get parameter passed to script to know what to create WMI filter against (srv, wks, both)
# https://stackoverflow.com/questions/5592531/how-to-pass-an-argument-to-a-powershell-script

import-module GroupPolicy #check for cmdlet existing then import module if not
import-module SDM-GPMC    #check for cmdlet existing then import module if not, try to not use this module if possible 

new-gpo -Name $gpoName

Set-GPPrefRegistryValue -name $gpoName

<# Based on function from https://gallery.technet.microsoft.com/scriptcenter/f1491111-9f5d-4c83-b436-537eca9e8d94

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
 
Create-WMIFilters 
#>