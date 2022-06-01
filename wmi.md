# WMI 101

*WMI = Windows Management Instrumentation*  
- https://docs.microsoft.com/en-us/windows/win32/wmisdk/wmi-architecture

--> Microsoft implementationn of CIM (Common Information Model) and  WBEM (Web Based Enterprise Management).  
--> Provides a uniform interface for applications/scripts to manage a local or remote computer or network.  

*WMIC = Command-Line interface for WMI*

<img src="./images/wmi-architecture.png" width="500"/>

## WMI Components

### Manaed Object Format (MOF) files
Use to define WMI namespaces, classes, provides etc...  

- Stored in ```%WINDIR%\System32\Wbem\``` directory with extension *.mof*
- We can write our own MOF files to expand WMI

### Providers
Generally, provider is associated with every *MOF* file.  
- A provider could be a DLL within ```%WINDIR%\System32\Wbem\``` directory  or could be othe type (Class, Instance, Event, Event Consumer, Method)
- A provider just like a driver, works as a bridge between a managed object and WMI.

--> Provider main function is to provide access to classes.

### Managed Objects
Managed object is the component being managed by WMI like process, service, operating systems etc...  

### Namespaces
Namespaces are crearted by providers and are used to divide classes logically.

Well known namespaces are :
- root\cimv2
- root\default
- root\security
- root\subscription

### Repository
WMI repository is the database used to store static data (definitions) of classes.

- Located in the ```%WINDIR%\System32\Wbem\Repository``` directory  

### Consumers
Applications or scripts which can be used to interact with WMI classes for query of data or to run methods or to subscribe to events.

- PowerShell
- WMIC.exe
- ... 

## WMI with PowerShell

Listing WMI providers within PowerShell Version 2 cmdlet:

```
Get-Command -CommandType cmdlet *wmi*

Get-WmiObject : Retrieve instances
Invoke-WmiMethod : Run a method
Register-WmiEvent : Register WMI events
Remove-WmiObject : Remove an object
Set-WmiInstance : Modify the writable property of WMI object
```

PowerShell version 3 provides CIM (Common Information Model) cmdlets which uses WS-MAN and CIM standards to manage objects.
```
Get-Command -CommandType cmdlet *cim*

Cmdlet          Get-CimAssociatedInstance                          1.0.0.0    CimCmdlets
Cmdlet          Get-CimClass                                       1.0.0.0    CimCmdlets
Cmdlet          Get-CimInstance                                    1.0.0.0    CimCmdlets
Cmdlet          Get-CimSession                                     1.0.0.0    CimCmdlets
Cmdlet          Invoke-CimMethod                                   1.0.0.0    CimCmdlets
Cmdlet          New-CimInstance                                    1.0.0.0    CimCmdlets
Cmdlet          New-CimSession                                     1.0.0.0    CimCmdlets
Cmdlet          New-CimSessionOption                               1.0.0.0    CimCmdlets
Cmdlet          Register-CimIndicationEvent                        1.0.0.0    CimCmdlets
Cmdlet          Remove-CimInstance                                 1.0.0.0    CimCmdlets
Cmdlet          Remove-CimSession                                  1.0.0.0    CimCmdlets
Cmdlet          Set-CimInstance                                    1.0.0.0    CimCmdlets
```
--> Use of WS-MAN allows CIM cmdlets to be used against boxes where WMI blocked but WS-MAN (WinRM) is enabled. (even with PSv2 )
 
Listing all namespaces within *root* class
```
PS C:\>  Get-WmiObject -Namespace "root" -Class "__Namespace" 
```
 
Listing all namespaces only select the name property
```
PS C:\>  Get-WmiObject -Namespace "root" -Class "__Namespace" | select name
PS C:\>  Get-CimInstance -Namespace "root" -Class "__Namespace" | select name
```

Listing all namespaces nested into other namespaces, in our case *root* namespace (recursive approach)
```
function Get-WmiNamespace {
    Param (
        $Namespace='root'
    )
    Get-WmiObject -Namespace $Namespace -Class __NAMESPACE | ForEach-Object {
        ($ns = '{0}\{1}' -f $_.__NAMESPACE,$_.Name)
        Get-WmiNamespace $ns
    }
}
```

## Wmi host recon 

List class containing "*bios*" string (by default it will request on root\cimv2 Namespace)
```
Get-WmiObject -Class *bios* -List
```

Get Information regarding the current hardware and system
```
PS C:\> Get-WmiObject -Class win32_bios

SMBIOSBIOSVersion : VMW71.00V.18452719.B64.2108091906
Manufacturer      : VMware, Inc.
Name              : VMW71.00V.18452719.B64.2108091906
SerialNumber      : VMware-f3 4f 09 a3 2f 43 66 1e-1c 27 a6 ad 02 bs dd aa
Version           : INTEL  - 6040000
```

Listing process running and filtering on *explorer.exe*
```
Get-WmiObject -Class Win32_Process -Filter "Name = 'explorer.exe'"
```

Listing specific process running using the *Query* parameter
```
Get-WmiObject -Query "select * from Win32_Process where Name = 'explorer.exe'"
```

Listing Anti-virus product
```
Get-WmiObject -Namespace root\SecurityCenter2 -Class AntiVirusProduct
```

Listing folder within a directory
```
Get-CimInstance Win32_Directory -Filter "Name = 'C:\\Windows\\System32'" | Get-CimAssociatedInstance -Association Win32_Subdirectory | select Name
```
```
Get-WmiObject Win32_Directory -filter 'Drive="C:" and Path="\\"' | Format-Table name
```

Listing file with *ini* extension within *C:\\*
```
Get-WmiObject CIM_DataFile -filter 'Drive="C:" and Path="\\Windows\\" and Extension="ini"' | Format-List *
```

Listing Services and state
```
Get-WmiObject -Class win32_service -computer "." -Namespace "root\cimv2" | format-list Name, State
```

Get processor architecture details
```
Get-WmiObject -Class Win32_Processor
```

List current logged accountlist installed patches wmi
```
Get-WmiObject -class Win32_ComputerSystem | Format-List Username
```

List installed security update
```
Get-Wmiobject -Class win32_quickfixengineering
```

List all process with their command line used to start
```
Get-WmiObject -Class "Win32_Process" -ComputerName "." | Format-List -Property CommandLine, Name
``` 

List specific process (cmd.exe) and command line used to start
```
Get-WmiObject -Class "Win32_Process" -ComputerName "." | where {($_.name -eq 'powershell.exe')} | Format-List -Property CommandLine, Name
```

Get-WmiObject -Class Win32_NTEventLogFile -ComputerName $strComputer | Where-Object {$_.LogFileName -eq 'security'}

Path to executables for running services
