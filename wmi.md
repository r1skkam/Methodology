# WMI 101

*WMI = Windows Management Instrumentation*  
- https://docs.microsoft.com/en-us/windows/win32/wmisdk/wmi-architecture

--> Microsoft implementationn of CIM (Common Information Model) and  WBEM (Web Based Enterprise Management).  
--> Provides a uniform interface for applications/scripts to manage a local or remote computer or network.  

*WMIC = Command-Line interface for WMI*

<img src="./images/wmi-architecture.png" width="500"/>

## WMI Components
https://0xinfection.github.io/posts/wmi-classes-methods-part-2/

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

Path to executables for running services and user runnning services
```
Get-WmiObject -Class Win32_Service | select Name, StartName, PathName
```

Remove WMI objects:  
WMI returns *live*, *editable*, objects so you can for exemple kill a process using WMI.
```
Get-WmiObject -Class Win32_Process | Where-Object {$_.Name -eq "notepad.exe"} | Remove-WmiObject 
```

Searching for file recursively
```
function get-wmifile {
[CmdletBinding()]
param (
 [Parameter(Mandatory = $true)]
 [string]$path,
 [string]$file
)

if ($path.IndexOf('\\') -le 0 ){
  $path = $path.replace('\', '\\')
}

if ($path.IndexOf('*') -ge 0 ){
  $path = $path.replace('*', '%')
}

Write-Verbose -Message "Path to search: $path"

$folders = Get-CimInstance -ClassName Win32_Directory -Filter "Name LIKE '$path'"
foreach ($folder in $folders){
 if ($file) {
   Get-CimAssociatedInstance -InputObject $folder -ResultClassName CIM_DataFile |
   where Name -Like "*$file" |
   Select Name
 }
 else {
   Get-CimAssociatedInstance -InputObject $folder -ResultClassName CIM_DataFile |
   Select Name
 }
}

}
```

```
. ./get-wmifile.ps1
get-wmifile -path 'c:\Windows' -file 'unattend.xml'
```

Get owner of a specific process
```
Get-WmiObject Win32_Process -Filter "name='calculator.exe'" | Select Name, @{Name="UserName"; Expression={$_.GetOwner().Domain+"\"+$_.GetOwner().User}} | Sort-Object UserName, Name
```

Get owner for all process
```
Get-WmiObject Win32_Process | Select Name, @{Name="UserName"; Expression={$_.GetOwner().Domain+"\"+$_.GetOwner().User}} | Sort-Object UserName, Name
```

## WMI Methods
List all methods within *ROOT\CIMV2*  NameSpace
```
Get-WmiObject * -List | where-object {$_.Methods}
Get-CimClass -MethodName Create*
```

List all methods within by default *ROOT\CIMV2* NameSpace in specific class
```
Get-WmiObject -Class Win32_process -List | select -ExpandProperty Methods
```

List parameters for specific method *Create* within the *Win32_Proces* within *ROOT\Cimv2* NameSpace
```
Get-CimClass -Class Win32_process | select -ExpandProperty CimClassMethods | where name -eq "Create" | select -ExpandProperty Parameters
```

Invoke the previously enumerated method *Create* from *Win32_Process* class with *calc.exe* argument as parameter to pop up calc.exe process.
```
Invoke-WmiMethod -Class Win32_Process -Name create -ArgumentList calc.exe
```

## Association classes
https://raw.githubusercontent.com/dfinke/images/master/acn.png

Association classes are relationship between WMI classes which can be used to retrieve information about a managed object which is not available from a single class.

*__RELPATH* property of a WMI class can be used as key to list relationships of this class.
```
Get-wmiobject -class win32_networkadapter | select __RELPATH
Get-WmiObject -Query "Associators Of {Win32_NetworkAdapter.DeviceID=10} where ClassDefsOnly"
 ```

## WMI Console (WMIC)
<img src="./images/wmic_verbs.png" width="500"/>


## Registry key manipulation
https://docs.microsoft.com/en-us/windows/win32/wmisdk/wmi-tasks--registry

WMI provides a class called StdRegProv for interacting with the Windows Registry.  
--> An important point to note here is that we need to use the root\DEFAULT namespace for working with the registry
 
```

```

using WMI you can set or remove registry key using *Set-WmiObject* and *Remove-WmiObject*.
