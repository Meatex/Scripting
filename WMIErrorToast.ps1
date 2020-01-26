<#
Wrote this to find out what process was bugging out my WMI process and causing it to use 10% CPU constantly
Set it to be triggered on WMI error 5858
#>

$app = '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe'
[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime]

$Template = [Windows.UI.Notifications.ToastTemplateType]::ToastImageAndText01

#Gets the Template XML so we can manipulate the values
[xml]$ToastTemplate = ([Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent($Template).GetXml())

#get error event and extract key information -if it errors here it means most likely process is terminated so no point going further
$Event = Get-WinEvent -FilterHashtable @{Logname='Microsoft-Windows-WMI-Activity/Operational';ID=5858} -MaxEvents 1
$ProblemPID = $Event.Message.Split(";") | Select-String "ClientProcessId"
$ProblemPID = [regex]::Match($ProblemPID, "\d+(?!.*\d+)").value -as [int32]
$AppName = (Get-Process -Id $ProblemPID -ErrorAction Stop).ProcessName
#$explain = $Event.Message.Split(";") | Select-String "PossibleCause"

[xml]$ToastTemplate = @"
<toast launch="app-defined-string">
  <visual>
    <binding template="ToastGeneric">
      <text>WMI Error Alert...</text>
      <text>The application $AppName is causing errors and possible high CPU usage</text>
    </binding>
  </visual>
</toast>
"@

# Check to see if WMI is going crazy with the usage - doesn't account for multiple instances or anything
[Decimal]$threshhold  = 5
$CpuCores = (Get-WMIObject Win32_ComputerSystem).NumberOfLogicalProcessors

Start-Sleep -Seconds 10
$WMIUsage = ((Get-Counter "\Process(wmiprvse)\% Processor Time").CounterSamples | Select InstanceName, @{Name="CPU";Expression={[Decimal]::Round(($_.CookedValue / $CpuCores), 2)}}).CPU
if ($WMIUsage -ge 5) {
    $ToastXml = New-Object -TypeName Windows.Data.Xml.Dom.XmlDocument
    $ToastXml.LoadXml($ToastTemplate.OuterXml)
    $notify = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($app)
    $notify.Show($ToastXml)
}

