<#
ToDo
Write a wait and check for high CPU usage prior to notification
Probably need to use wmi for that info
#>

$app = '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe'
[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime]

$Template = [Windows.UI.Notifications.ToastTemplateType]::ToastImageAndText01

#Gets the Template XML so we can manipulate the values
[xml]$ToastTemplate = ([Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent($Template).GetXml())

#get error event and extract key information
$Event = Get-WinEvent -FilterHashtable @{Logname='Microsoft-Windows-WMI-Activity/Operational';ID=5858} -MaxEvents 1
$ProblemPID = $Event.Message.Split(";") | Select-String "ClientProcessId"
$ProblemPID = [regex]::Match($ProblemPID, "\d+(?!.*\d+)").value -as [int32]
$AppName = Get-Process -Id $ProblemPID


[xml]$ToastTemplate = @"
<toast launch="app-defined-string">
  <visual>
    <binding template="ToastGeneric">
      <text>WMI Error Alert...</text>
      <text>The application $AppName.ProcessName is causing errors and possible high CPU usage</text>
    </binding>
  </visual>
</toast>
"@

$ToastXml = New-Object -TypeName Windows.Data.Xml.Dom.XmlDocument
$ToastXml.LoadXml($ToastTemplate.OuterXml)

$notify = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($app)

$notify.Show($ToastXml)