[cmdletbinding()]
Param (
    [Parameter(Mandatory = $false)]
    [string]$base_location
)

if ([string]::IsNullOrEmpty($base_location)) {
    #if ($base_location -eq "") {
    $base_location = $PSScriptRoot
    
    if (!(Test-Path "$($base_location)/settings.json")) {
        #Recommended location
        $base_location = "C:\Program Files\AppDynamics\AppDWorkSpaceMonitor"
    }
}

Write-Host "Base Path - $base_location `n"

if (!(Test-Path "$($base_location)/settings.json")) {

    Write-Host "*********************************************************************************** `n 
    This is weird, I know...but please bear with us. You've run into a Windows's Scheduler Problem `n 
    We are unable to locate the path to this script. You must define an explicit full location of the folder containing this script for it work - `n 
    this is because Windows Scheduler doesn't understand the implicit .\ home path and it often fails to interpret th PSScriptRoot command.`n 
    You have two options:
    1. Either copy the content of the package into the default recommended location at $base_location  or
    2. Locate where this script is ($PSScriptRoot), then pass it as argument in the command line. for example: .\workspace_monitor.ps1 -base_location 'full path' `n" -ForegroundColor RED

}

$config_json = Get-Content -Path "$($base_location)/settings.json" | ConvertFrom-Json

############## Logging initialisations ##############
$LogDir = ".\logs"
$ilogFile = "log.txt"
$LogPath = $LogDir + '\' + $iLogFile

#Load Logger Function - relative path
# Function to Write into Log file
function Write-Log {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $False)]
        [ValidateSet("INFO", "WARN", "ERROR", "FATAL", "DEBUG")]
        [String]
        $Level = "INFO",

        [Parameter(Mandatory = $True)]
        [string]
        $Message,

        [Parameter(Mandatory = $False)]
        [string]
        $logfile
    )

    $Stamp = (Get-Date).toString("yyyy/MM/dd HH:mm:ss")
    $Line = "$Stamp $Level $Message"
    if ($logfile) {
        Add-Content $logfile -Value $Line
    }
    else {
        Write-Output $Line
    }
}

#Checking for existence of logfolders and files if not create them.
if (!(Test-Path $LogDir)) {
    New-Item -Path $LogDir -ItemType directory
    New-Item -Path $LogDir -Name $iLogFile -ItemType File
    Write-Host INFO "Created $LogDir" $LogPath
}

function PrepValue($var) {
    If ([string]::IsNullOrEmpty($var)) {            
        # Write-Host "Variable is Null"  
        $var = '"null"'     
    } 
    return $var
}
function ConvertTo-UnixTimestamp {
    $epoch = Get-Date -Year 1970 -Month 1 -Day 1 -Hour 0 -Minute 0 -Second 0
    $input | ForEach-Object {
        $milliSeconds = [math]::truncate($_.ToUniversalTime().Subtract($epoch).TotalMilliSeconds)
        Write-Output $milliSeconds
    }
}


$now = Get-Date
$unix_timestamp = $now | ConvertTo-UnixTimestamp

# $status_code = (Invoke-WebRequest -Uri "$($config_json.url)/eumcollector/iot/v1/application/$($config_json.key)/enabled").StatusCode

$desktop_details = Get-WmiObject  -Class win32_operatingsystem  -ErrorAction SilentlyContinue 
$memory_cal = ((($desktop_details.TotalVisibleMemorySize - $desktop_details.FreePhysicalMemory)*100)/ $desktop_details.TotalVisibleMemorySize)

$memory_utilisation = [math]::Round($memory_cal, 2)

$total_visible_memorySize = $desktop_details | Measure-Object -Property TotalVisibleMemorySize -Sum | ForEach-Object { [Math]::Round($_.sum/1024/1024) }

$free_physical_memory = $desktop_details | Measure-Object -Property FreePhysicalMemory -Sum | ForEach-Object { [Math]::Round($_.sum/1024/1024) }

#let's do the %tage calc in AppD 
#$disk_utilisation = (Get-WmiObject -Class Win32_logicaldisk -Filter "DeviceID = 'C:'"  -ErrorAction SilentlyContinue `
#                    | Select-Object name,freespace,size,@{Name='util';Expression={($_.freespace / $_.size)*100}}).util

$drive_c = Get-WmiObject -Class Win32_logicaldisk -Filter "DeviceID = 'C:'"  -ErrorAction SilentlyContinue `
| Select-Object -Property DeviceID, DriveType, VolumeName, 
@{L = 'FreeSpaceGB'; E = { "{0:N2}" -f ($_.FreeSpace /1GB) } },
@{L = "Capacity"; E = { "{0:N2}" -f ($_.Size/1GB) } }

$disk_free = $drive_c.FreeSpaceGB
$disk_capacity = $drive_c.Capacity
                    
Write-Host "`n Taking 5 samples of CPU utilisation at 2 sec interval. This will take approximately 11 seconds to execute `n" -ForegroundColor Yellow
Write-Host "Please wait... `n" -ForegroundColor Yellow

# Make the Call ones per excution for optimal performance - top processes will also be derived from this result. 
$cpu_util_call = Get-Counter "\Process(*)\% Processor Time" -SampleInterval 2 -MaxSamples 5  -ErrorAction SilentlyContinue `
| Select-Object -ExpandProperty CounterSamples `
| Where-Object { $_.Status -eq 0 -and $_.instancename -notin "_total", "idle" } 

$cpu_utilisation = ($cpu_util_call | Select-Object -ExpandProperty CookedValue | Measure-Object -Average).average.ToString("P")    

Write-Host "Average of CPU usage (calculated with 5 Sample with interval of 2 sec) $cpu_utilisation `n"  -ForegroundColor Yellow
Write-Host "`n Calculate Top 5 CPU processes that are consuming CPU - over the sample period `n" -ForegroundColor Yellow

$top_cpu_processes = $cpu_util_call `
| sort CookedValue -Descending | Select-Object -First 5 `
| Select-Object TimeStamp,
@{N = "Name"; E = { $_.InstanceName } },
@{N = "Id"; E = { [System.Diagnostics.Process]::GetProcessesByName($_.InstanceName)[0].Id } },
@{N = "CPU"; E = { ($_.CookedValue/100/$env:NUMBER_OF_PROCESSORS).ToString("P") } } 

#this approach is faster than the native wmiobject
$top_mem_processes = Get-Process | Sort-Object -Descending WS `
| Select-Object -First 5 `
| Select-Object name, description, id, @{l = "Private Memory (MB)"; e = { ([math]::Round($_.privatememorysize/1Mb, 2)) } }

#Gloabl variable initialisations...
$lastbootuptime = $desktop_details | Select-Object @{label = 'LastRestart'; expression = { $_.ConvertToDateTime($_.LastBootUpTime) } }
$lastbootuptime = $lastbootuptime.LastRestart 

$NUMBER_OF_PROCESSORS = $env:NUMBER_OF_PROCESSORS
$OS = $env:OS
$COMPUTERNAME = PrepValue($env:COMPUTERNAME)
$STXHD_INSTANCE_ID = PrepValue($env:STXHD_INSTANCE_ID)
$STXHD_ACCOUNT_ID = PrepValue($env:STXHD_ACCOUNT_ID)
$STXHD_REGION = PrepValue($env:STXHD_REGION)
$STXHD_PERFORMANCE = PrepValue($env:STXHD_PERFORMANCE)
$PROCESSOR_REVISION = PrepValue($env:PROCESSOR_REVISION)
$PROCESSOR_LEVEL = PrepValue($env:PROCESSOR_LEVEL)
$USERNAME = PrepValue($env:USERNAME)
$TPICAPUSERLOCATION = PrepValue($env:TPICAPUSERLOCATION)
$USERDNSDOMAIN = PrepValue($env:USERDNSDOMAIN)
$TPICAPLOCATION = PrepValue($env:TPICAPLOCATION)
$TPICAPUSERREGION = PrepValue($env:TPICAPUSERREGION)
$TPICAPREGION = PrepValue($env:TPICAPREGION)
$TPICAPSITE = PrepValue($env:TPICAPSITE)
$LOGONSERVER = PrepValue($env:LOGONSERVER)
$LOGONSERVER = $LOGONSERVER -replace "\\", "" #Strip \\ coz AppD IoT platform doesn't like it. 
$TPICAPUSERSITE = PrepValue($env:TPICAPUSERSITE)

$deviceID = $COMPUTERNAME + "_" + ${$env:TPICAPSITE}
#$deviceName = $COMPUTERNAME + "_" + ${env:$USERNAME}
$os_details = "OS:" + $OS + ". BuildNumber:" + $desktop_details.BuildNumber + ". BuildType:" + $desktop_details.BuildType 
$hardware_serial_number = "SN:" + $desktop_details.SerialNumber
$processor_info = "Processor Info - Core:" + $NUMBER_OF_PROCESSORS + ". Revision:" + $PROCESSOR_REVISION + ". Level:$PROCESSOR_LEVEL"

$user_location = "TPICAPUSERLOCATION: $TPICAPUSERLOCATION TPICAPLOCATION: $TPICAPLOCATION . TPICAPUSERREGION: $TPICAPUSERREGION . TPICAPREGION: $TPICAPREGION  TPICAPSITE: $TPICAPSITE "
#https://safebreach.com/Post/Amazon-Workspaces-Unquoted-Search-Path-and-Potential-Abuses
$stxhd_details = "STXHD_ACCOUNT_ID: $STXHD_ACCOUNT_ID . STXHD_INSTANCE_ID: $STXHD_INSTANCE_ID . STXHD_REGION: $STXHD_REGION " 

# Post Params 
$Params = @{
    Method  = 'Post'
    URI     = "$($config_json.url)/eumcollector/iot/v1/application/$($config_json.key)/beacons"
    Headers = @{'accept' = 'application/json' }
}
function PayloadBuilder ($reqHandle) {
    # These objects are common to all the Payloads 
    $reqHandle.deviceInfo.deviceID = $deviceID
    $reqHandle.deviceInfo.deviceName = $COMPUTERNAME 

    $reqHandle.versionInfo.operatingSystemVersion = $os_details
    $reqHandle.versionInfo.hardwareVersion = $hardware_serial_number
    $reqHandle.versionInfo.softwareVersion = $os_details
    $reqHandle.versionInfo.firmwareVersion = $processor_info
    
    $reqHandle.customevents.timestamp = $unix_timestamp
    $reqHandle.customEvents.stringProperties.USERNAME = $USERNAME
    
}

############## Infra CPU, Disk and Mem Monitoring ##############
$msg = "Processing Infra CPU, Disk and Mem Monitoring payloads"
Write-Host $msg -ForegroundColor Yellow
Write-Log INFO $msg $LogPath

$infra_req = Get-Content "$($base_location)/json/base_beacon.json" -raw | ConvertFrom-Json

#Build the basic request Data
PayloadBuilder($infra_req)

$infra_req.customEvents.doubleProperties.MemoryUsagePercent = $memory_utilisation
$infra_req.customEvents.doubleProperties.MemoryTotalSizeGB = $total_visible_memorySize
$infra_req.customEvents.doubleProperties.MemoryFreeSizeGB = $free_physical_memory

$infra_req.customEvents.doubleProperties.DiskFreeSpaceGB = $disk_free
$infra_req.customEvents.doubleProperties.DiskCapacityGB = $disk_capacity

$infra_req.customEvents.doubleProperties.CPU = [double]($cpu_utilisation -replace "%", "")

$infra_req.customEvents.stringProperties.USERDNSDOMAIN = $USERDNSDOMAIN
$infra_req.customEvents.stringProperties.USERLOCATION = $user_location
$infra_req.customEvents.stringProperties.USERSITE = $TPICAPUSERSITE
$infra_req.customEvents.stringProperties.STXHD_ACCOUNT = $stxhd_details
$infra_req.customEvents.stringProperties.PROCESSOR_LEVEL = $PROCESSOR_LEVEL
$infra_req.customEvents.stringProperties.NUMBER_OF_PROCESSORS = $NUMBER_OF_PROCESSORS 
$infra_req.customEvents.stringProperties.LOGONSERVER = $LOGONSERVER
$infra_req.customEvents.stringProperties.STXHD_PERFORMANCE = $STXHD_PERFORMANCE

#$infra_req.customEvents.stringProperties.PROCESSOR_REVISION = $PROCESSOR_REVISION
#$infra_req.customEvents.stringProperties.TPICAPLOCATION = $TPICAPLOCATION 
#$infra_req.customEvents.stringProperties.TPICAPUSERREGION = $TPICAPUSERREGION
#$infra_req.customEvents.stringProperties.TPICAPREGION = $TPICAPREGION
#$infra_req.customEvents.stringProperties.TPICAPSITE = $TPICAPSITE
#$infra_req.customEvents.stringProperties.LOGONSERVER = $LOGONSERVER

#$infra_req.customEvents.stringProperties.NUMBER_OF_PROCESSORS = $NUMBER_OF_PROCESSORS 
#$infra_req.customEvents.stringProperties.STXHD_INSTANCE_ID = $STXHD_INSTANCE_ID
#$infra_req.customEvents.stringProperties.STXHD_ACCOUNT_ID = $STXHD_ACCOUNT_ID
#$infra_req.customEvents.stringProperties.STXHD_REGION = $STXHD_REGION

$infra_req | ConvertTo-Json -Compress -Depth 3 | Set-Content "$($base_location)/json/base_beacon_new.json"

$infra_req_payload = $infra_req | ConvertTo-Json -Compress -Depth 3

Write-Host "`n Sending base metrics to AppDynamics IoT Platform...`n"  -ForegroundColor Yellow

try {
    Invoke-RestMethod -v @Params -Body ("[" + $infra_req_payload + "]")
    Write-Host "=========rinfra monitor request body====="
    Write-Host $infra_req_payload
    Write-Host "==========================="
}
catch {
    Write-Warning "$($error[0])"
    $msg = "Error occured in sending Infra Monitoring Base Metrics `n Code: " + $_.Exception.Response.StatusCode.value__ + " `n Message Details: " + $_.Exception.Message + " `n StatusDescription: " + $_.Exception.Response.StatusDescription 
    Write-Host $msg -ForegroundColor Red
    Write-Log FATAL $msg $LogPath   
}

############## TOP CPU Procs ##############
$msg = "Processing Top 5 processes that are consuming CPU payload"
Write-Host $msg -ForegroundColor Yellow
Write-Log INFO $msg $LogPath

$top_cpu_req = Get-Content "$($base_location)/json/cpu_procs.json" -raw | ConvertFrom-Json

#Build the basic request Data
PayloadBuilder($top_cpu_req)

$top_cpu_req.customEvents.stringProperties.cpu1_process = $top_cpu_processes[0].Name
$top_cpu_req.customEvents.stringProperties.cpu2_process = $top_cpu_processes[1].Name
$top_cpu_req.customEvents.stringProperties.cpu3_process = $top_cpu_processes[2].Name
$top_cpu_req.customEvents.stringProperties.cpu4_process = $top_cpu_processes[3].Name
$top_cpu_req.customEvents.stringProperties.cpu5_process = $top_cpu_processes[4].Name

$top_cpu_req.customEvents.stringProperties.cpu1_id = [String]($top_cpu_processes[0].Id)
$top_cpu_req.customEvents.stringProperties.cpu2_id = [String]($top_cpu_processes[1].Id)
$top_cpu_req.customEvents.stringProperties.cpu3_id = [String]($top_cpu_processes[2].Id)
$top_cpu_req.customEvents.stringProperties.cpu4_id = [String]($top_cpu_processes[3].Id)
$top_cpu_req.customEvents.stringProperties.cpu5_id = [String]($top_cpu_processes[4].Id)

$top_cpu_req.customEvents.doubleProperties.cpu1_value = [double]($top_cpu_processes[0].CPU -replace "%", "")
$top_cpu_req.customEvents.doubleProperties.cpu2_value = [double]($top_cpu_processes[1].CPU -replace "%", "" )
$top_cpu_req.customEvents.doubleProperties.cpu3_value = [double]($top_cpu_processes[2].CPU -replace "%", "")
$top_cpu_req.customEvents.doubleProperties.cpu4_value = [double]($top_cpu_processes[3].CPU -replace "%", "")
$top_cpu_req.customEvents.doubleProperties.cpu5_value = [double]($top_cpu_processes[4].CPU -replace "%", "")

$top_cpu_req | ConvertTo-Json -Compress -Depth 3 | Set-Content "$($base_location)/json/cpu_procs_new.json"

$top_cpu_req_payload = $top_cpu_req | ConvertTo-Json -Compress -Depth 3

Write-Host "`n Sending TOP CPU Procs Metrics to the AppDynamics IoT Platform...`n"  -ForegroundColor Yellow
try {
    Invoke-RestMethod -v @Params -Body ("[" + $top_cpu_req_payload + "]")
    Write-Host "=========request body====="
    Write-Host $top_cpu_req_payload
    Write-Host "==========================="
}
catch {
    Write-Warning "$($error[0])"
    $msg = "Error occured in sending Top CPU metrics `n Code: " + $_.Exception.Response.StatusCode.value__ + " `n Message Details: " + $_.Exception.Message + " `n StatusDescription: " + $_.Exception.Response.StatusDescription 
    Write-Host $msg -ForegroundColor Red
    Write-Log FATAL $msg $LogPath
    
}

############## TOP Memory Procs ##############
$msg = "Processing Top 5 processes that are consuming Memory payload"
Write-Host $msg -ForegroundColor Yellow
Write-Log INFO $msg $LogPath

$top_mem_req = Get-Content "$($base_location)/json/mem_procs.json" -raw | ConvertFrom-Json

#Build the basic request Data
PayloadBuilder($top_mem_req)

$top_mem_req.customEvents.stringProperties.mem1_process = $top_mem_processes[0].name
$top_mem_req.customEvents.stringProperties.mem2_process = $top_mem_processes[1].name
$top_mem_req.customEvents.stringProperties.mem3_process = $top_mem_processes[2].name
$top_mem_req.customEvents.stringProperties.mem4_process = $top_mem_processes[3].name
$top_mem_req.customEvents.stringProperties.mem5_process = $top_mem_processes[4].name

$top_mem_req.customEvents.stringProperties.mem1_id = [String]($top_mem_processes[0].id)
$top_mem_req.customEvents.stringProperties.mem2_id = [String]($top_mem_processes[1].id)
$top_mem_req.customEvents.stringProperties.mem3_id = [String]($top_mem_processes[2].id)
$top_mem_req.customEvents.stringProperties.mem4_id = [String]($top_mem_processes[3].id)
$top_mem_req.customEvents.stringProperties.mem5_id = [String]($top_mem_processes[4].id)

$top_mem_req.customEvents.doubleProperties.mem1_value = $top_mem_processes[0].'Private Memory (MB)'
$top_mem_req.customEvents.doubleProperties.mem2_value = $top_mem_processes[1].'Private Memory (MB)'
$top_mem_req.customEvents.doubleProperties.mem3_value = $top_mem_processes[2].'Private Memory (MB)'
$top_mem_req.customEvents.doubleProperties.mem4_value = $top_mem_processes[2].'Private Memory (MB)'
$top_mem_req.customEvents.doubleProperties.mem5_value = $top_mem_processes[4].'Private Memory (MB)'

$top_mem_req | ConvertTo-Json -Compress -Depth 3 | Set-Content "$($base_location)/json/mem_procs_new.json"

$top_mem_req_payload = $top_mem_req | ConvertTo-Json -Compress -Depth 3

Write-Host "`n Sending TOP Memory Consumption Metrics to AppDynamics IoT Platform..." -ForegroundColor Yellow

try {
    Invoke-RestMethod -v @Params -Body ("[" + $top_mem_req_payload + "]")
    Write-Host "=========response body====="
    Write-Host $top_mem_req_payload
    Write-Host "==========================="
}
catch {
    Write-Warning "$($error[0])"
    $msg = "Error occured in sending Top Memory metrics `n Code: " + $_.Exception.Response.StatusCode.value__ + " `n Message Details: " + $_.Exception.Message + " `n StatusDescription: " + $_.Exception.Response.StatusDescription 
    Write-Host $msg -ForegroundColor Red
    Write-Log FATAL $msg $LogPath 
}

############## Windows Events Logs ##############
$msg = "Processing Windows Events Logs payload"
Write-Host $msg -ForegroundColor Yellow
Write-Log INFO $msg $LogPath

$windows_event_req = Get-Content "$($base_location)/json/event.json" -raw | ConvertFrom-Json

$Begin = $now.AddSeconds(0 - $config_json.windows_events_search_interval_mins*60)
Write-Host "Searching Windows events logs for pre-configured search strings ... `n" -ForegroundColor Yellow
foreach ($log_type in $config_json.windows_events_log) {
    # foreach ($search_term in $config_json.message_contains) {
    foreach ($search_term in $log_type.PSObject.Properties.Value) {
        Write-Host "`n Searching for * $search_term * in *" $log_type.PSObject.Properties.Name "* Windows Events `n" -ForegroundColor Yellow
        $ev = Get-EventLog -LogName $log_type.PSObject.Properties.Name -Message *$search_term* -After $Begin -Before $now
        #$ev
        #$ev.PSObject.Properties.Name
        if ($ev.Count -gt 0) {
            Write-Host " `n Found"+ $ev.Count +"Windows Event(s)`n"
            foreach ($elem in $ev) {
                # $windows_event_req = Get-Content "$($base_location)/json/event.json" -raw | ConvertFrom-Json

                PayloadBuilder($windows_event_req)

                $windows_event_req.customEvents.stringProperties.USERLOCATION = $TPICAPUSERLOCATION
                $windows_event_req.customEvents.stringProperties.USERDNSDOMAIN = $USERDNSDOMAIN
                $windows_event_req.customEvents.stringProperties.USERREGION = $TPICAPUSERREGION
                $windows_event_req.customEvents.stringProperties.ORGREGION = $TPICAPREGION
                $windows_event_req.customEvents.stringProperties.AWSREGION = $TPICAPSITE
                $windows_event_req.customEvents.stringProperties.LOGONSERVER = $LOGONSERVER
                $windows_event_req.customEvents.stringProperties.USERSITE = $TPICAPUSERSITE
                
                $windows_event_req.customevents.stringProperties.EventID = $elem.EventID
                $windows_event_req.customevents.stringProperties.EventCategory = $elem.Category
                $windows_event_req.customevents.stringProperties.EventEntryType = $elem.EntryType
                $windows_event_req.customevents.stringProperties.EventMessage = $elem.Message
                $windows_event_req.customevents.stringProperties.EventSource = $elem.Source
                $windows_event_req.customevents.stringProperties.EventInstanceID = $elem.InstanceId
                $windows_event_req.customevents.stringProperties.EventUserName = $elem.UserName
           
                $windows_event_req.customevents.datetimeProperties.EventTimeGenerated = (Get-Date -Date $elem.TimeGenerated -UFormat %s) + "000"
                $windows_event_req.customevents.datetimeProperties.EventTimeWritten = (Get-Date -Date $elem.TimeWritten -UFormat %s) + "000"

                $windows_event_req | ConvertTo-Json -Compress -Depth 3 | Set-Content "$($base_location)/json/event_new.json"
                $windows_event_req_payload = $windows_event_req | ConvertTo-Json -Compress -Depth 3

                Write-Host " `n Sending Windows events logs to AppDynamics. `n" -ForegroundColor Yellow
                try {
                    Invoke-RestMethod -v @Params -Body ("[" + $windows_event_req_payload + "]")

                    Write-Host "=========response body====="
                    Write-Host $windows_event_req_payload
                    Write-Host "==========================="
                 
                }
                catch {
                    Write-Warning "$($error[0])"
                    $msg = "Error occured in sending Windows Events Metrics `n Code:  " + $_.Exception.Response.StatusCode.value__ + " `n Message Details: " + $_.Exception.Message + " `n StatusDescription: " + $_.Exception.Response.StatusDescription 
                    Write-Host $msg -ForegroundColor Red
                    Write-Log FATAL $msg $LogPath
                }
            
            }
        }
        else {

            Write-Host "No result found " -ForegroundColor Yellow

        }
    }
}
