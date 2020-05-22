[cmdletbinding()]
Param (
    [Parameter(Mandatory = $false)]
    [string]$base_location
)

if ($base_location -eq "") {
    $base_location = "C:\Program Files\AppDynamics\IoT"
}

$config_json = Get-Content -Path "$($base_location)/settings.json" | ConvertFrom-Json

$now = Get-Date
# $unixEpochStart = New-Object DateTime 1970, 1, 1, 0, 0, 0, ([DateTimeKind]::Utc)
# $unix_timestamp = [int64]((([datetime]$now) - $unixEpochStart).TotalMilliseconds)
function ConvertTo-UnixTimestamp {
    $epoch = Get-Date -Year 1970 -Month 1 -Day 1 -Hour 0 -Minute 0 -Second 0
    $input | ForEach-Object {
        $milliSeconds = [math]::truncate($_.ToUniversalTime().Subtract($epoch).TotalMilliSeconds)
        Write-Output $milliSeconds
    }
}
$unix_timestamp = $now | ConvertTo-UnixTimestamp
# $unix_timestamp  = [int](Get-Date -UFormat %s) * 1000

# $status_code = (Invoke-WebRequest -Uri "$($config_json.url)/eumcollector/iot/v1/application/$($config_json.key)/enabled").StatusCode

$desktop_details = Get-WmiObject  -Class win32_operatingsystem  -ErrorAction SilentlyContinue 
$memory_cal = ((($desktop_details.TotalVisibleMemorySize - $desktop_details.FreePhysicalMemory)*100)/ $desktop_details.TotalVisibleMemorySize)

$memory_utilisation = [math]::Round($memory_cal, 2)

$total_visible_memorySize =  $desktop_details | Measure-Object -Property TotalVisibleMemorySize -Sum | ForEach-Object {[Math]::Round($_.sum/1024/1024)}

$free_physical_memory = $desktop_details | Measure-Object -Property FreePhysicalMemory -Sum | ForEach-Object {[Math]::Round($_.sum/1024/1024)}

#let's do the %tage calc in AppD 
#$disk_utilisation = (Get-WmiObject -Class Win32_logicaldisk -Filter "DeviceID = 'C:'"  -ErrorAction SilentlyContinue `
#                    | Select-Object name,freespace,size,@{Name='util';Expression={($_.freespace / $_.size)*100}}).util

$drive_c = Get-WmiObject -Class Win32_logicaldisk -Filter "DeviceID = 'C:'"  -ErrorAction SilentlyContinue `
           | Select-Object -Property DeviceID, DriveType, VolumeName, 
            @{L='FreeSpaceGB';E={"{0:N2}" -f ($_.FreeSpace /1GB)}},
            @{L="Capacity";E={"{0:N2}" -f ($_.Size/1GB)}}

$disk_free = $drive_c.FreeSpaceGB

$disk_capacity = $drive_c.Capacity
                    

Write-Host "`n Taking 5 samples of CPU utilisation at 2 sec interval. This will take approximately 11 seconds to execute `n" -ForegroundColor Yellow
Write-Host "Please wait... `n" -ForegroundColor Yellow

# Make the Call ones per excution for optimal performance - top processes will also be derived from this result. 

$cpu_util_call = Get-Counter "\Process(*)\% Processor Time" -SampleInterval 2 -MaxSamples 5  -ErrorAction SilentlyContinue `
                 | Select-Object -ExpandProperty CounterSamples `
                 | Where-Object {$_.Status -eq 0 -and $_.instancename -notin "_total", "idle"} 

$cpu_utilisation = ($cpu_util_call | Select-Object -ExpandProperty CookedValue | Measure-Object -Average).average.ToString("P")    
 
Write-Host "Average of CPU usage (calculated with 5 Sample with interval of 2 sec) $cpu_utilisation `n"  -ForegroundColor Yellow

Write-Host "`n Calculate Top 5 CPU processes that are consuming CPU - over the sample period `n" -ForegroundColor Yellow

$top_cpu_processes = $cpu_util_call `
                    | sort CookedValue -Descending | Select-Object -First 5 `
                    | Select-Object TimeStamp,
                    @{N="Name";E={ $_.InstanceName  }},
                    @{N="Id";E={[System.Diagnostics.Process]::GetProcessesByName($_.InstanceName)[0].Id}},
                    @{N="CPU";E={($_.CookedValue/100/$env:NUMBER_OF_PROCESSORS).ToString("P")}} 

 #this approach is faster than the native wmiobject
$top_mem_processes = Get-Process | Sort-Object -Descending WS `
                    | Select-Object -First 5 `
                    | Select-Object name, description, id, @{l = "Private Memory (MB)"; e = { ([math]::Round($_.privatememorysize/1Mb,2)) } }


function PrepValue($var){
    #Because AppD IoT platform doesn't like "" or null. 
    If([string]::IsNullOrEmpty($var)){            
       # Write-Host "Variable is Null"  
       $var = '"null"'     
    } 
    return $var
}

#Gloabl variable initialisations...

$lastbootuptime = $desktop_details | Select-Object @{label='LastRestart';expression={$_.ConvertToDateTime($_.LastBootUpTime)}}
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
$LOGONSERVER = $LOGONSERVER  -replace "\\","" #Strip \\ coz AppD IoT platform doesn't like it. 
$TPICAPUSERSITE = PrepValue($env:TPICAPUSERSITE)

$deviceID = $COMPUTERNAME + "_" + ${$env:TPICAPSITE}
#$deviceName = $COMPUTERNAME + "_" + ${env:$USERNAME}
$os_details  =  "OS:" + $OS +". BuildNumber:"+ $desktop_details.BuildNumber +". BuildType:"+ $desktop_details.BuildType 
$hardware_serial_number = "SN:"+ $desktop_details.SerialNumber
$processor_info = "Processor Info - Core:" + $NUMBER_OF_PROCESSORS + ". Revision:" + $PROCESSOR_REVISION + ". Level:$PROCESSOR_LEVEL"

$user_location = "TPICAPUSERLOCATION: $TPICAPUSERLOCATION TPICAPLOCATION: $TPICAPLOCATION . TPICAPUSERREGION: $TPICAPUSERREGION . TPICAPREGION: $TPICAPREGION  TPICAPSITE: $TPICAPSITE "
#https://safebreach.com/Post/Amazon-Workspaces-Unquoted-Search-Path-and-Potential-Abuses
$stxhd_details = "STXHD_ACCOUNT_ID: $STXHD_ACCOUNT_ID . STXHD_INSTANCE_ID: $STXHD_INSTANCE_ID . STXHD_REGION: $STXHD_REGION " 

$a = Get-Content "$($base_location)/json/base_beacon.json" -raw | ConvertFrom-Json

$a.deviceInfo.deviceID = $deviceID
$a.deviceInfo.deviceName = $COMPUTERNAME 

$a.versionInfo.operatingSystemVersion = $os_details
$a.versionInfo.hardwareVersion = $hardware_serial_number
$a.versionInfo.softwareVersion = $os_details
$a.versionInfo.firmwareVersion = $processor_info

$a.customEvents.doubleProperties.MemoryUsagePercent = $memory_utilisation
$a.customEvents.doubleProperties.MemoryTotalSizeGB = $total_visible_memorySize
$a.customEvents.doubleProperties.MemoryFreeSizeGB = $free_physical_memory

$a.customEvents.doubleProperties.DiskFreeSpaceGB = $disk_free
$a.customEvents.doubleProperties.DiskCapacityGB = $disk_capacity

$a.customEvents.doubleProperties.CPU = [double]($cpu_utilisation -replace "%", "")

$a.customevents.timestamp = $unix_timestamp

$a.customEvents.stringProperties.USERNAME = $USERNAME
$a.customEvents.stringProperties.USERDNSDOMAIN = $USERDNSDOMAIN
$a.customEvents.stringProperties.USERLOCATION = $user_location
$a.customEvents.stringProperties.USERSITE = $TPICAPUSERSITE
$a.customEvents.stringProperties.STXHD_ACCOUNT = $stxhd_details
$a.customEvents.stringProperties.PROCESSOR_LEVEL = $PROCESSOR_LEVEL
$a.customEvents.stringProperties.NUMBER_OF_PROCESSORS = $NUMBER_OF_PROCESSORS 
$a.customEvents.stringProperties.LOGONSERVER = $LOGONSERVER
$a.customEvents.stringProperties.STXHD_PERFORMANCE = $STXHD_PERFORMANCE

#$a.customEvents.stringProperties.PROCESSOR_REVISION = $PROCESSOR_REVISION
#$a.customEvents.stringProperties.TPICAPLOCATION = $TPICAPLOCATION 
#$a.customEvents.stringProperties.TPICAPUSERREGION = $TPICAPUSERREGION
#$a.customEvents.stringProperties.TPICAPREGION = $TPICAPREGION
#$a.customEvents.stringProperties.TPICAPSITE = $TPICAPSITE
#$a.customEvents.stringProperties.LOGONSERVER = $LOGONSERVER

#$a.customEvents.stringProperties.NUMBER_OF_PROCESSORS = $NUMBER_OF_PROCESSORS 
#$a.customEvents.stringProperties.STXHD_INSTANCE_ID = $STXHD_INSTANCE_ID
#$a.customEvents.stringProperties.STXHD_ACCOUNT_ID = $STXHD_ACCOUNT_ID

#$a.customEvents.stringProperties.STXHD_REGION = $STXHD_REGION

$a | ConvertTo-Json -Compress -Depth 3 | set-content "$($base_location)/json/base_beacon_new.json"

$Params = @{
    Method  = 'Post'
    URI     = "$($config_json.url)/eumcollector/iot/v1/application/$($config_json.key)/beacons"
    Headers = @{'accept' = 'application/json' }
}

$body = $a | ConvertTo-Json -Compress -Depth 3

write-host "`n Sending base metrics to AppDynamics IoT Platform...`n"  -ForegroundColor Yellow

Invoke-RestMethod -v @Params -Body ("[" + $body + "]")

write-host "=========request body====="
write-host $body
write-host "==========================="


$b = Get-Content "$($base_location)/json/cpu_procs.json" -raw | ConvertFrom-Json

$b.deviceInfo.deviceID = $deviceID
$b.deviceInfo.deviceName = $COMPUTERNAME 

$b.versionInfo.operatingSystemVersion = $os_details
$b.versionInfo.hardwareVersion = $hardware_serial_number
$b.versionInfo.softwareVersion = $os_details
$b.versionInfo.firmwareVersion = $processor_info

$b.customevents.timestamp = $unix_timestamp
$b.customEvents.stringProperties.USERNAME = $USERNAME

#Max 16 metrics are allowed
#$b.customEvents.stringProperties.TPICAPUSERLOCATION = $TPICAPUSERLOCATION
#$b.customEvents.stringProperties.USERDNSDOMAIN = $USERDNSDOMAIN
#$b.customEvents.stringProperties.TPICAPLOCATION = $TPICAPLOCATION
#$b.customEvents.stringProperties.TPICAPUSERREGION = $TPICAPUSERREGION
#$b.customEvents.stringProperties.TPICAPREGION = $TPICAPREGION
#$b.customEvents.stringProperties.TPICAPSITE = $TPICAPSITE
#$b.customEvents.stringProperties.LOGONSERVER = $LOGONSERVER
#$b.customEvents.stringProperties.TPICAPUSERSITE = $TPICAPUSERSITE

#$b.customEvents.stringProperties.NUMBER_OF_PROCESSORS = $NUMBER_OF_PROCESSORS 
#$b.customEvents.stringProperties.STXHD_INSTANCE_ID = $STXHD_INSTANCE_ID
#$b.customEvents.stringProperties.STXHD_ACCOUNT_ID = $STXHD_ACCOUNT_ID
#$b.customEvents.stringProperties.STXHD_REGION = $STXHD_REGION
#$b.customEvents.stringProperties.PROCESSOR_REVISION = $PROCESSOR_REVISION
#$b.customEvents.stringProperties.PROCESSOR_LEVEL = $PROCESSOR_LEVEL

$b.customEvents.stringProperties.cpu1_process = $top_cpu_processes[0].Name
$b.customEvents.stringProperties.cpu2_process = $top_cpu_processes[1].Name
$b.customEvents.stringProperties.cpu3_process = $top_cpu_processes[2].Name
$b.customEvents.stringProperties.cpu4_process = $top_cpu_processes[3].Name
$b.customEvents.stringProperties.cpu5_process = $top_cpu_processes[4].Name

$b.customEvents.stringProperties.cpu1_id =  [String]($top_cpu_processes[0].Id)
$b.customEvents.stringProperties.cpu2_id =  [String]($top_cpu_processes[1].Id)
$b.customEvents.stringProperties.cpu3_id =  [String]($top_cpu_processes[2].Id)
$b.customEvents.stringProperties.cpu4_id = [String]($top_cpu_processes[3].Id)
$b.customEvents.stringProperties.cpu5_id = [String]($top_cpu_processes[4].Id)

$b.customEvents.doubleProperties.cpu1_value = [double]($top_cpu_processes[0].CPU -replace "%", "")
$b.customEvents.doubleProperties.cpu2_value = [double]($top_cpu_processes[1].CPU -replace "%", "" )
$b.customEvents.doubleProperties.cpu3_value = [double]($top_cpu_processes[2].CPU -replace "%", "")
$b.customEvents.doubleProperties.cpu4_value = [double]($top_cpu_processes[3].CPU  -replace "%", "")
$b.customEvents.doubleProperties.cpu5_value = [double]($top_cpu_processes[4].CPU -replace "%", "")

$b | ConvertTo-Json -Compress -Depth 3 | set-content "$($base_location)/json/cpu_procs_new.json"

$body2 = $b | ConvertTo-Json -Compress -Depth 3

write-host "`n Sending TOP CPU Consumption Metrics to AppDynamics IoT Platform...`n"  -ForegroundColor Yellow

Invoke-RestMethod -v @Params -Body ("[" + $body2 + "]")
write-host "=========request body====="
write-host $body2
write-host "==========================="

$c = Get-Content "$($base_location)/json/mem_procs.json" -raw | ConvertFrom-Json

$c.deviceInfo.deviceID = $deviceID
$c.deviceInfo.deviceName = $COMPUTERNAME 

$c.versionInfo.operatingSystemVersion = $os_details
$c.versionInfo.hardwareVersion = $hardware_serial_number
$c.versionInfo.softwareVersion = $os_details
$c.versionInfo.firmwareVersion = $processor_info

$c.customevents.timestamp = $unix_timestamp
$c.customEvents.stringProperties.USERNAME = $USERNAME

#$c.customEvents.stringProperties.TPICAPUSERLOCATION = $TPICAPUSERLOCATION
#$c.customEvents.stringProperties.USERDNSDOMAIN = $USERDNSDOMAIN
#$c.customEvents.stringProperties.TPICAPLOCATION = $TPICAPLOCATION
#$c.customEvents.stringProperties.TPICAPUSERREGION = $TPICAPUSERREGION
#$c.customEvents.stringProperties.TPICAPREGION = $TPICAPREGION
#$c.customEvents.stringProperties.TPICAPSITE = $TPICAPSITE
#$c.customEvents.stringProperties.LOGONSERVER = $LOGONSERVER
#$c.customEvents.stringProperties.TPICAPUSERSITE = $TPICAPUSERSITE

#$c.customEvents.stringProperties.NUMBER_OF_PROCESSORS = $NUMBER_OF_PROCESSORS 
#$c.customEvents.stringProperties.STXHD_INSTANCE_ID = $STXHD_INSTANCE_ID
#$c.customEvents.stringProperties.STXHD_ACCOUNT_ID = $STXHD_ACCOUNT_ID
#$c.customEvents.stringProperties.STXHD_REGION = $STXHD_REGION
#$c.customEvents.stringProperties.PROCESSOR_REVISION = $PROCESSOR_REVISION
#$c.customEvents.stringProperties.PROCESSOR_LEVEL = $PROCESSOR_LEVEL

$c.customEvents.stringProperties.mem1_process = $top_mem_processes[0].name
$c.customEvents.stringProperties.mem2_process = $top_mem_processes[1].name
$c.customEvents.stringProperties.mem3_process = $top_mem_processes[2].name
$c.customEvents.stringProperties.mem4_process = $top_mem_processes[3].name
$c.customEvents.stringProperties.mem5_process = $top_mem_processes[4].name

$c.customEvents.stringProperties.mem1_id = [String]($top_mem_processes[0].id)
$c.customEvents.stringProperties.mem2_id = [String]($top_mem_processes[1].id)
$c.customEvents.stringProperties.mem3_id = [String]($top_mem_processes[2].id)
$c.customEvents.stringProperties.mem4_id = [String]($top_mem_processes[3].id)
$c.customEvents.stringProperties.mem5_id = [String]($top_mem_processes[4].id)

$c.customEvents.doubleProperties.mem1_value = $top_mem_processes[0].'Private Memory (MB)'
$c.customEvents.doubleProperties.mem2_value = $top_mem_processes[1].'Private Memory (MB)'
$c.customEvents.doubleProperties.mem3_value = $top_mem_processes[2].'Private Memory (MB)'
$c.customEvents.doubleProperties.mem4_value = $top_mem_processes[2].'Private Memory (MB)'
$c.customEvents.doubleProperties.mem5_value = $top_mem_processes[4].'Private Memory (MB)'
$c | ConvertTo-Json -Compress -Depth 3 | set-content "$($base_location)/json/mem_procs_new.json"

$body3 = $c | ConvertTo-Json -Compress -Depth 3

write-host "`n Sending TOP Memory Consumption Metrics to AppDynamics IoT Platform..." -ForegroundColor Yellow

Invoke-RestMethod -v @Params -Body ("[" + $body3 + "]")

write-host "=========response body====="
write-host $body3
write-host "==========================="

$Begin = $now.AddSeconds(0 - $config_json.interval_mins*60)
write-host "Searching Windows events logs for pre-configured search strings ..." -ForegroundColor Yellow
# foreach ($log_source in $config_json.event_log_source) {
foreach ($log_type in $config_json.event_log_source) {
    # foreach ($search_term in $config_json.message_contains) {
    foreach ($search_term in $log_type.PSObject.Properties.Value) {
        Write-Host "`n Searching for * $search_term * in *" $log_type.PSObject.Properties.Name "* Windows Events `n" -ForegroundColor Yellow

        $ev = Get-EventLog -LogName $log_type.PSObject.Properties.Name -Message *$search_term* -After $Begin -Before $now
        if ($ev.Count -gt 0) {
            write-host " `n Found windows events logs `n"
            foreach ($elem in $ev) {
                $d = Get-Content "$($base_location)/json/event.json" -raw | ConvertFrom-Json
                
                $d.deviceInfo.deviceID = $deviceID
                $d.deviceInfo.deviceName = $COMPUTERNAME 

                $d.versionInfo.operatingSystemVersion = $os_details
                $d.versionInfo.hardwareVersion = $hardware_serial_number
                $d.versionInfo.softwareVersion = $os_details
                $d.versionInfo.firmwareVersion = $processor_info

                $d.customevents.timestamp = $unix_timestamp
                $d.customEvents.stringProperties.USERNAME = $USERNAME
                
                #$d.customEvents.stringProperties.TPICAPUSERLOCATION = $TPICAPUSERLOCATION
                #$d.customEvents.stringProperties.USERDNSDOMAIN = $USERDNSDOMAIN
                #$d.customEvents.stringProperties.TPICAPLOCATION = $TPICAPLOCATION
                #$d.customEvents.stringProperties.TPICAPUSERREGION = $TPICAPUSERREGION
                #$d.customEvents.stringProperties.TPICAPREGION = $TPICAPREGION
                #$d.customEvents.stringProperties.TPICAPSITE = $TPICAPSITE
                #$d.customEvents.stringProperties.LOGONSERVER = $LOGONSERVER
                #$d.customEvents.stringProperties.TPICAPUSERSITE = $TPICAPUSERSITE
                
                $d.customevents.event_id = $elem.EventID
                $d.customevents.event_machine_name = $elem.MachineNames
                $d.customevents.event_data = $elem.Data
                $d.customevents.event_index = $elem.Index
                $d.customevents.event_category = $elem.Category
                $d.customevents.event_category_number = $elem.CategoryNumber
                $d.customevents.event_entry_type = $elem.EntryType
                $d.customevents.event_message = $elem.Message
                $d.customevents.event_source = $elem.Source
                $d.customevents.event_replacement_string = $elem.ReplacementStrings
                $d.customevents.event_instance_id = $elem.InstanceId
                $d.customevents.event_username = $elem.UserName
                $d.customevents.event_site = $elem.Site
                $d.customevents.event_container = $elem.Container
                $d.datetimeProperties.event_time_generated = (Get-Date -Date $elem.TimeGenerated -UFormat %s) + "000"
                $d.datetimeProperties.event_time_written = (Get-Date -Date $elem.TimeWritten -UFormat %s) + "000"

                $d | ConvertTo-Json -Compress -Depth 3 | set-content "$($base_location)/json/event_new.json"
                $body4 = $d | ConvertTo-Json -Compress -Depth 3

                write-host " `n Sending Windows events logs to AppDynamics. `n" -ForegroundColor Yellow

                Invoke-RestMethod -v @Params -Body ("[" + $body4 + "]")

                write-host "=========response body====="
                write-host $body4
                write-host "==========================="

            }
        }
        else {

            write-host "No result found " -ForegroundColor Yellow

        }
    }
}
