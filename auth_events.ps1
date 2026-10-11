param([string]$Since,[long]$SecurityCursor=0,[long]$SshCursor=0)
[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false)
$sinceDate=[DateTime]::Parse($Since).ToUniversalTime()
$events=@();$coverage=@()
foreach($channel in @('Security','OpenSSH/Operational')) {
    try {
        $null=Get-WinEvent -ListLog $channel -ErrorAction Stop
        $filter=@{LogName=$channel;StartTime=$sinceDate}
        if($channel -eq 'Security') {$filter.Id=@(4624,4625,4648,4672,4728,4732,4756)}
        $queryErrors=@()
        $rows=@(Get-WinEvent -FilterHashtable $filter -MaxEvents 201 -ErrorAction SilentlyContinue -ErrorVariable queryErrors)
        $fatal=@($queryErrors | Where-Object {$_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*'})
        if($fatal.Count){throw 'Event query unavailable'}
        $coverage+=@{source=$channel;status='available';truncated=($rows.Count -gt 200)}
        foreach($event in $rows | Select-Object -First 200 | Sort-Object RecordId) {
            $cursor=if($channel -eq 'Security') {$SecurityCursor} else {$SshCursor}
            if($event.RecordId -le $cursor){continue}
            [xml]$xml=$event.ToXml();$data=@{}
            foreach($entry in $xml.Event.EventData.Data){if($entry.Name){$data[$entry.Name]=$entry.'#text'}}
            $kind='ssh-event';$account='';$address='';$logonType=''
            if($channel -eq 'Security') {
                $kind=switch($event.Id){4624 {'logon-success'} 4625 {'authentication-failure'} 4648 {'explicit-credentials'} 4672 {'privileged-logon'} default {'admin-membership-change'}}
                $account=if($data.TargetUserName){$data.TargetUserName}else{$data.SubjectUserName}
                $address=$data.IpAddress;$logonType=$data.LogonType
                # Routine built-in service privilege events are excluded to reduce noise.
                if($event.Id -eq 4672 -and $data.SubjectUserSid -in @('S-1-5-18','S-1-5-19','S-1-5-20')){continue}
            } else {
                $message=$event.Message
                if($message -match 'failed password|authentication fail|invalid user|failed publickey'){$kind='authentication-failure'}
                elseif($message -match 'Accepted password|Accepted publickey'){$kind='ssh-or-session-success'}
                elseif($message -match 'connection|disconnect|preauth'){$kind='ssh-connection'}
            }
            $events+=@{source=$channel;recordId=$event.RecordId;eventId=$event.Id;kind=$kind;account=$account;address=$address;logonType=$logonType;time=$event.TimeCreated.ToUniversalTime().ToString('o')}
        }
    } catch {$coverage+=@{source=$channel;status='unavailable';reason='Log missing, disabled, or access denied'}}
}
ConvertTo-Json -InputObject @{events=$events;coverage=$coverage} -Depth 5 -Compress
