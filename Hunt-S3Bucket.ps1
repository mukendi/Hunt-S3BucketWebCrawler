#Requires -Version 5.1
<#
.SYNOPSIS
    Web crawler that finds abandoned S3 buckets referenced in HTML/JS/JSON pages.

.PARAMETER Domain
    Target domain, e.g. "example.com" or "https://example.com"

.PARAMETER MaxPages
    Maximum number of pages to crawl. Default: 200

.PARAMETER MaxDepth
    Maximum crawl depth from root. Default: 4

.PARAMETER IncludeExternal
    Also parse JS/JSON assets hosted on third-party domains (CDN, etc.)

.PARAMETER SkipRobots
    Ignore robots.txt

.PARAMETER OutputFile
    Export results to JSON file

.PARAMETER CheckDNS
    Use DNS instead of HTTP to check bucket existence

.PARAMETER TimeoutSec
    HTTP timeout in seconds. Default: 10

.EXAMPLE
    .\Invoke-S3BucketWebCrawler.ps1 -Domain "example.com"

.EXAMPLE
    .\Invoke-S3BucketWebCrawler.ps1 -Domain "example.com" -MaxPages 300 -OutputFile "report.json"

.NOTES
    Defensive use only. Only audit domains you own or have written authorization to test.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$Domain,

    [int]$MaxPages = 200,

    [int]$MaxDepth = 4,

    [switch]$IncludeExternal,

    [switch]$SkipRobots,

    [string]$OutputFile,

    [switch]$CheckDNS,

    [int]$TimeoutSec = 10
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "SilentlyContinue"

$script:VERSION    = "2.0"
$script:RATE_MS    = 300
$script:S3_RATE_MS = 200
$script:UA         = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36"

$script:S3_PATTERNS = @(
    '(?i)([a-z0-9][a-z0-9\-\.]{1,61}[a-z0-9])\.s3(?:[-\.][a-z0-9\-]+)?\.amazonaws\.com',
    '(?i)s3(?:[-\.][a-z0-9\-]+)?\.amazonaws\.com/([a-z0-9][a-z0-9\-\.]{1,61}[a-z0-9])',
    '(?i)arn:aws:s3:::([a-z0-9][a-z0-9\-\.]{1,61}[a-z0-9])',
    '(?i)s3[an]?://([a-z0-9][a-z0-9\-\.]{1,61}[a-z0-9])(?:/|")',
    '(?i)bucket(?:_name)?\s*[=:]\s*["\x27]([a-z0-9][a-z0-9\-\.]{1,61}[a-z0-9])["\x27]',
    '(?i)s3[an]?://([a-z0-9][a-z0-9\-\.]{1,61}[a-z0-9])/'
)

$script:WHITELIST = @(
    "aws-cloudtrail-logs", "elasticmapreduce", "aws-codestar-",
    "cloudformation-examples-", "aws-glue-", "sagemaker-",
    "amazon-braket-", "aws-sam-cli-managed-", "cdk-hnb659fds-",
    "amplify-", "serverlessdeploymentbucket", "aws-logs-"
)

# ---------------------------------------------------------------------------
# DISPLAY
# ---------------------------------------------------------------------------

function Write-Banner {
    Write-Host ""
    Write-Host "  ==========================================================" -ForegroundColor Cyan
    Write-Host "   S3 Abandoned Bucket Web Crawler  v$($script:VERSION)" -ForegroundColor Cyan
    Write-Host "   Defensive use only" -ForegroundColor DarkGray
    Write-Host "  ==========================================================" -ForegroundColor Cyan
    Write-Host ""
}

function Write-Log {
    param(
        [string]$Msg,
        [string]$L = "INFO"
    )
    $ts = Get-Date -Format "HH:mm:ss"
    switch ($L) {
        "OK"    { Write-Host "  [+] [$ts] $Msg" -ForegroundColor Green }
        "WARN"  { Write-Host "  [!] [$ts] $Msg" -ForegroundColor Yellow }
        "ERR"   { Write-Host "  [-] [$ts] $Msg" -ForegroundColor Red }
        "DEAD"  { Write-Host "  [X] [$ts] $Msg" -ForegroundColor Magenta }
        "STEP"  { Write-Host "  [>] [$ts] $Msg" -ForegroundColor Cyan }
        "DIM"   { Write-Host "      [$ts] $Msg" -ForegroundColor DarkGray }
        default { Write-Host "  [*] [$ts] $Msg" -ForegroundColor White }
    }
}

# ---------------------------------------------------------------------------
# URL HELPERS
# ---------------------------------------------------------------------------

function Get-NormalizedBaseUrl {
    param([string]$Raw)
    $s = $Raw.Trim()
    if ($s -notmatch '^https?://') {
        $s = "https://$s"
    }
    return $s.TrimEnd('/')
}

function Get-HostFromUrl {
    param([string]$Url)
    try {
        return ([uri]$Url).Host
    }
    catch {
        return $null
    }
}

function Get-ExtFromUrl {
    param([string]$Url)
    try {
        return [System.IO.Path]::GetExtension(([uri]$Url).AbsolutePath).ToLower()
    }
    catch {
        return ""
    }
}

# ---------------------------------------------------------------------------
# ROBOTS.TXT
# ---------------------------------------------------------------------------

function Get-RobotsDisallowed {
    param([string]$BaseUrl)

    $disallowed = [System.Collections.Generic.HashSet[string]]::new()

    try {
        $wc = [System.Net.WebClient]::new()
        $wc.Headers.Add("User-Agent", $script:UA)
        $wc.Encoding = [System.Text.Encoding]::UTF8
        $content = $wc.DownloadString("$BaseUrl/robots.txt")
        $wc.Dispose()

        $inAll = $false
        foreach ($line in ($content -split "`n")) {
            $line = $line.Trim()
            if ($line -match '^User-agent:\s*\*') {
                $inAll = $true
                continue
            }
            if ($line -match '^User-agent:') {
                $inAll = $false
                continue
            }
            if ($inAll -and $line -match '^Disallow:\s*(.+)') {
                $p = $Matches[1].Trim()
                if ($p -ne "" -and $p -ne "/") {
                    [void]$disallowed.Add($p)
                }
            }
        }
        Write-Log "robots.txt read - $($disallowed.Count) path(s) excluded" "DIM"
    }
    catch {
        Write-Log "robots.txt not found or unreadable (skipped)" "DIM"
    }

    return $disallowed
}

function Test-RobotsAllowed {
    param(
        [string]$Url,
        [System.Collections.Generic.HashSet[string]]$Disallowed
    )
    if ($Disallowed.Count -eq 0) { return $true }
    try {
        $path = ([uri]$Url).AbsolutePath
        foreach ($d in $Disallowed) {
            if ($path.StartsWith($d)) { return $false }
        }
    }
    catch { }
    return $true
}

# ---------------------------------------------------------------------------
# HTTP FETCH
# ---------------------------------------------------------------------------

function Invoke-SafeGet {
    param([string]$Url)

    $result = @{
        Success     = $false
        Body        = ""
        ContentType = ""
        FinalUrl    = $Url
    }

    try {
        $req = [System.Net.HttpWebRequest]::Create($Url)
        $req.Method = "GET"
        $req.Timeout = $TimeoutSec * 1000
        $req.UserAgent = $script:UA
        $req.AllowAutoRedirect = $true
        $req.MaximumAutomaticRedirections = 5
        $req.Accept = "text/html,application/xhtml+xml,*/*;q=0.8"

        $resp   = $req.GetResponse()
        $stream = $resp.GetResponseStream()
        $reader = [System.IO.StreamReader]::new($stream, [System.Text.Encoding]::UTF8)
        $body   = $reader.ReadToEnd()
        $reader.Close()
        $resp.Close()

        $result.Success     = $true
        $result.Body        = $body
        $result.ContentType = $resp.ContentType
        $result.FinalUrl    = $resp.ResponseUri.ToString()
    }
    catch {
        # network error - result stays Success=false
    }

    return $result
}

# ---------------------------------------------------------------------------
# EXTRACT LINKS FROM HTML
# ---------------------------------------------------------------------------

function Get-LinksFromHtml {
    param(
        [string]$Html,
        [string]$BaseUrl,
        [string]$TargetHost
    )

    $links = [System.Collections.Generic.HashSet[string]]::new()
    $base  = [uri]$BaseUrl
    $attrs = 'href|src|action|data-src|data-href|data-url'
    $rx    = "(?i)(?:$attrs)\s*=\s*[`"']([^`"'#>]{3,})[`"']"

    $regexMatches = [regex]::Matches($Html, $rx)
    foreach ($m in $regexMatches) {
        $raw = $m.Groups[1].Value.Trim()
        if ([string]::IsNullOrEmpty($raw)) { continue }
        if ($raw -match '^(mailto:|tel:|javascript:|data:|#)') { continue }

        try {
            $uri = [uri]::new($base, $raw)
            $abs = $uri.ToString().Split('#')[0].TrimEnd('/')

            if ($uri.Host -eq $TargetHost) {
                [void]$links.Add($abs)
            }
            elseif ($IncludeExternal) {
                $ext = Get-ExtFromUrl -Url $abs
                if ($ext -in @(".js",".json",".xml") -or $abs -match 'amazonaws\.com') {
                    [void]$links.Add($abs)
                }
            }
        }
        catch { }
    }

    return $links
}

# ---------------------------------------------------------------------------
# EXTRACT S3 REFERENCES FROM TEXT CONTENT
# ---------------------------------------------------------------------------

function Get-S3BucketsFromContent {
    param(
        [string]$Content,
        [string]$SourceUrl
    )

    $found = [System.Collections.Generic.List[hashtable]]::new()

    foreach ($pattern in $script:S3_PATTERNS) {
        $regexMatches = [regex]::Matches($Content, $pattern)
        foreach ($m in $regexMatches) {
            $name = $null
            if ($m.Groups.Count -gt 1 -and $m.Groups[1].Success) {
                $name = $m.Groups[1].Value.ToLower().Trim('.')
            }
            if ([string]::IsNullOrEmpty($name)) { continue }
            if ($name.Length -lt 3 -or $name.Length -gt 63) { continue }
            if ($name -match '[^a-z0-9\-\.]') { continue }
            if ($name -match '\.\.')          { continue }
            if ($name -match '-$')            { continue }
            if ($name -match '^\d{1,3}(\.\d{1,3}){3}$') { continue }

            $white = $false
            foreach ($p in $script:WHITELIST) {
                if ($name.StartsWith($p)) { $white = $true; break }
            }
            if ($white) { continue }

            $found.Add(@{
                BucketName = $name
                FullMatch  = $m.Value
                SourceUrl  = $SourceUrl
            })
        }
    }

    return $found
}

# ---------------------------------------------------------------------------
# S3 BUCKET EXISTENCE CHECK
# ---------------------------------------------------------------------------

function Test-S3Bucket {
    param(
        [string]$BucketName,
        [switch]$DNS
    )

    Start-Sleep -Milliseconds $script:S3_RATE_MS

    $r = @{
        BucketName  = $BucketName
        Exists      = $null
        Status      = "UNKNOWN"
        StatusCode  = $null
        Region      = $null
        IsPublic    = $false
        Error       = $null
    }

    if ($DNS) {
        try {
            [void][System.Net.Dns]::GetHostEntry("$BucketName.s3.amazonaws.com")
            $r.Exists = $true
            $r.Status = "EXISTS"
        }
        catch [System.Net.Sockets.SocketException] {
            if ($_.Exception.SocketErrorCode -eq "HostNotFound") {
                $r.Exists = $false
                $r.Status = "ABANDONED"
            }
            else {
                $r.Status = "DNS_ERROR"
                $r.Error  = $_.Exception.Message
            }
        }
        catch {
            $r.Status = "DNS_ERROR"
            $r.Error  = $_.Exception.Message
        }
        return $r
    }

    # HTTP HEAD check
    $url = "https://$BucketName.s3.amazonaws.com/"

    try {
        $req = [System.Net.HttpWebRequest]::Create($url)
        $req.Method = "HEAD"
        $req.Timeout = $TimeoutSec * 1000
        $req.UserAgent = $script:UA
        $req.AllowAutoRedirect = $true

        $resp = $req.GetResponse()
        $r.StatusCode = [int]$resp.StatusCode
        $r.IsPublic   = ($r.StatusCode -eq 200)
        $r.Exists     = $true

        if ($resp.Headers["x-amz-bucket-region"]) {
            $r.Region = $resp.Headers["x-amz-bucket-region"]
        }

        $r.Status = if ($r.IsPublic) { "PUBLIC" } else { "EXISTS_PRIVATE" }
        $resp.Close()
    }
    catch [System.Net.WebException] {
        $webEx = $_.Exception

        if ($null -ne $webEx.Response) {
            $hr = [System.Net.HttpWebResponse]$webEx.Response
            $r.StatusCode = [int]$hr.StatusCode

            try {
                $sr   = [System.IO.StreamReader]::new($hr.GetResponseStream())
                $body = $sr.ReadToEnd()
                $sr.Close()

                if     ($body -match '<Code>NoSuchBucket</Code>')      { $r.Exists = $false; $r.Status = "ABANDONED" }
                elseif ($body -match '<Code>AllAccessDisabled</Code>') { $r.Exists = $true;  $r.Status = "LOCKED" }
                elseif ($body -match '<Code>AccessDenied</Code>')      { $r.Exists = $true;  $r.Status = "PRIVATE" }
                elseif ($r.StatusCode -eq 301) {
                    $r.Exists = $true
                    $r.Status = "EXISTS_REDIRECT"
                    if ($hr.Headers["x-amz-bucket-region"]) {
                        $r.Region = $hr.Headers["x-amz-bucket-region"]
                    }
                }
                else {
                    $r.Status = "HTTP_$($r.StatusCode)"
                }
            }
            catch {
                $r.Status = "PARSE_ERROR"
                $r.Error  = $_.Exception.Message
            }

            $hr.Close()
        }
        else {
            $r.Status = "NETWORK_ERROR"
            $r.Error  = $webEx.Message
        }
    }
    catch {
        $r.Status = "ERROR"
        $r.Error  = $_.Exception.Message
    }

    return $r
}

# ---------------------------------------------------------------------------
# MAIN CRAWLER
# ---------------------------------------------------------------------------

function Invoke-WebCrawl {
    param(
        [string]$BaseUrl,
        [string]$TargetHost
    )

    $queue      = [System.Collections.Generic.Queue[hashtable]]::new()
    $visited    = [System.Collections.Generic.HashSet[string]]::new()
    $allBuckets = [System.Collections.Generic.Dictionary[string,
                    System.Collections.Generic.List[hashtable]]]::new()
    $pageLog    = [System.Collections.Generic.List[hashtable]]::new()

    if ($SkipRobots) {
        $disallowed = [System.Collections.Generic.HashSet[string]]::new()
    }
    else {
        $disallowed = Get-RobotsDisallowed -BaseUrl $BaseUrl
    }

    $queue.Enqueue(@{ Url = $BaseUrl; Depth = 0 })
    [void]$visited.Add($BaseUrl)

    $pageCount  = 0
    $assetCount = 0

    Write-Log "Starting crawl on $TargetHost" "STEP"
    Write-Host ""

    while ($queue.Count -gt 0 -and ($pageCount + $assetCount) -lt $MaxPages) {

        $item  = $queue.Dequeue()
        $url   = $item.Url
        $depth = $item.Depth

        if (-not (Test-RobotsAllowed -Url $url -Disallowed $disallowed)) {
            Write-Log "Skipped (robots.txt): $url" "DIM"
            continue
        }

        $ext     = Get-ExtFromUrl -Url $url
        $isPage  = ($ext -in @(".html",".htm","") -or $url -eq $BaseUrl)
        $isAsset = ($ext -in @(".js",".mjs",".jsx",".json",".xml",".css",".yaml",".yml",".txt"))

        if (-not ($isPage -or $isAsset)) { continue }

        if ($isPage)  { $pageCount++ }
        else          { $assetCount++ }

        $total    = $pageCount + $assetCount
        $icon     = if ($isPage) { "[HTML] " } else { "[ASSET]" }
        $shortUrl = if ($url.Length -gt 90) { $url.Substring(0,87) + "..." } else { $url }

        Write-Host "  $icon " -NoNewline -ForegroundColor DarkCyan
        Write-Host "[$total] " -NoNewline -ForegroundColor DarkGray
        Write-Host $shortUrl -ForegroundColor Gray

        Start-Sleep -Milliseconds $script:RATE_MS

        $result = Invoke-SafeGet -Url $url
        if (-not $result.Success) {
            Write-Log "Failed to fetch: $url" "DIM"
            continue
        }

        $body = $result.Body

        # Extract S3 references
        $buckets = Get-S3BucketsFromContent -Content $body -SourceUrl $url

        foreach ($b in $buckets) {
            if (-not $allBuckets.ContainsKey($b.BucketName)) {
                $allBuckets[$b.BucketName] = [System.Collections.Generic.List[hashtable]]::new()
            }

            $alreadyLogged = $false
            foreach ($existing in $allBuckets[$b.BucketName]) {
                if ($existing.SourceUrl -eq $b.SourceUrl) {
                    $alreadyLogged = $true
                    break
                }
            }

            if (-not $alreadyLogged) {
                $allBuckets[$b.BucketName].Add($b)
                Write-Host "     " -NoNewline
                Write-Host " >> S3 found: " -NoNewline -ForegroundColor Yellow
                Write-Host $b.BucketName -ForegroundColor Cyan
            }
        }

        $pageLog.Add(@{
            Url     = $url
            Depth   = $depth
            IsPage  = $isPage
            Buckets = @($buckets | ForEach-Object { $_.BucketName })
        })

        # Extract links (HTML pages only, within depth limit)
        if ($isPage -and $depth -lt $MaxDepth) {
            $links = Get-LinksFromHtml -Html $body -BaseUrl $url -TargetHost $TargetHost

            foreach ($link in $links) {
                if ($visited.Contains($link)) { continue }
                [void]$visited.Add($link)

                $linkExt  = Get-ExtFromUrl -Url $link
                $linkHost = Get-HostFromUrl -Url $link

                if ($linkHost -eq $TargetHost) {
                    $queue.Enqueue(@{ Url = $link; Depth = ($depth + 1) })
                }
                elseif ($IncludeExternal -and $linkExt -in @(".js",".mjs",".json",".xml",".yaml",".yml")) {
                    $queue.Enqueue(@{ Url = $link; Depth = ($depth + 1) })
                }
            }
        }
    }

    Write-Host ""
    Write-Log "Crawl complete: $pageCount page(s), $assetCount asset(s), $($visited.Count) URL(s) visited" "OK"
    Write-Log "Unique S3 buckets detected: $($allBuckets.Count)" "OK"

    return @{
        Buckets = $allBuckets
        PageLog = $pageLog
        Stats   = @{
            Pages   = $pageCount
            Assets  = $assetCount
            Visited = $visited.Count
        }
    }
}

# ---------------------------------------------------------------------------
# BATCH BUCKET VERIFICATION
# ---------------------------------------------------------------------------

function Invoke-BucketVerification {
    param(
        [System.Collections.Generic.Dictionary[string,
            System.Collections.Generic.List[hashtable]]]$Buckets
    )

    if ($Buckets.Count -eq 0) {
        Write-Log "No buckets to verify." "WARN"
        return @()
    }

    $mode = if ($CheckDNS) { "DNS" } else { "HTTP" }
    Write-Host ""
    Write-Log "Verifying $($Buckets.Count) bucket(s) via $mode ..." "STEP"
    Write-Host ""

    $findings = [System.Collections.Generic.List[hashtable]]::new()
    $i = 0

    foreach ($entry in $Buckets.GetEnumerator()) {
        $i++
        $name    = $entry.Key
        $sources = $entry.Value

        Write-Progress -Activity "Checking S3 buckets" `
            -Status "[$i/$($Buckets.Count)] $name" `
            -PercentComplete ([Math]::Round(($i / $Buckets.Count) * 100))

        $check = Test-S3Bucket -BucketName $name -DNS:$CheckDNS

        $icon = switch ($check.Status) {
            "ABANDONED"       { "[DEAD]" }
            "PUBLIC"          { "[OPEN]" }
            "EXISTS_PRIVATE"  { "[PRIV]" }
            "PRIVATE"         { "[PRIV]" }
            "LOCKED"          { "[LOCK]" }
            "EXISTS_REDIRECT" { "[RDIR]" }
            "EXISTS"          { "[LIVE]" }
            default           { "[????]" }
        }

        $color = switch ($check.Status) {
            "ABANDONED"       { "Magenta" }
            "PUBLIC"          { "Green" }
            "EXISTS_PRIVATE"  { "DarkGreen" }
            "PRIVATE"         { "DarkGreen" }
            "LOCKED"          { "DarkYellow" }
            "EXISTS_REDIRECT" { "Cyan" }
            "EXISTS"          { "Green" }
            default           { "DarkGray" }
        }

        $label = switch ($check.Status) {
            "ABANDONED"       { "ABANDONED  <-- HIJACKABLE" }
            "PUBLIC"          { "PUBLIC (listing/read possible)" }
            "EXISTS_PRIVATE"  { "PRIVATE (exists, access denied)" }
            "PRIVATE"         { "PRIVATE (exists, access denied)" }
            "LOCKED"          { "LOCKED" }
            "EXISTS_REDIRECT" { "EXISTS in region: $($check.Region)" }
            "EXISTS"          { "EXISTS" }
            default           { $check.Status }
        }

        Write-Host "  $icon " -NoNewline -ForegroundColor $color
        Write-Host $name.PadRight(52) -NoNewline -ForegroundColor White
        Write-Host $label -ForegroundColor $color

        foreach ($src in ($sources | Select-Object -First 3)) {
            $s = if ($src.SourceUrl.Length -gt 75) { $src.SourceUrl.Substring(0,72) + "..." } else { $src.SourceUrl }
            Write-Host "        > $s" -ForegroundColor DarkGray
        }
        if ($sources.Count -gt 3) {
            Write-Host "        > ...and $($sources.Count - 3) more source(s)" -ForegroundColor DarkGray
        }

        $findings.Add(@{
            BucketName  = $name
            Status      = $check.Status
            StatusCode  = $check.StatusCode
            IsAbandoned = ($check.Status -eq "ABANDONED")
            IsPublic    = $check.IsPublic
            Region      = $check.Region
            Error       = $check.Error
            Sources     = @($sources | ForEach-Object {
                @{ SourceUrl = $_.SourceUrl; Match = $_.FullMatch }
            })
            SourceCount = $sources.Count
        })
    }

    Write-Progress -Activity "Checking S3 buckets" -Completed
    return $findings
}

# ---------------------------------------------------------------------------
# FINAL REPORT
# ---------------------------------------------------------------------------

function Show-Report {
    param(
        [array]$Findings,
        [string]$TargetDomain,
        [hashtable]$Stats
    )

    $abandoned = @($Findings | Where-Object { $_.IsAbandoned })
    $public    = @($Findings | Where-Object { $_.IsPublic -and -not $_.IsAbandoned })
    $private   = @($Findings | Where-Object {
        -not $_.IsAbandoned -and
        -not $_.IsPublic -and
        $_.Status -notin @("TIMEOUT_OR_NETWORK","UNKNOWN","ERROR","NETWORK_ERROR")
    })

    $bar = "=" * 68

    Write-Host ""
    Write-Host "  $bar" -ForegroundColor DarkGray
    Write-Host "  FINAL REPORT -- $TargetDomain" -ForegroundColor Cyan
    Write-Host "  $bar" -ForegroundColor DarkGray

    Write-Host ""
    Write-Host "  CRAWL STATS:" -ForegroundColor White
    Write-Host "    Pages crawled  : $($Stats.Pages)" -ForegroundColor Gray
    Write-Host "    Assets parsed  : $($Stats.Assets)" -ForegroundColor Gray
    Write-Host "    URLs visited   : $($Stats.Visited)" -ForegroundColor Gray

    Write-Host ""
    Write-Host "  S3 BUCKETS:" -ForegroundColor White
    Write-Host "    Total found    : $($Findings.Count)" -ForegroundColor Gray

    if ($abandoned.Count -gt 0) {
        Write-Host "    [DEAD] Abandoned : $($abandoned.Count)  <-- CRITICAL" -ForegroundColor Magenta
    }
    else {
        Write-Host "    [DEAD] Abandoned : 0" -ForegroundColor Gray
    }

    if ($public.Count -gt 0) {
        Write-Host "    [OPEN] Public    : $($public.Count)  <-- Review" -ForegroundColor Yellow
    }
    else {
        Write-Host "    [OPEN] Public    : 0" -ForegroundColor Gray
    }

    Write-Host "    [PRIV] Private   : $($private.Count)" -ForegroundColor Gray

    if ($abandoned.Count -gt 0) {
        Write-Host ""
        Write-Host "  $bar" -ForegroundColor DarkGray
        Write-Host "  [DEAD] ABANDONED BUCKETS -- HIJACKABLE" -ForegroundColor Magenta
        Write-Host "  $bar" -ForegroundColor DarkGray

        foreach ($b in $abandoned) {
            Write-Host ""
            Write-Host "  Bucket : " -NoNewline -ForegroundColor Gray
            Write-Host $b.BucketName -ForegroundColor Magenta
            Write-Host "  Found in $($b.SourceCount) source URL(s):" -ForegroundColor Gray
            foreach ($src in ($b.Sources | Select-Object -First 5)) {
                Write-Host "    > $($src.SourceUrl)" -ForegroundColor DarkGray
                if ($src.Match) {
                    $short = if ($src.Match.Length -gt 80) { $src.Match.Substring(0,77) + "..." } else { $src.Match }
                    Write-Host "      match : $short" -ForegroundColor DarkGray
                }
            }
        }

        Write-Host ""
        Write-Host "  RECOMMENDED ACTIONS:" -ForegroundColor Cyan
        Write-Host "    1. Re-register abandoned buckets immediately with a deny-all bucket policy"
        Write-Host "    2. Update all references to point to controlled CDN or S3 URLs"
        Write-Host "    3. Add SHA256 integrity checks (SRI) on all fetched assets"
        Write-Host "    4. Enable AWS Config rules to detect orphaned resources"
        Write-Host "    5. Add an SCP to prevent accidental deletion of production buckets"
    }

    if ($public.Count -gt 0) {
        Write-Host ""
        Write-Host "  $bar" -ForegroundColor DarkGray
        Write-Host "  [OPEN] PUBLIC BUCKETS (review access)" -ForegroundColor Yellow
        Write-Host "  $bar" -ForegroundColor DarkGray
        foreach ($b in $public) {
            $reg = if ($b.Region) { " [$($b.Region)]" } else { "" }
            Write-Host "    $($b.BucketName)$reg" -ForegroundColor Yellow
        }
    }

    Write-Host ""
    Write-Host "  $bar" -ForegroundColor DarkGray
    Write-Host ""
}

# ---------------------------------------------------------------------------
# ENTRY POINT
# ---------------------------------------------------------------------------

Write-Banner

$baseUrl    = Get-NormalizedBaseUrl -Raw $Domain
$targetHost = Get-HostFromUrl -Url $baseUrl

if ([string]::IsNullOrEmpty($targetHost)) {
    Write-Log "Invalid domain: $Domain" "ERR"
    exit 1
}

Write-Log "Target    : $baseUrl"    "INFO"
Write-Log "Host      : $targetHost" "INFO"
Write-Log "MaxPages  : $MaxPages  |  MaxDepth: $MaxDepth" "INFO"
Write-Log "External  : $($IncludeExternal.IsPresent)  |  CheckDNS: $($CheckDNS.IsPresent)" "INFO"
Write-Log "Started   : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" "INFO"
Write-Host ""

# Phase 1 - Crawl
$crawl = Invoke-WebCrawl -BaseUrl $baseUrl -TargetHost $targetHost

# Phase 2 - Verify buckets
$findings = Invoke-BucketVerification -Buckets $crawl.Buckets

# Phase 3 - Report
Show-Report -Findings $findings -TargetDomain $targetHost -Stats $crawl.Stats

# Optional JSON export
if (-not [string]::IsNullOrEmpty($OutputFile)) {
    $export = @{
        Timestamp    = (Get-Date -Format "o")
        Version      = $script:VERSION
        Target       = $baseUrl
        Host         = $targetHost
        CrawlStats   = $crawl.Stats
        TotalBuckets = $findings.Count
        Abandoned    = @($findings | Where-Object IsAbandoned).Count
        Public       = @($findings | Where-Object IsPublic).Count
        Findings     = $findings
    }
    $export | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutputFile -Encoding UTF8
    Write-Log "Results exported to: $OutputFile" "OK"
}

Write-Log "Done: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" "OK"
