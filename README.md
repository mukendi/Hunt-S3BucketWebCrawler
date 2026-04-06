# Hunt-S3BucketWebCrawler

> **Defensive security tool** — crawls a domain (and its subdomains) to detect references to abandoned Amazon S3 buckets that could be hijacked by an attacker.

---

## Background

In February 2025, the watchTowr Labs research team registered ~150 abandoned S3 buckets still referenced by live software products, governments, and Fortune 500 infrastructure. Over two months, those buckets received **more than 8 million requests** for software updates, CloudFormation templates, VM images, unsigned binaries, and JavaScript files — from networks including military, NASA, and major financial institutions.

The root cause is simple: a bucket gets deleted, its name returns to the public pool, and **anyone can re-register it** and serve whatever content they want to every system that still points to it.

This tool helps you find that exposure **before an attacker does**.

---

## Features

- Crawls HTML pages and parses linked assets (JS, JSON, XML, CSS, YAML)
- Detects S3 references via 6 regex patterns covering all common formats
- Supports a **single domain**, an **inline list of subdomains**, or a **text file** of targets
- **Parallel crawl** via PowerShell RunspacePool (configurable thread count)
- Verifies each discovered bucket via HTTP (reads AWS XML error codes) or DNS
- Deduplicates buckets globally across all targets — one check per bucket regardless of how many subdomains reference it
- Tracks which targets and source URLs reference each bucket
- Color-coded terminal output with per-target crawl summary
- Optional JSON export for integration into CI/CD pipelines or reporting tools
- Respects `robots.txt` by default

---

## Requirements

| Requirement | Detail |
|---|---|
| PowerShell | Version 5.1 or later (Windows built-in) |
| Network access | Outbound HTTPS to target domains and `*.s3.amazonaws.com` |
| Permissions | No AWS credentials required — all checks are unauthenticated |

---

## Installation

No installation required. Download the script and run it directly.

```powershell
# Option 1 - Clone the repository
git clone https://github.com/youruser/Hunt-S3BucketWebCrawler.git
cd Hunt-S3BucketWebCrawler

# Option 2 - Direct download
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/youruser/Hunt-S3BucketWebCrawler/main/Hunt-S3BucketWebCrawler.ps1" `
    -OutFile "Hunt-S3BucketWebCrawler.ps1"
```

---

## Usage

### Basic — single domain

```
powershell.exe -ExecutionPolicy Bypass -File ".\Hunt-S3BucketWebCrawler.ps1" -Domain "exemple.cd"
```


### Use DNS verification instead of HTTP (quieter, less AWS log noise)

```
powershell.exe -ExecutionPolicy Bypass -File ".\Hunt-S3BucketWebCrawler.ps1" -Domain "example.com" -CheckDNS
```

---

## Parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-Domain` | `string` | — | Single target domain. Accepts bare hostnames or  target**. |
| `-MaxDepth` | `int` | `3` | Maximum link depth from the root URL. |
| `-Threads` | `int` | `3` | Number of targets to crawl in parallel (1–10). |
| `-CheckDNS` | `switch` | off | Verify bucket existence via DNS lookup instead of HTTP HEAD. |
| `-IncludeExternal` | `switch` | off | Also parse JS/JSON assets hosted on path. |
| `-TimeoutSec` | `int` | `10` | HTTP timeout per request in seconds. |

---

## Subdomain file format

Plain text, one target per line. Blank lines and lines starting with `#` are skipped.
Both bare hostnames and full URLs are accepted.

```
# Main domain
example.com

# Application subdomains
app.example.com
api.example.com
https://portal.example.com

# Skipped (commented out)
# legacy.example.com
```

---

## How it works

The tool runs in three sequential phases.

```
Phase 1 — CRAWL
  For each target (in parallel if -Threads > 1):
    1. Fetch robots.txt and build exclusion list
    2. BFS crawl: download each HTML page and linked asset
    3. Extract all S3 references using 6 regex patterns
    4. Add new links to the queue (up to MaxDepth)
    5. Push discovered bucket names into the global registry

Phase 2 — VERIFY
  For every unique bucket name found across all targets:
    HTTP HEAD  ->  read AWS XML response code
      NoSuchBucket      => ABANDONED  (hijackable)
      AccessDenied      => PRIVATE    (exists, closed)
      200 OK            => PUBLIC     (exists, readable)
    or DNS lookup (with -CheckDNS)

Phase 3 — REPORT
  Per-target crawl table  (pages / assets / buckets)
  Abandoned bucket list   (with source URLs and target mapping)
  Public bucket list      (access review recommended)
  Remediation checklist
  Optional JSON export
```

### S3 reference patterns detected

| Pattern | Example match |
|---|---|
| Virtual-hosted URL | `bucket-name.s3.amazonaws.com` |
| Virtual-hosted with region | `bucket-name.s3.eu-west-1.amazonaws.com` |
| Path-style URL | `s3.amazonaws.com/bucket-name` |
| ARN | `arn:aws:s3:::bucket-name` |
| S3 URI | `s3://bucket-name/path` |
| Terraform / CloudFormation | `bucket = "bucket-name"` |

---

## Output

### Terminal (color-coded)

```
  [HTML]  [app.example.com|1] https://app.example.com/
       >> S3: my-old-assets-bucket
          found in: https://app.example.com/

  [ASSET] [api.example.com|3] https://api.example.com/config.json
       >> S3: deploy-artifacts-prod
          found in: https://api.example.com/config.json

  [DEAD] my-old-assets-bucket                    ABANDONED  <-- HIJACKABLE
         > [app.example.com]  https://app.example.com/

  [PRIV] deploy-artifacts-prod                   PRIVATE (exists, access denied)
         > [api.example.com]  https://api.example.com/config.json
```

### Bucket status codes

| Code | Meaning | Risk |
|---|---|---|
| `[DEAD] ABANDONED` | `NoSuchBucket` — free to register | **Critical** |
| `[OPEN] PUBLIC` | Bucket exists, content is publicly listable | High |
| `[PRIV] PRIVATE` | Bucket exists, access denied | Low |
| `[LOCK] LOCKED` | `AllAccessDisabled` | Low |
| `[RDIR] EXISTS_REDIRECT` | Exists in a different AWS region | Informational |

### JSON export structure

```json
{
  "Timestamp": "2025-02-01T14:30:00+00:00",
  "Version": "3.0",
  "Targets": ["https://example.com", "https://app.example.com"],
  "CrawlResults": [
    { "Target": "example.com", "Pages": 42, "Assets": 18, "Visited": 60 }
  ],
  "TotalBuckets": 7,
  "Abandoned": 2,
  "Public": 1,
  "Findings": [
    {
      "BucketName": "my-old-assets-bucket",
      "Status": "ABANDONED",
      "IsAbandoned": true,
      "IsPublic": false,
      "Region": null,
      "SourceCount": 3,
      "TargetCount": 2,
      "Targets": ["example.com", "app.example.com"],
      "Sources": [
        {
          "SourceUrl": "https://app.example.com/",
          "Match": "my-old-assets-bucket.s3.amazonaws.com"
        }
      ]
    }
  ]
}
```

---

## Remediation

If abandoned buckets are found, take these actions in order.

**1. Re-register the bucket immediately**
Log into the AWS account that originally owned the bucket and re-register it with a deny-all bucket policy. This prevents anyone else from registering it.

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Deny",
    "Principal": "*",
    "Action": "s3:*",
    "Resource": [
      "arn:aws:s3:::BUCKET-NAME",
      "arn:aws:s3:::BUCKET-NAME/*"
    ]
  }]
}
```

**2. Update all references**
Replace every hardcoded S3 URL in your code, documentation, and build scripts with a URL under your control (your own S3 bucket or CDN).

**3. Add integrity checks**
For any asset fetched from S3 at runtime, add SHA-256 verification. For browser assets, use Subresource Integrity (SRI).

```html
<script src="https://your-bucket.s3.amazonaws.com/app.js"
        integrity="sha256-BASE64HASH="
        crossorigin="anonymous"></script>
```

**4. Enable AWS Config**
Enable the `s3-bucket-public-read-prohibited` and `s3-bucket-public-write-prohibited` managed rules to get alerts when bucket permissions change.

**5. Add an SCP**
Add a Service Control Policy to prevent accidental bucket deletion in production accounts.

```json
{
  "Effect": "Deny",
  "Action": "s3:DeleteBucket",
  "Resource": "*",
  "Condition": {
    "StringEquals": { "aws:ResourceTag/Environment": "production" }
  }
}
```

---

## Examples

### Audit a single domain and save results

```powershell
.\Hunt-S3BucketWebCrawler.ps1 -Domain "example.com" -MaxPages 200 -OutputFile "example-report.json"
```

### Audit a full subdomain list from a recon tool output

```powershell
# Works directly with output from tools like subfinder, amass, etc.
.\Hunt-S3BucketWebCrawler.ps1 -SubdomainFile ".\subfinder-output.txt" -Threads 8 -MaxPages 50
```

### Quiet DNS-only check (no HTTP to target, minimal footprint)

```powershell
.\Hunt-S3BucketWebCrawler.ps1 -Domain "example.com" -CheckDNS -MaxPages 30
```

### Include third-party CDN assets (broader coverage)

```powershell
.\Hunt-S3BucketWebCrawler.ps1 -Domain "example.com" -IncludeExternal -MaxPages 100
```

### Loop over results from another tool

```powershell
$targets = Get-Content ".\urls_success.txt" | Where-Object { $_.Trim() -ne "" -and -not $_.StartsWith("#") }

.\Hunt-S3BucketWebCrawler.ps1 `
    -Subdomains $targets `
    -Threads 5 `
    -MaxPages 50 `
    -OutputFile "bulk-report.json"
```

---

## Limitations

- **JavaScript-rendered content**: The crawler does not execute JavaScript. Buckets referenced only in dynamically rendered DOM or in `fetch()` calls inside SPAs may not be detected. Use `-IncludeExternal` and increase `-MaxPages` to improve coverage, or extract JS file URLs separately and feed them as targets.
- **Rate limiting**: Some targets may return 429 or block the crawler after many requests. Reduce `-MaxPages` or increase `-TimeoutSec` if this occurs.
- **HTTPS only**: The crawler connects via HTTPS by default. Targets that redirect HTTP to HTTPS are handled automatically.
- **Authentication-gated pages**: Content behind login walls is not crawled.

---

## Legal notice

This tool is intended for **defensive security auditing only**.

Only use it against domains and infrastructure that you own or have **explicit written authorization** to test. Unauthorized scanning of third-party systems may violate computer fraud laws in your jurisdiction.

The authors accept no liability for misuse.

---

## References

- [watchTowr Labs — 8 Million Requests Later](https://labs.watchtowr.com/8-million-requests-later-we-made-the-solarwinds-supply-chain-attack-look-amateur/) — the research that inspired this tool
- [AWS S3 Bucket Policy reference](https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-policies.html)
- [AWS Config managed rules](https://docs.aws.amazon.com/config/latest/developerguide/managed-rules-by-aws-config.html)
- [Subresource Integrity (MDN)](https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity)