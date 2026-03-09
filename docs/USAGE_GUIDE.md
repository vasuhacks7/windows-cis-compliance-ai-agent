# 📘 Windows CIS Compliance AI Agent — Usage Guide

## 🎯 Overview

The **Windows CIS Compliance AI Agent** is a tool that converts Nessus CIS compliance scan CSV exports into verified, company-branded Excel reports. It optionally uses AI (OpenAI GPT models) to validate each finding by running PowerShell commands on the target Windows Server.

---

## 🚀 Quick Start

### Step 1: Export Nessus Scan

1. Open Nessus → Select your CIS compliance scan
2. Export → Choose **CSV** format
3. Save the file (e.g., `windows_2022_cis.csv`)

### Step 2: Set API Key & Base URL (One-Time)

```powershell
# Set your OpenAI API key
setx OPENAI_API_KEY "sk-proj-your-key-here"

# If using a custom endpoint (Azure OpenAI, proxy, etc.), also set the base URL:
setx OPENAI_BASE_URL "https://your-custom-endpoint.com/v1"

# RESTART your terminal after setting the key!
```

Or pass the base URL directly via `--api-base`:
```powershell
python windows_cis_compliance_ai_agent.py ... --api-base "https://your-custom-endpoint.com/v1"
```

### Step 3: Test with 5 Findings

```powershell
python windows_cis_compliance_ai_agent.py `
  -i windows_2022_cis.csv `
  -t samples/template.xlsx `
  -o test_report.xlsx `
  --only-failed `
  --validate `
  --add-evidence `
  --limit 5
```

### Step 4: Review Results

Open `test_report.xlsx` and verify the results look correct.

### Step 5: Full Run

```powershell
python windows_cis_compliance_ai_agent.py `
  -i windows_2022_cis.csv `
  -t samples/template.xlsx `
  -o final_report.xlsx `
  --only-failed `
  --validate `
  --add-evidence
```

---

## 📊 Output Modes

### Mode 1: Format Only (No AI)

```powershell
python windows_cis_compliance_ai_agent.py `
  -i scan.csv -t samples/template.xlsx -o report.xlsx --only-failed
```

- **Time:** ~5 seconds
- **Cost:** $0
- **Output:** Excel with Nessus status (may contain false positives)

### Mode 2: AI Validation

```powershell
python windows_cis_compliance_ai_agent.py `
  -i scan.csv -t samples/template.xlsx -o report.xlsx `
  --only-failed --validate
```

- **Time:** ~15 minutes (225 findings)
- **Cost:** ~$0.12
- **Output:** Excel with verified status

### Mode 3: AI Validation + Evidence

```powershell
python windows_cis_compliance_ai_agent.py `
  -i scan.csv -t samples/template.xlsx -o report.xlsx `
  --only-failed --validate --add-evidence
```

- **Time:** ~15 minutes
- **Cost:** ~$0.12
- **Output:** Excel with verified status + command/output/reasoning columns

---

## 📋 Excel Output Columns

### Standard Columns
| Column | Description |
|--------|-------------|
| Sr. No | Sequential finding number |
| CIS Benchmark | CIS benchmark ID (e.g., `CIS...L1 - 1.1.1`) |
| Finding | Clean finding title |
| Details Summary | Finding description + impact |
| Remediation | Fix steps |
| Status | `Compliant` or `Non Compliant` |

### Evidence Columns (with `--add-evidence`)
| Column | Description |
|--------|-------------|
| Validation Command | PowerShell command executed |
| Validation Output | Command output (first 500 chars) |
| Validation Reasoning | AI explanation of compliance status |
| Expected Pattern | What compliant output should look like |
| Compliance Logic | How compliance is determined |
| Output Type | Category: registry, service, policy, etc. |

### Status Colors
- 🟢 **Green** — Compliant
- 🔴 **Red** — Non Compliant
- 🟡 **Yellow** — Error during validation
- 🔵 **Blue** — Blocked (unsafe command) or Dry-Run

---

## ⚙️ Advanced Usage

### Process a Specific Range of Findings

```powershell
# Skip first 50, process next 25
python windows_cis_compliance_ai_agent.py `
  -i scan.csv -t samples/template.xlsx -o report.xlsx `
  --only-failed --validate --skip 50 --limit 25
```

### Resume an Interrupted Scan

```powershell
# If the scan was interrupted (network error, API timeout, etc.)
python windows_cis_compliance_ai_agent.py `
  -i scan.csv -t samples/template.xlsx -o report.xlsx `
  --only-failed --validate --resume
```

### Dry-Run Mode (Preview Only)

```powershell
python windows_cis_compliance_ai_agent.py `
  -i scan.csv -t samples/template.xlsx -o report.xlsx `
  --only-failed --validate --dry-run
```

### Save Logs to File

```powershell
python windows_cis_compliance_ai_agent.py `
  -i scan.csv -t samples/template.xlsx -o report.xlsx `
  --only-failed --validate --log-file scan_log.txt --verbose
```

### Use a Different AI Model

```powershell
# Use GPT-4o (more accurate, slower, ~10x cost)
python windows_cis_compliance_ai_agent.py `
  -i scan.csv -t samples/template.xlsx -o report.xlsx `
  --only-failed --validate --model gpt-4o
```

### Custom CIS Benchmark Name

```powershell
python windows_cis_compliance_ai_agent.py `
  -i scan.csv -t samples/template.xlsx -o report.xlsx `
  --only-failed --validate `
  --benchmark "CIS Microsoft Windows Server 2019 Stand-alone v2.0.0 L1"
```

### Batch Processing (Multiple Servers)

```powershell
$servers = @("dc01", "web01", "db01", "app01")

foreach ($server in $servers) {
    Write-Host "Processing $server..."
    python windows_cis_compliance_ai_agent.py `
      -i "scans\${server}_scan.csv" `
      -t samples/template.xlsx `
      -o "reports\${server}_report.xlsx" `
      --only-failed --validate --add-evidence
}
```

---

## 🐛 Troubleshooting

### "OPENAI_API_KEY not set"
```powershell
setx OPENAI_API_KEY "your-key"
# RESTART your terminal!
```

### "openai package not installed"
```powershell
pip install -r requirements.txt
```

### PowerShell Commands Fail
Make sure you are running the tool:
- On a **Windows Server** (not Windows 10/11 Home)
- With **Administrator privileges**
- In a **PowerShell** terminal (not CMD)

### Template Column Mismatch
The tool expects these column headers in your Excel template:
- Sr. No
- CIS Benchmark
- Finding
- Details Summary
- Remediation
- Status

### API Rate Limiting
The tool has built-in retry logic with exponential backoff. If you encounter persistent rate limits:
- Use `--limit` to process fewer findings at a time
- Add a delay between runs

---

## 💡 Tips

1. **Always test first** — Use `--limit 5` before processing all findings
2. **Save evidence** — Use `--add-evidence` for audit documentation
3. **Use checkpoints** — For large scans, the tool auto-saves every 10 findings
4. **Compare results** — Run once without `--validate`, once with, and compare
5. **Log everything** — Use `--log-file` and `--verbose` for debugging
