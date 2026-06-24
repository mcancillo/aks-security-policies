<#
.SYNOPSIS
    CLZ v2 Security Maturity Scanner — HTML Report Generator
.DESCRIPTION
    Generates a comprehensive HTML web report with maturity scoring,
    findings grouped by category/severity, and executive summary.
#>

function New-SecurityReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][array]$SubscriptionResults,
        [Parameter(Mandatory)][string]$OutputPath,
        [string]$ScanTimestamp
    )

    $allFindings = $SubscriptionResults | ForEach-Object { $_.Findings } | ForEach-Object { $_ }
    $overallScore = [math]::Round(($SubscriptionResults | ForEach-Object { $_.OverallScore } | Measure-Object -Average).Average, 0)

    $criticalCount = ($allFindings | Where-Object { $_.Severity -eq 'Critical' }).Count
    $highCount     = ($allFindings | Where-Object { $_.Severity -eq 'High' }).Count
    $mediumCount   = ($allFindings | Where-Object { $_.Severity -eq 'Medium' }).Count
    $infoCount     = ($allFindings | Where-Object { $_.Severity -eq 'Info' }).Count

    $scoreColor = if ($overallScore -ge 80) { '#22c55e' } elseif ($overallScore -ge 60) { '#f59e0b' } elseif ($overallScore -ge 40) { '#f97316' } else { '#ef4444' }
    $maturityLevel = if ($overallScore -ge 80) { 'Run' } elseif ($overallScore -ge 60) { 'Walk' } elseif ($overallScore -ge 40) { 'Crawl' } else { 'Pre-Crawl' }

    # Build findings rows
    $findingsHtml = ""
    $rowIndex = 0
    $groupedByCategory = $allFindings | Group-Object -Property Category
    foreach ($group in ($groupedByCategory | Sort-Object Name)) {
        foreach ($f in ($group.Group | Sort-Object { switch ($_.Severity) { 'Critical' { 0 } 'High' { 1 } 'Medium' { 2 } 'Info' { 3 } default { 4 } } })) {
            $sevClass = switch ($f.Severity) { 'Critical' { 'sev-critical' } 'High' { 'sev-high' } 'Medium' { 'sev-medium' } default { 'sev-info' } }
            $perspIcon = if ($f.Perspective -eq 'Hacker') { '&#x1F3AD;' } else { '&#x1F3E2;' }
            $hasArtifacts = ($f.Artifacts -and $f.Artifacts.Count -gt 0)
            $cursorStyle = if ($hasArtifacts) { 'cursor: pointer;' } else { '' }
            $expandHint = if ($hasArtifacts) { '<span class="expand-hint">&#x25B6; Double-click to expand ($($f.Artifacts.Count) items)</span>' } else { '' }

            $findingsHtml += @"
            <tr class="finding-row" data-row="$rowIndex" style="$cursorStyle">
                <td><span class="badge $sevClass">$($f.Severity)</span></td>
                <td>$($f.Category)</td>
                <td><strong>$($f.Check)</strong><br><span class="detail">$($f.Detail)</span>$expandHint</td>
                <td class="remediation">$($f.Remediation)</td>
                <td class="perspective">$perspIcon $($f.Perspective)</td>
            </tr>
"@
            # Build artifact detail row (hidden by default)
            if ($hasArtifacts) {
                $artifactTableHtml = "<table class='artifact-table'><thead><tr>"
                $headers = $f.Artifacts[0].Keys | Sort-Object
                foreach ($h in $headers) {
                    $artifactTableHtml += "<th>$h</th>"
                }
                $artifactTableHtml += "</tr></thead><tbody>"
                foreach ($artifact in $f.Artifacts) {
                    $artifactTableHtml += "<tr>"
                    foreach ($h in $headers) {
                        $val = if ($artifact[$h]) { $artifact[$h] } else { '-' }
                        $artifactTableHtml += "<td>$val</td>"
                    }
                    $artifactTableHtml += "</tr>"
                }
                $artifactTableHtml += "</tbody></table>"

                $findingsHtml += @"
            <tr class="artifact-row" data-row="$rowIndex" style="display:none;">
                <td colspan="5">
                    <div class="artifact-container">
                        <div class="artifact-header">&#x1F4CB; Associated Items ($($f.Artifacts.Count))</div>
                        $artifactTableHtml
                    </div>
                </td>
            </tr>
"@
            }
            $rowIndex++
        }
    }

    # Build subscription summary rows
    $subSummaryHtml = ""
    foreach ($sub in $SubscriptionResults) {
        $subColor = if ($sub.OverallScore -ge 80) { '#22c55e' } elseif ($sub.OverallScore -ge 60) { '#f59e0b' } else { '#ef4444' }
        $subSummaryHtml += @"
        <tr>
            <td>$($sub.SubscriptionName)</td>
            <td><code>$($sub.SubscriptionId)</code></td>
            <td>$($sub.Environment)</td>
            <td style="color: $subColor; font-weight: 700;">$($sub.OverallScore)%</td>
            <td>$($sub.RbacScore)%</td>
            <td>$($sub.NetworkScore)%</td>
            <td>$($sub.ExtendedScore)%</td>
        </tr>
"@
    }

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CLZ v2 Security Maturity Report</title>
    <style>
        :root { --bg: #0f172a; --surface: #1e293b; --border: #334155; --text: #e2e8f0; --muted: #94a3b8; }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif; background: var(--bg); color: var(--text); line-height: 1.6; padding: 2rem; }
        .container { max-width: 1400px; margin: 0 auto; }
        h1 { font-size: 1.75rem; margin-bottom: 0.25rem; }
        .subtitle { color: var(--muted); margin-bottom: 2rem; }
        .score-hero { display: flex; align-items: center; gap: 2rem; background: var(--surface); border-radius: 12px; padding: 2rem; margin-bottom: 2rem; border: 1px solid var(--border); }
        .score-ring { position: relative; width: 140px; height: 140px; }
        .score-ring svg { transform: rotate(-90deg); }
        .score-ring .bg { stroke: var(--border); }
        .score-ring .fg { stroke: $scoreColor; stroke-linecap: round; transition: stroke-dashoffset 1s ease; }
        .score-value { position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); font-size: 2.5rem; font-weight: 800; color: $scoreColor; }
        .score-meta h2 { font-size: 1.25rem; margin-bottom: 0.5rem; }
        .maturity-badge { display: inline-block; padding: 4px 14px; border-radius: 6px; font-weight: 700; font-size: 0.9rem; background: ${scoreColor}22; color: $scoreColor; border: 1px solid $scoreColor; }
        .kpi-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 1rem; margin-bottom: 2rem; }
        .kpi { background: var(--surface); border-radius: 10px; padding: 1.25rem; text-align: center; border: 1px solid var(--border); }
        .kpi .num { font-size: 2rem; font-weight: 800; }
        .kpi .label { color: var(--muted); font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.05em; }
        .kpi.critical .num { color: #ef4444; }
        .kpi.high .num { color: #f97316; }
        .kpi.medium .num { color: #f59e0b; }
        .kpi.info .num { color: #3b82f6; }
        table { width: 100%; border-collapse: collapse; background: var(--surface); border-radius: 10px; overflow: hidden; margin-bottom: 2rem; border: 1px solid var(--border); }
        th { background: #0f172a; text-align: left; padding: 12px 16px; font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.05em; color: var(--muted); border-bottom: 1px solid var(--border); }
        td { padding: 12px 16px; border-bottom: 1px solid var(--border); vertical-align: top; font-size: 0.9rem; }
        tr:last-child td { border-bottom: none; }
        tr:hover { background: #ffffff08; }
        .badge { padding: 3px 10px; border-radius: 4px; font-size: 0.75rem; font-weight: 700; text-transform: uppercase; }
        .sev-critical { background: #ef444422; color: #ef4444; border: 1px solid #ef4444; }
        .sev-high { background: #f9731622; color: #f97316; border: 1px solid #f97316; }
        .sev-medium { background: #f59e0b22; color: #f59e0b; border: 1px solid #f59e0b; }
        .sev-info { background: #3b82f622; color: #3b82f6; border: 1px solid #3b82f6; }
        .detail { color: var(--muted); font-size: 0.85rem; }
        .remediation { color: #67e8f9; font-size: 0.85rem; }
        .perspective { font-size: 0.85rem; white-space: nowrap; }
        code { background: #0f172a; padding: 2px 6px; border-radius: 4px; font-size: 0.8rem; }
        .section-title { font-size: 1.2rem; margin: 2rem 0 1rem; padding-bottom: 0.5rem; border-bottom: 1px solid var(--border); }
        .footer { text-align: center; color: var(--muted); font-size: 0.8rem; margin-top: 3rem; padding-top: 1rem; border-top: 1px solid var(--border); }
        .legend { display: flex; gap: 2rem; margin-bottom: 1rem; flex-wrap: wrap; }
        .legend-item { display: flex; align-items: center; gap: 0.5rem; font-size: 0.85rem; color: var(--muted); }
        .expand-hint { display: block; margin-top: 4px; font-size: 0.75rem; color: #818cf8; opacity: 0.8; }
        .finding-row[style*="cursor"] .expand-hint { display: block; }
        .artifact-row td { padding: 0 !important; border-bottom: 1px solid var(--border); }
        .artifact-container { background: #0f172a; padding: 16px 20px; border-left: 3px solid #818cf8; margin: 0; }
        .artifact-header { font-size: 0.85rem; font-weight: 700; color: #818cf8; margin-bottom: 10px; }
        .artifact-table { width: 100%; background: #1e293b; border-radius: 6px; border: 1px solid var(--border); margin: 0; }
        .artifact-table th { background: #334155; font-size: 0.7rem; padding: 8px 12px; color: #e2e8f0; }
        .artifact-table td { font-size: 0.8rem; padding: 6px 12px; color: var(--muted); font-family: 'Cascadia Code', 'Fira Code', monospace; word-break: break-all; }
        .artifact-table tr:hover { background: #ffffff0a; }
        .finding-row[style*="cursor"]:hover { background: #818cf810 !important; }
        .finding-row.expanded { background: #818cf80a; }
        .finding-row.expanded .expand-hint { color: #a5b4fc; }
        .finding-row.expanded .expand-hint::before { content: ''; }

        @media print {
            body { background: #fff; color: #111; }
            .kpi, table, .score-hero { border-color: #ddd; background: #fff; }
            .score-value, .kpi .num { color: inherit !important; }
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>&#x1F6E1; CLZ v2 Security Maturity Report</h1>
        <p class="subtitle">Generated: $ScanTimestamp &nbsp;|&nbsp; Subscriptions scanned: $($SubscriptionResults.Count)</p>

        <div class="score-hero">
            <div class="score-ring">
                <svg width="140" height="140" viewBox="0 0 140 140">
                    <circle class="bg" cx="70" cy="70" r="60" fill="none" stroke-width="12"/>
                    <circle class="fg" cx="70" cy="70" r="60" fill="none" stroke-width="12"
                        stroke-dasharray="$([math]::Round(2 * [math]::PI * 60, 1))"
                        stroke-dashoffset="$([math]::Round((2 * [math]::PI * 60) * (1 - $overallScore/100), 1))"/>
                </svg>
                <div class="score-value">$overallScore</div>
            </div>
            <div class="score-meta">
                <h2>Overall Security Maturity</h2>
                <p>CLZ Phase: <span class="maturity-badge">$maturityLevel</span></p>
                <p style="color: var(--muted); margin-top: 0.5rem; font-size: 0.9rem;">
                    Based on $($allFindings.Count) findings across RBAC, Network, Defender, Key Vault, Storage, Policy, and Identity checks.
                </p>
            </div>
        </div>

        <div class="kpi-grid">
            <div class="kpi critical"><div class="num">$criticalCount</div><div class="label">Critical</div></div>
            <div class="kpi high"><div class="num">$highCount</div><div class="label">High</div></div>
            <div class="kpi medium"><div class="num">$mediumCount</div><div class="label">Medium</div></div>
            <div class="kpi info"><div class="num">$infoCount</div><div class="label">Informational</div></div>
        </div>

        <h3 class="section-title">&#x1F4CA; Subscription Breakdown</h3>
        <table>
            <thead><tr>
                <th>Subscription</th><th>ID</th><th>Environment</th>
                <th>Overall</th><th>RBAC</th><th>Network</th><th>Extended</th>
            </tr></thead>
            <tbody>$subSummaryHtml</tbody>
        </table>

        <h3 class="section-title">&#x1F50D; Detailed Findings</h3>
        <div class="legend">
            <div class="legend-item">&#x1F3AD; Hacker Perspective — exploitability &amp; attack surface</div>
            <div class="legend-item">&#x1F3E2; CISO Perspective — governance, compliance &amp; risk management</div>
        </div>
        <table>
            <thead><tr>
                <th>Severity</th><th>Category</th><th>Finding</th><th>Remediation</th><th>Perspective</th>
            </tr></thead>
            <tbody>$findingsHtml</tbody>
        </table>

        <div class="footer">
            CLZ v2 Security Maturity Scanner &nbsp;|&nbsp; github.com/mcancillo/aks-security-policies &nbsp;|&nbsp; $ScanTimestamp
        </div>
    </div>
    <script>
        document.querySelectorAll('.finding-row').forEach(row => {
            row.addEventListener('dblclick', () => {
                const rowId = row.dataset.row;
                const artifactRow = document.querySelector('.artifact-row[data-row="' + rowId + '"]');
                if (!artifactRow) return;

                const isVisible = artifactRow.style.display !== 'none';
                artifactRow.style.display = isVisible ? 'none' : 'table-row';
                row.classList.toggle('expanded', !isVisible);

                // Update hint text
                const hint = row.querySelector('.expand-hint');
                if (hint) {
                    hint.innerHTML = isVisible
                        ? hint.innerHTML.replace('&#x25BC;', '&#x25B6;').replace('▼', '▶')
                        : hint.innerHTML.replace('&#x25B6;', '&#x25BC;').replace('▶', '▼');
                }
            });
        });
    </script>
</body>
</html>
"@

    $html | Out-File -FilePath $OutputPath -Encoding utf8
    Write-Host "`n  Report written to: $OutputPath" -ForegroundColor Green
    return $OutputPath
}

Export-ModuleMember -Function New-SecurityReport
