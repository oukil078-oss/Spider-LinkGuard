import { DetectionRules, ScanReport } from '../types/scanner.ts';

/**
 * Generates SIEM / IDS rules for detected malicious / suspicious URLs
 */
export function generateDetectionRules(
  hostname: string,
  pathname: string,
  canonicalUrl: string,
  verdict: string
): DetectionRules {
  const cleanHost = hostname.replace(/[^\w.-]/g, '');
  const ruleId = `spider_${Math.floor(100000 + Math.random() * 900000)}`;
  const dateStr = new Date().toISOString().split('T')[0];

  // Sigma Rule (YAML)
  const sigma = `title: Detect Suspicious Connection to ${cleanHost}
id: ${ruleId}-sigma
status: experimental
description: Auto-generated detection rule by Spider-LinkGuard for malicious/suspicious destination ${cleanHost}
references:
    - https://spider-linkguard.local/reports/${ruleId}
author: Spider-LinkGuard Autonomous Sandbox
date: ${dateStr}
tags:
    - attack.initial_access
    - attack.t1566.002
    - attack.command_and_control
    - attack.t1071.001
logsource:
    category: proxy
    product: any
detection:
    selection_host:
        c-uri-host: '${cleanHost}'
    selection_url:
        c-uri-path|contains: '${pathname.length > 1 ? pathname : cleanHost}'
    condition: selection_host or selection_url
fields:
    - ClientIP
    - c-uri-host
    - c-uri-path
    - cs-method
    - sc-status
falsepositives:
    - Legitimate traffic if domain is reassigned or sinkholed
level: ${verdict === 'CRITICAL' || verdict === 'MALICIOUS' ? 'high' : 'medium'}
`;

  // Suricata Rule
  const sid = Math.floor(2800000 + Math.random() * 99999);
  const suricata = `alert dns $HOME_NET any -> any 53 (msg:"SPIDER-LINKGUARD DNS Query to Suspicious Host ${cleanHost}"; dns.query; content:"${cleanHost}"; nocase; classtype:trojan-activity; sid:${sid}; rev:1; metadata:created_at ${dateStr};)
alert tls $HOME_NET any -> any 443 (msg:"SPIDER-LINKGUARD TLS SNI to Suspicious Host ${cleanHost}"; tls.sni; content:"${cleanHost}"; nocase; classtype:trojan-activity; sid:${sid + 1}; rev:1; metadata:created_at ${dateStr};)
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"SPIDER-LINKGUARD HTTP Host Request ${cleanHost}"; http.host; content:"${cleanHost}"; nocase; classtype:trojan-activity; sid:${sid + 2}; rev:1; metadata:created_at ${dateStr};)`;

  // Snort Rule
  const snort = `alert tcp $HOME_NET any -> $EXTERNAL_NET [80,443] (msg:"SPIDER-LINKGUARD Outbound Connection to ${cleanHost}"; flow:to_server,established; content:"${cleanHost}"; http_header; classtype:bad-unknown; sid:${sid + 3}; rev:1;)`;

  // YARA-L (Chronicle SIEM)
  const yaraL = `rule spider_linkguard_${cleanHost.replace(/[^a-zA-Z0-9_]/g, '_')} {
  meta:
    author = "Spider-LinkGuard"
    description = "Matches proxy or DNS events to suspicious indicator ${cleanHost}"
    severity = "${verdict}"
    date = "${dateStr}"

  events:
    $e.target.hostname = /.*${cleanHost.replace(/\./g, '\\.')}/ or
    $e.network.dns.questions.name = /.*${cleanHost.replace(/\./g, '\\.')}/

  condition:
    $e
}`;

  return {
    sigma,
    suricata,
    snort,
    yaraL,
  };
}

/**
 * Generates complete executive Markdown scan dossier
 */
export function generateMarkdownReport(report: ScanReport): string {
  const norm = report.normalization;
  const intel = report.threatIntel;
  const score = report.scoring;

  return `# SPIDER-LINKGUARD DETONATION DOSSIER
**Incident Reference:** \`${report.id}\`  
**Timestamp:** \`${report.timestamp}\`  
**Overall Threat Score:** **${score.overallScore}/100** — \`${score.verdict}\`  
**Verdict Rationale:** ${score.verdictReason}

---

## 1. TARGET SUMMARY
| Property | Value |
| :--- | :--- |
| **Submitted URL** | \`${report.inputUrl}\` |
| **Canonical URL** | \`${norm.canonicalUrl}\` |
| **Defanged URL** | \`${norm.defangedUrl}\` |
| **Host / IP** | \`${norm.hostname}\` (${norm.isIp ? 'Raw IP' : 'Domain Name'}) |
| **Top-Level Domain** | \`.${norm.tld}\` (${norm.isSuspiciousTld ? '⚠ Suspicious/High-Abuse' : 'Standard'}) |
| **Protocol / Port** | \`${norm.scheme}://${norm.port}\` |

---

## 2. RISK FACTOR BREAKDOWN
${score.breakdown
  .map(
    (b) =>
      `- **[+${b.score} pts / ${b.weight} max]** \`${b.category}\` (${b.severity.toUpperCase()}): ${b.description}`
  )
  .join('\n')}

---

## 3. HEURISTICS & CRYPTOGRAPHIC ENTROPY
- **Path Shannon Entropy:** \`${report.entropy.pathEntropy}\`
- **Query Parameter Entropy:** \`${report.entropy.queryEntropy}\`
- **Full URL Entropy:** \`${report.entropy.fullUrlEntropy}\`
- **Homoglyph / Punycode Analysis:**
  - Has Lookalike Characters: \`${report.homoglyphs.hasHomoglyphs ? 'YES' : 'NO'}\`
  - Spoofed Brand: \`${report.homoglyphs.spoofedBrand || 'None'}\`
  - Explanation: ${report.homoglyphs.explanation}

---

## 4. MULTI-ENGINE THREAT REPUTATION
- **VirusTotal AV Ratio:** \`${intel.virusTotal.positives} / ${intel.virusTotal.total}\`
- **URLhaus (Abuse.ch):** \`${intel.urlhaus.detected ? 'DETECTED (' + intel.urlhaus.threat + ')' : 'CLEAN'}\`
- **urlscan.io:** \`${intel.urlscan.malicious ? 'MALICIOUS' : 'CLEAN / UNLISTED'}\` (Country: \`${intel.urlscan.country || 'N/A'}\`, ASN: \`${intel.urlscan.asn || 'N/A'}\`)
- **Google Safe Browsing:** \`${intel.googleSafeBrowsing.detected ? intel.googleSafeBrowsing.threatTypes.join(', ') : 'CLEAR'}\`

---

## 5. REDIRECT CHAIN TRAVERSAL (${report.redirectChain.totalHops} HOPS)
${report.redirectChain.hops
  .map(
    (hop) =>
      `1. **Hop #${hop.hopIndex}** — Status: \`${hop.statusCode} ${hop.statusText}\` (${hop.latencyMs}ms)  
   URL: \`${hop.url}\`  
   Content-Type: \`${hop.contentType}\`  
   ${hop.cookiesSet.length > 0 ? 'Cookies: `' + hop.cookiesSet.join(', ') + '`' : ''}`
  )
  .join('\n')}

${
  report.redirectChain.evasionDetected
    ? `> ⚠ **Evasion Warning:** ${report.redirectChain.evasionReasons.join('; ')}`
    : ''
}

---

## 6. DOM SANDBOX FINDINGS
- **Page Title:** \`${report.domSandbox.title}\`
- **Credential Harvester Detected:** \`${report.domSandbox.hasCredentialHarvester ? 'YES ⚠' : 'NO'}\`
- **Interactive Forms:** ${report.domSandbox.forms.length} forms extracted
- **External Scripts:** ${report.domSandbox.scripts.length} third-party scripts loaded

---

## 7. READY-TO-DEPLOY SIEM DETECTION (SIGMA)
\`\`\`yaml
${report.rules.sigma}
\`\`\`

## 8. SURICATA IDS RULES
\`\`\`suricata
${report.rules.suricata}
\`\`\`

---
*Spider-LinkGuard SecOps Automated Sandbox • Companion microservice to Zak's Spider Workstation*
`;
}
