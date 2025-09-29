---
title: "Detection for CVE-2025-8875 & CVE-2025-8876"
datePublished: Tue Aug 26 2025 18:40:21 GMT+0000 (Coordinated Universal Time)
cuid: cmesw5jfx000c02l4a8tj8dce
slug: detection-for-cve-2025-8875-and-cve-2025-8876
cover: https://cdn.hashnode.com/res/hashnode/image/upload/v1756235193612/757ba586-d327-4497-9d03-4b358e18faac.png
tags: vulnerability, cybersecurity-1, nuclei, detection, zerodayvulnerability

---

Over the past few weeks, two critical vulnerabilities - CVE-2025-8875 and CVE-2025-8876 have surfaced as active threats in the wild. Both have been flagged by CISA as being widely exploited, and organisations relying on N-able N-central are particularly at risk.

## **What Are These Vulnerabilities?**

* **CVE-2025-8875**
    
    A critical flaw in N-able N-central that stems from improper handling of untrusted data. It allows remote attackers to exploit deserialization weaknesses and potentially execute arbitrary code on the affected system.
    
* **CVE-2025-8876**
    
    Closely related, this vulnerability involves a Deserialization of Untrusted Data issue in N-central, which leads to local execution of code. Versions of N-central before 2025.3.1 are impacted. If left unpatched, attackers can leverage this flaw to gain control of systems running vulnerable deployments.
    

Both vulnerabilities present high-impact attack vectors — exploitation could mean full system compromise, lateral movement within a network, and unauthorised access to sensitive data.

## **Exploitation in the Wild**

CISA has confirmed that these vulnerabilities are being actively weaponised. Threat actors are rapidly incorporating them into their attack chains, highlighting the urgency for defenders to detect and mitigate affected instances.

## **My Nuclei Detection Script**

To support the security community, I created a Nuclei detection template that helps identify vulnerable N-central installations. The script checks for the exposed login endpoint, validates the presence of N-central, extracts the version number, and compares it against the patched version (2025.3.1.9).

Here’s what the script does step by step:

1. **Sends a GET request** to the N-central login page.
    
2. **Matches page indicators** confirming the application is N-central.
    
3. **Extracts the software version** via regex from the HTML response.
    
4. **Compares the version number** with the safe baseline (2025.3.1.9).
    
5. Flags the host if it’s vulnerable.
    

```yaml
id: CVE-2025-8875/6

info:
  name: CVE-2025-8875/6
  author: rxerium
  severity: critical
  description: |
    Deserialization of Untrusted Data vulnerability in N-able N-central allows Local Execution of Code. This issue affects N-central: before 2025.3.1.
  metadata:
    verified: true
    max-request: 1
    shodan-query:
      - http.title:"N-central Login"
  tags: n-able,ncentral,kev

http:
  - method: GET
    path:
      - "{{BaseURL}}/login"

    extractors:
      - type: regex
        name: version
        regex:
          - '202\d+\.\d+\.\d+\.\d+\b'
        part: body

    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200

      - type: word
        words:
          - 'class="ncentral"'

      - type: dsl
        dsl:
          - compare_versions(version, '< 2025.3.1.9')
```

A link to my detection script can be found on GitHub [here](https://github.com/rxerium/CVE-2025-8875-CVE-2025-8876/tree/main).

## **Community Recognition**

The script was well received and shared within the community. After posting it on Twitter (X), it reached over 20,000 impressions — a sign of how important and urgent actionable detection methods for these vulnerabilities are, my original post on this can be found [here](https://x.com/rxerium/status/1957147780440264823).

Following this, I sent [another post](https://x.com/rxerium/status/1958443266895925318) on the 21st of August 2025 stating how many IP addresses were still vulnerable to these CVEs, reminding IT and security admins to patch their systems:

[![](https://cdn.hashnode.com/res/hashnode/image/upload/v1756233357785/903da530-568e-426c-ae6b-01cda20f8588.jpeg align="center")](https://x.com/rxerium/status/1958443266895925318)

## **Closing Thoughts**

With CVE-2025-8875 and CVE-2025-8876 actively exploited in the wild, defenders must move fast. Whether you’re a security researcher, a SOC analyst, or a sysadmin, deploying detection mechanisms like this can buy valuable time until patches are fully rolled out.

I’ll continue to publish more Nuclei templates and detection scripts to help the community stay ahead of threats.