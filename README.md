<img width="721" height="742" alt="Mail7" src="https://github.com/user-attachments/assets/0503ac13-f3e7-4753-82b4-a76d60f36193" />

SOC Incident Ticket: Microsoft Impersonation & Header Forgery

**Ticket ID:** INC-PHISH-004
**Date:** 20.9.2026
**Analyst:** Selma Oguz

SECTION 1: Incident Summary

**Header Analysis Link:** [MXToolBox Analysis](https://mxtoolbox.com/Public/Tools/EmailHeaders.aspx?huid=ff01d645-1f3c-4851-8e36-3ec35513db90)

On September 8, 2023, a phishing email impersonating the Microsoft Account Security Team was detected. The email employs scareware tactics, falsely alerting the user (`phishing@pot`) of an unauthorized login from "Russia/Moscow" to create a false sense of urgency and force interaction with a malicious payload.

**Analyst Observations & Red Flags:**
* **Severe Header Mismatch (Forgery):** The attacker completely failed to align the email headers. The `From` address (`access-accsecurity.com`), the `Reply-To` address (`sotrecognizd@gmail.com`), and the `Return-Path` (`thcultarfdes.co.uk`) all utilize completely different, unrelated domains. 
* **Infrastructure Analysis:** The sending IP (`89.144.44.2`) resolves to `r2.mscode.pl`. This IP is owned by MSCode / Ghostnet, a Polish VPS provider. It has zero association with Microsoft's official mail servers, revealing the true infrastructure used by the threat actor.
* **Typographical Errors:** The email body contains obvious grammatical anomalies, such as "Unusual sign.in activity" (using a dot instead of a hyphen), which is uncharacteristic of legitimate corporate communications.
* **Malicious Payload:** The embedded call-to-action ("Report The User") redirects to `thebandalisty[.]com`, a domain flagged by multiple security vendors as malicious.

**Impact Assessment:** 
No user interaction or compromise occurred. The incident is a True Positive but effectively a Non-Issue.

A) Email Artifacts (Observables)

* **Sender Name:** `Microsoft account team`
* **Sending Address:** `no-reply[@]access-accsecurity[.]com`
* **Subject Line:** `Microsoft account unusual signin activity`
* **Recipients:** `phishing@pot`
* **Sending Server IP:** `89[.]144[.]44[.]2` (Polish VPS Provider)
* **Reply-To:** `sotrecognizd[@]gmail[.]com`
* **Return Path:** `bounce[@]thcultarfdes[.]co[.]uk`
* **Date and Time:** Fri, 8 Sep 2023 05:47:04 +0000

B) Web Artifacts (Observables)

* **Full URL Links (Defang-sanitized):** 
  * `hxxp[://]thebandalisty[.]com/track/o43062rdzGz18708448Gdrw1821750fYo33632dSjh176`
* **Root Domains (Defanged):** 
  * `access-accsecurity[.]com` (Sender Domain)
  * `thcultarfdes[.]co[.]uk` (Return-Path Domain)
  * `thebandalisty[.]com` (Payload Domain)

C) File (Attachment) Artifacts

* **File Name:** N/A
* **File Hash (SHA256):** N/A


SECTION 2: Artifact Analysis

* **VirusTotal Validation:** 10/92 security vendors flagged the payload domain (`thebandalisty.com`) as malicious.
* **Infrastructure Reputation:** The originating IP (`89.144.44.2`) has a history of bad activities, including DDoS and port scanning reports, confirming it is part of a compromised or malicious hosting environment.
* **DNS Resolution:** Both the sender domain (`access-accsecurity.com`) and return-path domain (`thcultarfdes.co.uk`) lack proper DNS records, further solidifying their illegitimate nature.


SECTION 3: Suggested Defensive Measures


* **Declaration:** **True Positive – No Impact (Non-Issue)**

* **Block the Domains:** 
  * `access-accsecurity[.]com`
  * `thcultarfdes[.]co[.]uk`
  * `thebandalisty[.]com`
* **Block the Reply-To Address:** `sotrecognizd[@]gmail[.]com`
* **Block The IP:** `89[.]144[.]44[.]2` *(Recommended: Temporary block for 24-48 hours due to active malicious traffic and port scanning history).*

***
**Disclaimer:** *This ticket is based on a real-world phishing sample analyzed within a controlled lab environment for educational and portfolio demonstration purposes.*
