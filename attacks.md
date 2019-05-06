# Attacks

> Attacks are the techniques that attackers use to exploit the vulnerabilities in applications. Attacks are often confused with vulnerabilities, so please try to be sure that the attack you are describing is something that an attacker would do, rather than a weakness in an application.

**https://www.owasp.org/index.php/Category:Attack**

## Examples

- [Abuse of Functionality](#abuse-of-functionality)
- [Automated Threat](#automated-threat)
- [Data Structure Attacks](#data-structure-attacks)
- [Embedded Maliicious Code](#embedded-malicious-code)
- [Exploitation of Authentication](#exploitation-of-authentication)
- [Injection](#injection)
- [Path Traversal Attack](#path-traversal-attack)
- [Probabilistic Techniques](#probabilistic-techniques)
- [Protocol Manipulation](#protocol-manipulation)
- [Resource Depletion](#resource-depletion)
- [Resource Manipulation](#resource-manipulation)
- [Sniffing Attacks](#sniffing-attacks)
- [Spoofing Attacks](#spoofing-attacks)

---

### Abuse of Functionality

- [Cache Poisoning](https://www.owasp.org/index.php/Cache_Poisoning)
- [Cross-User Defacement](https://www.owasp.org/index.php/Cross-User_Defacement)
- [Mobile Code: invoking untrusted mobile code](https://www.owasp.org/index.php/Mobile_code:_invoking_untrusted_mobile_code)
- [Mobile Code: non-final public field](https://www.owasp.org/index.php/Mobile_code:_non-final_public_field)
- [Mobile Code: object hijack](https://www.owasp.org/index.php/Mobile_code:_object_hijack)
- [Path Traversal](https://www.owasp.org/index.php/Path_Traversal)
- [Server Side Request Forgery](https://www.owasp.org/index.php/Server_Side_Request_Forgery)

### Automated Threat

> Threat events (an instance of something causing harm) to applications undertaken using automated actions. The focus is on abuse of functionality - misuse of inherent functionality and related design flaws, some of which are also referred to as business logic flaws. There is almost no focus on implementation bugs.

> In the specific case of web applications, threat events to web applications undertaken using automated actions. And for this web application case, attacks that can be achieved without the web are not in scope.

- [OAT-001 Carding](https://www.owasp.org/index.php/OAT-001_Carding)
- [OAT-002 Token Cracking](https://www.owasp.org/index.php/OAT-002_Token_Cracking)
- [OAT-003 Ad Fraud](https://www.owasp.org/index.php/OAT-003_Ad_Fraud)
- [OAT-004 Fingerprinting](https://www.owasp.org/index.php/OAT-004_Fingerprinting)
- [OAT-005 Scalping](https://www.owasp.org/index.php/OAT-005_Scalping)
- [OAT-006 Expediting](https://www.owasp.org/index.php/OAT-006_Expediting)
- [OAT-007 Credential Cracking](https://www.owasp.org/index.php/OAT-007_Credential_Cracking)
- [OAT-008 Credential Stuffing](https://www.owasp.org/index.php/OAT-008_Credential_Stuffing)
- [OAT-009 CAPTCHA Defeat](https://www.owasp.org/index.php/OAT-009_CAPTCHA_Defeat)
- [OAT-010 Card Cracking](https://www.owasp.org/index.php/OAT-010_Card_Cracking)
- [OAT-011 Scraping](https://www.owasp.org/index.php/OAT-011_Scraping)
- [OAT-012 Cashing Out](https://www.owasp.org/index.php/OAT-012_Cashing_Out)
- [OAT-013 Sniping](https://www.owasp.org/index.php/OAT-013_Sniping)
- [OAT-014 Vulnerability Scanning](https://www.owasp.org/index.php/OAT-014_Vulnerability_Scanning)
- [OAT-015 Denial of Service](https://www.owasp.org/index.php/OAT-015_Denial_of_Service)
- [OAT-016 Skewing](https://www.owasp.org/index.php/OAT-016_Skewing)
- [OAT-017 Spamming](https://www.owasp.org/index.php/OAT-017_Spamming)
- [OAT-018 Footprinting](https://www.owasp.org/index.php/OAT-018_Footprinting)
- [OAT-019 Account Creation](https://www.owasp.org/index.php/OAT-019_Account_Creation)
- [OAT-020 Account Aggregation](https://www.owasp.org/index.php/OAT-020_Account_Aggregation)
- [OAT-021 Denial of Inventory](https://www.owasp.org/index.php/OAT-021_Denial_of_Inventory)


### Data Structure Attacks

- [Buffer Overflow Attack](https://www.owasp.org/index.php/Buffer_overflow_attack)
- [Buffer Overflow via Environment Variables](https://www.owasp.org/index.php/Buffer_Overflow_via_Environment_Variables)


### Embedded Maliicious Code

- [Cross-Site Request Forgery (CSRF)](https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF))
- [Logic / Time Bomb](https://www.owasp.org/index.php/Logic/time_bomb)
- [Trojan Horse](https://www.owasp.org/index.php/Trojan_Horse)


### Exploitation of Authentication

- [Cross-Site Request Forgery (CSRF)](https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF))
- [CSRF](https://www.owasp.org/index.php/CSRF)
- [Execution After Redirect (AER)](https://www.owasp.org/index.php/Execution_After_Redirect_(EAR))
- [One-Click Attack](https://www.owasp.org/index.php/One-Click_Attack)
- [Session Fixation](https://www.owasp.org/index.php/Session_fixation)
- [Session Hijacking Attack](https://www.owasp.org/index.php/Session_hijacking_attack)
- [Session Prediction](https://www.owasp.org/index.php/Session_Prediction)
- [XSRF](https://www.owasp.org/index.php/XSRF)


### Injection

- [Blind SQL Injection](https://www.owasp.org/index.php/Blind_SQL_Injection)
- [Blind XPath Injection](https://www.owasp.org/index.php/Blind_XPath_Injection)
- [Code Injection](https://www.owasp.org/index.php/Code_Injection)
- [Command Injection](https://www.owasp.org/index.php/Command_Injection)
- [Comment Injection Attack](https://www.owasp.org/index.php/Comment_Injection_Attack)
- [Content Security Policy](https://www.owasp.org/index.php/Content_Security_Policy)
- [Content Spoofing](https://www.owasp.org/index.php/Content_Spoofing)
- [CORS Request Preflight Scrutiny](https://www.owasp.org/index.php/CORS_RequestPreflighScrutiny)
- [Cross-Site Scripting (XSS)](https://www.owasp.org/index.php/Cross-site_Scripting_(XSS))
- [Custom Special Character Injection](https://www.owasp.org/index.php/Custom_Special_Character_Injection)
- [Direct Dynamic Code Evaluation ('Eval Injection')](https://www.owasp.org/index.php/Direct_Dynamic_Code_Evaluation_(%27Eval_Injection%27))
- [Format String Attack](https://www.owasp.org/index.php/Format_string_attack)
- [Full Path Disclosure](https://www.owasp.org/index.php/Full_Path_Disclosure)
- [Function Injection](https://www.owasp.org/index.php/Function_Injection)
- [Parameter Delimeter](https://www.owasp.org/index.php/Parameter_Delimiter)
- [PHP Object Injection](https://www.owasp.org/index.php/PHP_Object_Injection)
- [Regular Expression Denial of Service (ReDoS)](https://www.owasp.org/index.php/Regular_expression_Denial_of_Service_-_ReDoS)
- [Resource Injection](https://www.owasp.org/index.php/Resource_Injection)
- [Server Side Includes (SSI) Injection](https://www.owasp.org/index.php/Server-Side_Includes_(SSI)_Injection)
- [Special Element Injection](https://www.owasp.org/index.php/Special_Element_Injection)
- [SQL Injection](https://www.owasp.org/index.php/SQL_Injection)
- [SQL Injection Bypassing WAF](https://www.owasp.org/index.php/SQL_Injection_Bypassing_WAF)
- [Web Parameter Tampering](https://www.owasp.org/index.php/Web_Parameter_Tampering)
- [XPATH Injection](https://www.owasp.org/index.php/XPATH_Injection)
- [XSS in Subtitle](https://www.owasp.org/index.php/Xss_in_subtitle)


### Path Traversal Attack

> This category of attacks exploit various path vulnerabilities to access files or directories that are not intended to be accessed. This attack works on applications that take user input and use it in a "path" that is used to access a filesystem

> If the attacker includes special characters that modify the meaning of the path, the application will misbehave and may allow the attacker to access unauthorized resources. This type of attack has been successful on web servers, application servers, and custom code.

> E.g. http://foo.com/../../barfile

- [Path Traversal](https://www.owasp.org/index.php/Path_Traversal)


### Probabilistic Techniques

- [Brute Force Attack](https://www.owasp.org/index.php/Brute_force_attack)
- [Cash Overflow](https://www.owasp.org/index.php/Cash_Overflow)
- [Cryptanalysis](https://www.owasp.org/index.php/Cryptanalysis)
- [Denial of Service](https://www.owasp.org/index.php/Denial_of_Service)


### Protocol Manipulation

- [Traffic Flood](https://www.owasp.org/index.php/Traffic_flood)


### Resource Depletion

- [Cash Overflow](https://www.owasp.org/index.php/Cash_Overflow)
- [Denial of Service](https://www.owasp.org/index.php/Denial_of_Service)


### Resource Manipulation

- [Comment Injection Attack](https://www.owasp.org/index.php/Comment_Injection_Attack)
- [Custom Special Character Injection](https://www.owasp.org/index.php/Custom_Special_Character_Injection)
- [Double Encoding](https://www.owasp.org/index.php/Double_Encoding)
- [Forced Browsing](https://www.owasp.org/index.php/Forced_browsing)
- [Path Traversal](https://www.owasp.org/index.php/Path_Traversal)
- [Relative Path Traversal](https://www.owasp.org/index.php/Relative_Path_Traversal)
- [Repudiation Attack](https://www.owasp.org/index.php/Repudiation_Attack)
- [Setting Manipulation](https://www.owasp.org/index.php/Setting_Manipulation)
- [Spyware](https://www.owasp.org/index.php/Spyware)
- [Unicode Encoding](https://www.owasp.org/index.php/Unicode_Encoding)


### Sniffing Attacks



### Spoofing Attacks

- [Cash Overflow](https://www.owasp.org/index.php/Cash_Overflow)
- [Cross Site Request Forgery (CSRF)](https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF))
- [Denial of Service](https://www.owasp.org/index.php/Denial_of_Service)
- [Man-In-The-Middle Attack](https://www.owasp.org/index.php/Man-in-the-middle_attack)
- [Server Side Request Forgery](https://www.owasp.org/index.php/Server_Side_Request_Forgery)

