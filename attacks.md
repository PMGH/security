# Attacks

Attacks are the techniques that attackers use to exploit the vulnerabilities in applications. Attacks are often confused with vulnerabilities, so please try to be sure that the attack you are describing is something that an attacker would do, rather than a weakness in an application.

**https://www.owasp.org/index.php/Category:Attack**

---

<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->
**Contents**

- [Abuse of Functionality](#abuse-of-functionality)
- [Automated Threat](#automated-threat)
- [Data Structure Attacks](#data-structure-attacks)
- [Embedded Malicious Code](#embedded-malicious-code)
- [Exploitation of Authentication](#exploitation-of-authentication)
- [Injection](#injection)
- [Path Traversal Attack](#path-traversal-attack)
- [Probabilistic Techniques](#probabilistic-techniques)
- [Protocol Manipulation](#protocol-manipulation)
- [Resource Depletion](#resource-depletion)
- [Resource Manipulation](#resource-manipulation)
- [Sniffing Attacks](#sniffing-attacks)
- [Spoofing Attacks](#spoofing-attacks)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

---

### Abuse of Functionality

- [Cache Poisoning](https://www.owasp.org/index.php/Cache_Poisoning "The impact of a maliciously constructed response can be magnified if it is cached either by a web cache used by multiple users or even the browser cache of a single user.")
- [Cross-User Defacement](https://www.owasp.org/index.php/Cross-User_Defacement "An attacker can make a single request to a vulnerable server that will cause the sever to create two responses, the second of which may be misinterpreted as a response to a different request, possibly one made by another user sharing the same TCP connection with the sever.")
- [Mobile Code: invoking untrusted mobile code](https://www.owasp.org/index.php/Mobile_code:_invoking_untrusted_mobile_code "Manipulation of a mobile code in order to execute malicious operations at the client side.")
- [Mobile Code: non-final public field](https://www.owasp.org/index.php/Mobile_code:_non-final_public_field "This attack aims to manipulate non-final public variables used in mobile code, by injecting malicious values on it, mostly in Java and C++ applications.")
- [Mobile Code: object hijack](https://www.owasp.org/index.php/Mobile_code:_object_hijack "This attack consists of a technique to create objects without constructors’ methods by taking advantage of the clone() method of Java-based applications.")
- [Path Traversal](https://www.owasp.org/index.php/Path_Traversal "A path traversal attack (also known as directory traversal) aims to access files and directories that are stored outside the web root folder.")
- [Server Side Request Forgery](https://www.owasp.org/index.php/Server_Side_Request_Forgery "Abuse of functionality on the server to read or update internal resources. The attacker can supply or a modify a URL which the code running on the server will read or submit data to.")


### Automated Threat

> Threat events (an instance of something causing harm) to applications undertaken using automated actions. The focus is on abuse of functionality - misuse of inherent functionality and related design flaws, some of which are also referred to as business logic flaws. There is almost no focus on implementation bugs.

> In the specific case of web applications, threat events to web applications undertaken using automated actions. And for this web application case, attacks that can be achieved without the web are not in scope.

- [OAT-001 Carding](https://www.owasp.org/index.php/OAT-001_Carding "Multiple payment authorisation attempts used to verify the validity of bulk stolen payment card data.")
- [OAT-002 Token Cracking](https://www.owasp.org/index.php/OAT-002_Token_Cracking "Mass enumeration of coupon numbers, voucher codes, discount tokens, etc.")
- [OAT-003 Ad Fraud](https://www.owasp.org/index.php/OAT-003_Ad_Fraud "False clicks and fraudulent display of web-placed advertisements.")
- [OAT-004 Fingerprinting](https://www.owasp.org/index.php/OAT-004_Fingerprinting "Elicit information about the supporting so ware and framework types and versions.")
- [OAT-005 Scalping](https://www.owasp.org/index.php/OAT-005_Scalping "Obtain limited-availability and/or preferred goods/services by unfair methods.")
- [OAT-006 Expediting](https://www.owasp.org/index.php/OAT-006_Expediting "Perform actions to hasten progress of usually slow, tedious or time-consuming actions.")
- [OAT-007 Credential Cracking](https://www.owasp.org/index.php/OAT-007_Credential_Cracking "Identify valid login credentials by trying different values for usernames and/or passwords.")
- [OAT-008 Credential Stuffing](https://www.owasp.org/index.php/OAT-008_Credential_Stuffing "Mass log in attempts used to verify the validity of stolen username/password pairs.")
- [OAT-009 CAPTCHA Defeat](https://www.owasp.org/index.php/OAT-009_CAPTCHA_Defeat "Solve anti-automation tests.")
- [OAT-010 Card Cracking](https://www.owasp.org/index.php/OAT-010_Card_Cracking "Identify missing start/expiry dates and security codes for stolen payment card data by trying different values.")
- [OAT-011 Scraping](https://www.owasp.org/index.php/OAT-011_Scraping "Collect application content and/or other data for use elsewhere.")
- [OAT-012 Cashing Out](https://www.owasp.org/index.php/OAT-012_Cashing_Out "Buy goods or obtain cash utilising validated stolen payment card or other user account data.")
- [OAT-013 Sniping](https://www.owasp.org/index.php/OAT-013_Sniping "Last minute bid or offer for goods or services.")
- [OAT-014 Vulnerability Scanning](https://www.owasp.org/index.php/OAT-014_Vulnerability_Scanning "Crawl and fuzz application to identify weaknesses and possible vulnerabilities.")
- [OAT-015 Denial of Service](https://www.owasp.org/index.php/OAT-015_Denial_of_Service "Target resources of the application and database servers, or individual user accounts, to achieve denial of service (DoS).")
- [OAT-016 Skewing](https://www.owasp.org/index.php/OAT-016_Skewing "Repeated link clicks, page requests or form submissions intended to alter some metric.")
- [OAT-017 Spamming](https://www.owasp.org/index.php/OAT-017_Spamming "Malicious or questionable information addition that appears in public or private content, databases or user messages.")
- [OAT-018 Footprinting](https://www.owasp.org/index.php/OAT-018_Footprinting "Probe and explore application to identify its constituents and properties.")
- [OAT-019 Account Creation](https://www.owasp.org/index.php/OAT-019_Account_Creation "Create multiple accounts for subsequent misuse.")
- [OAT-020 Account Aggregation](https://www.owasp.org/index.php/OAT-020_Account_Aggregation "Use by an intermediary application that collects together multiple accounts and interacts on their behalf.")
- [OAT-021 Denial of Inventory](https://www.owasp.org/index.php/OAT-021_Denial_of_Inventory "Deplete goods or services stock without ever completing the purchase or committing to the transaction.")


### Data Structure Attacks

- [Buffer Overflow Attack](https://www.owasp.org/index.php/Buffer_overflow_attack "Buffer overflows can consist of overflowing the stack (Stack overflow) or overflowing the heap (Heap overflow).")
- [Buffer Overflow via Environment Variables](https://www.owasp.org/index.php/Buffer_Overflow_via_Environment_Variables "This attack pattern involves causing a buffer overflow through manipulation of environment variables.")


### Embedded Malicious Code

- [Cross-Site Request Forgery (CSRF)](https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF) "Cross-Site Request Forgery (CSRF) is an attack that forces an end user to execute unwanted actions on a web application in which they're currently authenticated.")
- [Logic / Time Bomb](https://www.owasp.org/index.php/Logic/time_bomb "A logic bomb is a piece of malicious code that executes when specific trigger conditions are met.")
- [Trojan Horse](https://www.owasp.org/index.php/Trojan_Horse "A Trojan Horse is a program that uses malicious code masqueraded as a trusted application.")


### Exploitation of Authentication

- [Cross-Site Request Forgery (CSRF)](https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF) "Cross-Site Request Forgery (CSRF) is an attack that forces an end user to execute unwanted actions on a web application in which they're currently authenticated.")
- [CSRF](https://www.owasp.org/index.php/CSRF "Cross-Site Request Forgery (CSRF) is an attack that forces an end user to execute unwanted actions on a web application in which they're currently authenticated.")
- [Execution After Redirect (AER)](https://www.owasp.org/index.php/Execution_After_Redirect_(EAR) "Execution After Redirect (EAR) is an attack where an attacker ignores redirects and retrieves sensitive content intended for authenticated users.")
- [One-Click Attack](https://www.owasp.org/index.php/One-Click_Attack "Cross-Site Request Forgery (CSRF)")
- [Session Fixation](https://www.owasp.org/index.php/Session_fixation "Session Fixation is an attack that permits an attacker to hijack a valid user session. When authenticating a user, the vulnerable app doesn’t assign a new session ID, making it possible to use an existent session ID.")
- [Session Hijacking Attack](https://www.owasp.org/index.php/Session_hijacking_attack "The Session Hijacking attack consists of the exploitation of the web session control mechanism, which is normally managed for a session token. The Session Hijacking attack compromises the session token by stealing or predicting a valid session token to gain unauthorized access to the Web Server.")
- [Session Prediction](https://www.owasp.org/index.php/Session_Prediction "The session prediction attack focuses on predicting session ID values that permit an attacker to bypass the authentication schema of an application. By analyzing and understanding the session ID generation process, an attacker can predict a valid session ID value and get access to the application.")
- [XSRF](https://www.owasp.org/index.php/XSRF "Cross-Site Request Forgery (CSRF)")


### Injection

- [Blind SQL Injection](https://www.owasp.org/index.php/Blind_SQL_Injection "Blind SQL (Structured Query Language) injection is a type of SQL Injection attack that asks the database true or false questions and determines the answer based on the applications response. This attack is often used when the web application is configured to show generic error messages, but has not mitigated the code that is vulnerable to SQL injection.")
- [Blind XPath Injection](https://www.owasp.org/index.php/Blind_XPath_Injection "XPath is a type of query language that describes how to locate specific elements (including attributes, processing instructions, etc.) in an XML document. Since it is a query language, XPath is somewhat similar to Structured Query Language (SQL), however, XPath is different in that it can be used to reference almost any part of an XML document without access control restrictions. Using an XPATH Injection attack, an attacker is able to modify the XPATH query to perform an action of his choosing.")
- [Code Injection](https://www.owasp.org/index.php/Code_Injection "Code Injection is the general term for attack types which consist of injecting code that is then interpreted/executed by the application. This type of attack exploits poor handling of untrusted data. These types of attacks are usually made possible due to a lack of proper input/output data validation.")
- [Command Injection](https://www.owasp.org/index.php/Command_Injection "Command injection is an attack in which the goal is execution of arbitrary commands on the host operating system via a vulnerable application. Command injection attacks are possible when an application passes unsafe user supplied data (forms, cookies, HTTP headers etc.) to a system shell.")
- [Comment Injection Attack](https://www.owasp.org/index.php/Comment_Injection_Attack "Comments injected into an application through input can be used to compromise a system. As data is parsed, an injected/malformed comment may cause the process to take unexpected actions that result in an attack.")
- [Content Security Policy (CSP)](https://www.owasp.org/index.php/Content_Security_Policy "The risk with CSP can have 2 main sources: 1) Policies misconfiguration, and 2) too permissive policies.")
- [Content Spoofing](https://www.owasp.org/index.php/Content_Spoofing "Content spoofing, also referred to as content injection, 'arbitrary text injection' or virtual defacement, is an attack targeting a user made possible by an injection vulnerability in a web application. When an application does not properly handle user-supplied data, an attacker can supply content to a web application, typically via a parameter value, that is reflected back to the user. This presents the user with a modified page under the context of the trusted domain.")
- [CORS Request Preflight Scrutiny](https://www.owasp.org/index.php/CORS_RequestPreflighScrutiny "CORS stands for Cross-Origin Resource Sharing. The main risk here, is that the request preflight process is entirely managed on client side (by the browser) and then anything warrant web application that the request preflight process will be always followed. A user can create/send (using tools like Curl,OWASP Zap Proxy,...) a final HTTP request without previously sending the first request for preflight and then bypass request preflight process in order to act on data in a unsafe way.")
- [Cross-Site Scripting (XSS)](https://www.owasp.org/index.php/Cross-site_Scripting_(XSS) "Cross-Site Scripting (XSS) attacks are a type of injection, in which malicious scripts are injected into otherwise benign and trusted websites. XSS attacks occur when an attacker uses a web application to send malicious code, generally in the form of a browser side script, to a different end user.")
- [Custom Special Character Injection](https://www.owasp.org/index.php/Custom_Special_Character_Injection "The software does not properly filter or quote special characters or reserved words that are used in a custom or proprietary language or representation that is used by the product. That allows attackers to modify the syntax, content, or commands before they are processed by the end system.")
- [Direct Dynamic Code Evaluation ('Eval Injection')](https://www.owasp.org/index.php/Direct_Dynamic_Code_Evaluation_(%27Eval_Injection%27) "This attack consists of a script that does not properly validate user inputs in the page parameter. A remote user can supply a specially crafted URL to pass arbitrary code to an eval() statement, which results in code execution.")
- [Format String Attack](https://www.owasp.org/index.php/Format_string_attack "The Format String exploit occurs when the submitted data of an input string is evaluated as a command by the application. In this way, the attacker could execute code, read the stack, or cause a segmentation fault in the running application, causing new behaviors that could compromise the security or the stability of the system.")
- [Full Path Disclosure](https://www.owasp.org/index.php/Full_Path_Disclosure "Full Path Disclosure (FPD) vulnerabilities enable the attacker to see the path to the webroot/file. e.g.: /home/omg/htdocs/file/. Certain vulnerabilities, such as using the load_file() (within a SQL Injection) query to view the page source, require the attacker to have the full path to the file they wish to view.")
- [Function Injection](https://www.owasp.org/index.php/Function_Injection "A Function Injection attack consists of insertion or 'injection' of a function name from client to the application. A successful function injection exploit can execute any built-in or user defined function.")
- [Parameter Delimeter](https://www.owasp.org/index.php/Parameter_Delimiter "This attack is based on the manipulation of parameter delimiters used by web application input vectors in order to cause unexpected behaviors like access control and authorization bypass and information disclosure, among others.")
- [PHP Object Injection](https://www.owasp.org/index.php/PHP_Object_Injection "PHP Object Injection is an application level vulnerability that could allow an attacker to perform different kinds of malicious attacks, such as Code Injection, SQL Injection, Path Traversal and Application Denial of Service, depending on the context.")
- [Regular Expression Denial of Service (ReDoS)](https://www.owasp.org/index.php/Regular_expression_Denial_of_Service_-_ReDoS "The Regular expression Denial of Service (ReDoS) is a Denial of Service attack, that exploits the fact that most Regular Expression implementations may reach extreme situations that cause them to work very slowly (exponentially related to input size).")
- [Resource Injection](https://www.owasp.org/index.php/Resource_Injection "This attack consists of changing resource identifiers used by an application in order to perform a malicious task. When an application defines a resource type or location based on user input, such as a file name or port number, this data can be manipulated to execute or access different resources.")
- [Server Side Includes (SSI) Injection](https://www.owasp.org/index.php/Server-Side_Includes_(SSI)_Injection "The Server-Side Includes attack allows the exploitation of a web application by injecting scripts in HTML pages or executing arbitrary codes remotely. It can be exploited through manipulation of SSI in use in the application or force its use through user input fields.")
- [Special Element Injection](https://www.owasp.org/index.php/Special_Element_Injection "Special Element Injection is a type of injection attack that exploits a weakness related to reserved words and special characters.")
- [SQL Injection](https://www.owasp.org/index.php/SQL_Injection "A SQL injection attack consists of insertion or 'injection' of a SQL query via the input data from the client to the application. A successful SQL injection exploit can read sensitive data from the database, modify database data (Insert/Update/Delete), execute administration operations on the database (such as shutdown the DBMS), recover the content of a given file present on the DBMS file system and in some cases issue commands to the operating system.")
- [SQL Injection Bypassing WAF](https://www.owasp.org/index.php/SQL_Injection_Bypassing_WAF "Bypassed WAF. A SQL injection attack consists of insertion or 'injection' of a SQL query via the input data from the client to the application. A successful SQL injection exploit can read sensitive data from the database, modify database data (Insert/Update/Delete), execute administration operations on the database (such as shutdown the DBMS), recover the content of a given file present on the DBMS file system and in some cases issue commands to the operating system.")
- [Web Parameter Tampering](https://www.owasp.org/index.php/Web_Parameter_Tampering "The Web Parameter Tampering attack is based on the manipulation of parameters exchanged between client and server in order to modify application data, such as user credentials and permissions, price and quantity of products, etc. Usually, this information is stored in cookies, hidden form fields, or URL Query Strings, and is used to increase application functionality and control.")
- [XPATH Injection](https://www.owasp.org/index.php/XPATH_Injection "Similar to SQL Injection, XPath Injection attacks occur when a web site uses user-supplied information to construct an XPath query for XML data. By sending intentionally malformed information into the web site, an attacker can find out how the XML data is structured, or access data that he may not normally have access to. He may even be able to elevate his privileges on the web site if the XML data is being used for authentication (such as an XML based user file).")
- [XSS in Subtitle](https://www.owasp.org/index.php/Xss_in_subtitle "It is possible for an attacker to execute JavaScript in a video's subtitle. This is also referred to as XSS (Cross-Site Scripting). If a website loads the subtitle separately in the browser then an attacker can run any HTML or JavaScript in the video subtitle.")


### Path Traversal Attack

> This category of attacks exploit various path vulnerabilities to access files or directories that are not intended to be accessed. This attack works on applications that take user input and use it in a "path" that is used to access a filesystem

> If the attacker includes special characters that modify the meaning of the path, the application will misbehave and may allow the attacker to access unauthorized resources. This type of attack has been successful on web servers, application servers, and custom code.

> E.g. http://foo.com/../../barfile

- [Path Traversal](https://www.owasp.org/index.php/Path_Traversal "A path traversal attack (also known as directory traversal) aims to access files and directories that are stored outside the web root folder. By manipulating variables that reference files with “dot-dot-slash (../)” sequences and its variations or by using absolute file paths, it may be possible to access arbitrary files and directories stored on file system including application source code or configuration and critical system files. It should be noted that access to files is limited by system operational access control (such as in the case of locked or in-use files on the Microsoft Windows operating system).")


### Probabilistic Techniques

- [Brute Force Attack](https://www.owasp.org/index.php/Brute_force_attack "A brute force attack can manifest itself in many different ways, but primarily consists in an attacker configuring predetermined values, making requests to a server using those values, and then analyzing the response. For the sake of efficiency, an attacker may use a dictionary attack (with or without mutations) or a traditional brute-force attack (with given classes of characters e.g.: alphanumerical, special, case (in)sensitive).")
- [Cash Overflow](https://www.owasp.org/index.php/Cash_Overflow "A Cash Overflow attack is a Denial of Service attack specifically aimed at exceeding the hosting costs for a cloud application, either essentially bankrupting the service owner or exceeding the application cost limits, leading the cloud service provider to disable the application.")
- [Cryptanalysis](https://www.owasp.org/index.php/Cryptanalysis "Cryptanalysis is a process of finding weaknesses in cryptographic algorithms and using these weaknesses to decipher the ciphertext without knowing the secret key (instance deduction). Sometimes the weakness is not in the cryptographic algorithm itself, but rather in how it is applied that makes cryptanalysis successful.")
- [Denial of Service](https://www.owasp.org/index.php/Denial_of_Service "The Denial of Service (DoS) attack is focused on making a resource (site, application, server) unavailable for the purpose it was designed. There are many ways to make a service unavailable for legitimate users by manipulating network packets, programming, logical, or resources handling vulnerabilities, among others. If a service receives a very large number of requests, it may cease to be available to legitimate users.")


### Protocol Manipulation

- [Traffic Flood](https://www.owasp.org/index.php/Traffic_flood "Traffic Flood is a type of DoS attack targeting web servers. The attack explores the way that the TCP connection is managed. The attack consists of the generation of a lot of well-crafted TCP requisitions, with the objective to stop the Web Server or cause a performance decrease. The attack explores a characteristic of the HTTP protocol, opening many connections at the same time to attend a single requisition.")


### Resource Depletion

- [Cash Overflow](https://www.owasp.org/index.php/Cash_Overflow "A Cash Overflow attack is a Denial of Service attack specifically aimed at exceeding the hosting costs for a cloud application, either essentially bankrupting the service owner or exceeding the application cost limits, leading the cloud service provider to disable the application.")
- [Denial of Service](https://www.owasp.org/index.php/Denial_of_Service "The Denial of Service (DoS) attack is focused on making a resource (site, application, server) unavailable for the purpose it was designed. There are many ways to make a service unavailable for legitimate users by manipulating network packets, programming, logical, or resources handling vulnerabilities, among others. If a service receives a very large number of requests, it may cease to be available to legitimate users. In the same way, a service may stop if a programming vulnerability is exploited, or the way the service handles resources it uses.")


### Resource Manipulation

- [Comment Injection Attack](https://www.owasp.org/index.php/Comment_Injection_Attack "Comments injected into an application through input can be used to compromise a system. As data is parsed, an injected/malformed comment may cause the process to take unexpected actions that result in an attack.")
- [Custom Special Character Injection](https://www.owasp.org/index.php/Custom_Special_Character_Injection "The software does not properly filter or quote special characters or reserved words that are used in a custom or proprietary language or representation that is used by the product. That allows attackers to modify the syntax, content, or commands before they are processed by the end system.")
- [Double Encoding](https://www.owasp.org/index.php/Double_Encoding "This attack technique consists of encoding user request parameters twice in hexadecimal format in order to bypass security controls or cause unexpected behavior from the application. It's possible because the webserver accepts and processes client requests in many encoded forms. By using double encoding it’s possible to bypass security filters that only decode user input once. The second decoding process is executed by the backend platform or modules that properly handle encoded data, but don't have the corresponding security checks in place. Attackers can inject double encoding in pathnames or query strings to bypass the authentication schema and security filters in use by the web application.")
- [Forced Browsing](https://www.owasp.org/index.php/Forced_browsing "Forced browsing is an attack where the aim is to enumerate and access resources that are not referenced by the application, but are still accessible. An attacker can use Brute Force techniques to search for unlinked contents in the domain directory, such as temporary directories and files, and old backup and configuration files. These resources may store sensitive information about web applications and operational systems, such as source code, credentials, internal network addressing, and so on, thus being considered a valuable resource for intruders.")
- [Path Traversal](https://www.owasp.org/index.php/Path_Traversal "A path traversal attack (also known as directory traversal) aims to access files and directories that are stored outside the web root folder. By manipulating variables that reference files with “dot-dot-slash (../)” sequences and its variations or by using absolute file paths, it may be possible to access arbitrary files and directories stored on file system including application source code or configuration and critical system files. It should be noted that access to files is limited by system operational access control (such as in the case of locked or in-use files on the Microsoft Windows operating system).")
- [Relative Path Traversal](https://www.owasp.org/index.php/Relative_Path_Traversal "A path traversal attack (also known as directory traversal) aims to access files and directories that are stored outside the web root folder. By manipulating variables that reference files with “dot-dot-slash (../)” sequences and its variations or by using absolute file paths, it may be possible to access arbitrary files and directories stored on file system including application source code or configuration and critical system files. It should be noted that access to files is limited by system operational access control (such as in the case of locked or in-use files on the Microsoft Windows operating system).")
- [Repudiation Attack](https://www.owasp.org/index.php/Repudiation_Attack "A repudiation attack happens when an application or system does not adopt controls to properly track and log users' actions, thus permitting malicious manipulation or forging the identification of new actions. This attack can be used to change the authoring information of actions executed by a malicious user in order to log wrong data to log files. Its usage can be extended to general data manipulation in the name of others, in a similar manner as spoofing mail messages. If this attack takes place, the data stored on log files can be considered invalid or misleading.")
- [Setting Manipulation](https://www.owasp.org/index.php/Setting_Manipulation "This attack aims to modify application settings in order to cause misleading data or advantages on the attacker's behalf. He may manipulate values in the system and manage specific user resources of the application or affect its functionalities.")
- [Spyware](https://www.owasp.org/index.php/Spyware "Spyware is a program that captures statistical information from a user's computer and sends it over internet without user acceptance. This information is usually obtained from cookies and the web browser’s history. Spyware can also install other software, display advertisements, or redirect the web browser activity. Spyware differs from a virus, worm, and adware in various ways. Spyware does not self-replicate and distribute itself like viruses and worms, and does not necessarily display advertisements like adware.")
- [Unicode Encoding](https://www.owasp.org/index.php/Unicode_Encoding "The attack aims to explore flaws in the decoding mechanism implemented on applications when decoding Unicode data format. An attacker can use this technique to encode certain characters in the URL to bypass application filters, thus accessing restricted resources on the Web server or to force browsing to protected pages.")


### Sniffing Attacks

https://www.owasp.org/index.php/Sniffing_application_traffic_attack

> Sniffing application traffic simply means that the attacker is able to view network traffic and will try to steal credentials, confidential information, or other sensitive data.

> Anyone with physical access to the network, whether it is switched or via a hub, is likely able to sniff the traffic. (See dsniff and arpspoof tools). Also, anyone with access to intermediate routers, firewalls, proxies, servers, or other networking gear may be able to see the traffic as well.


### Spoofing Attacks

- [Cash Overflow](https://www.owasp.org/index.php/Cash_Overflow "A Cash Overflow attack is a Denial of Service attack specifically aimed at exceeding the hosting costs for a cloud application, either essentially bankrupting the service owner or exceeding the application cost limits, leading the cloud service provider to disable the application.")
- [Cross Site Request Forgery (CSRF)](https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF) "Cross-Site Request Forgery (CSRF) is an attack that forces an end user to execute unwanted actions on a web application in which they're currently authenticated.")
- [Denial of Service](https://www.owasp.org/index.php/Denial_of_Service "The Denial of Service (DoS) attack is focused on making a resource (site, application, server) unavailable for the purpose it was designed. There are many ways to make a service unavailable for legitimate users by manipulating network packets, programming, logical, or resources handling vulnerabilities, among others. If a service receives a very large number of requests, it may cease to be available to legitimate users. In the same way, a service may stop if a programming vulnerability is exploited, or the way the service handles resources it uses.")
- [Man-In-The-Middle Attack](https://www.owasp.org/index.php/Man-in-the-middle_attack "The man-in-the middle attack intercepts a communication between two systems. For example, in an http transaction the target is the TCP connection between client and server. Using different techniques, the attacker splits the original TCP connection into 2 new connections, one between the client and the attacker and the other between the attacker and the server. Once the TCP connection is intercepted, the attacker acts as a proxy, being able to read, insert and modify the data in the intercepted communication.")
- [Server Side Request Forgery](https://www.owasp.org/index.php/Server_Side_Request_Forgery "In a Server-Side Request Forgery (SSRF) attack, the attacker can abuse functionality on the server to read or update internal resources. The attacker can supply or a modify a URL which the code running on the server will read or submit data to, and by carefully selecting the URLs, the attacker may be able to read server configuration such as AWS metadata, connect to internal services like http enabled databases or perform post requests towards internal services which are not intended to be exposed.")
