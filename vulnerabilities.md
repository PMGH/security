# Vulnerabilities

> A vulnerability is a hole or a weakness in the application, which can be a design flaw or an implementation bug, that allows an attacker to cause harm to the stakeholders of an application. Stakeholders include the application owner, application users, and other entities that rely on the application. The term "vulnerability" is often used very loosely. However, here we need to distinguish threats, attacks, and countermeasures.

**https://www.owasp.org/index.php/Category:Vulnerability**

---

<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->
Contents

- [API Abuse](#api-abuse)
- [Authentication](#authentication)
- [Authorization](#authorization)
- [Availability](#availability)
- [Code Permission](#code-permission)
- [Code Quality](#code-quality)
- [Configuration](#configuration)
- [Cryptographic](#cryptographic)
- [Encoding](#encoding)
- [Environmental](#environmental)
- [Error Handling](#error-handling)
- [General Logic Error](#general-logic-error)
- [Input Validation](#input-validation)
- [Logging and Auditing](#logging-and-auditing)
- [Password Management](#password-management)
- [Path](#path)
- [Sensitive Data Protection](#sensitive-data-protection)
- [Session Management](#session-management)
- [Unsafe Mobile Code](#unsafe-mobile-code)
- [Use of Dangerous API](#use-of-dangerous-api)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

---

### API Abuse

> An API is a contract between a caller and a callee. The most common forms of API abuse are caused by the caller failing to honor its end of this contract. For example, if a program fails to call chdir() after calling chroot(), it violates the contract that specifies how to change the active root directory in a secure fashion. Another good example of library abuse is expecting the callee to return trustworthy DNS information to the caller. In this case, the caller abuses the callee API by making certain assumptions about its behavior (that the return value can be used for authentication purposes). One can also violate the caller-callee contract from the other side. For example, if a coder subclasses SecureRandom and returns a non-random value, the contract is violated.

- [Directory Restriction Error](https://www.owasp.org/index.php/Directory_Restriction_Error)
- [XML External Entity(XXE) Processing](https://www.owasp.org/index.php/XML_External_Entity_(XXE)_Processing)


### Authentication

- [Password Management Vulnerability](https://www.owasp.org/index.php/Category:Password_Management_Vulnerability)
- [Empty String Password](https://www.owasp.org/index.php/Empty_String_Password)
- [Unsafe Mobile Code](https://www.owasp.org/index.php/Unsafe_Mobile_Code)


### Authorization

- [Least Privilege Violation](https://www.owasp.org/index.php/Least_Privilege_Violation)


### Availability

No OWASP links available.

### Code Permission

No OWASP links available.

### Code Quality

- [Doubly Freeing Memory](https://www.owasp.org/index.php/Doubly_freeing_memory)
- [Leftover Debug Code](https://www.owasp.org/index.php/Leftover_Debug_Code)
- [Memory Leak](https://www.owasp.org/index.php/Memory_leak)
- [Null Dereference](https://www.owasp.org/index.php/Null_Dereference)
- [Poor Logging Practice](https://www.owasp.org/index.php/Poor_Logging_Practice)
- [Portability Flaw](https://www.owasp.org/index.php/Portability_Flaw)
- [Undefined Behaviour](https://www.owasp.org/index.php/Undefined_Behavior)
- [Unreleased Resource](https://www.owasp.org/index.php/Unreleased_Resource)
- [Unsafe Mobile Code](https://www.owasp.org/index.php/Unsafe_Mobile_Code)
- [Use of Obsolete Methods](https://www.owasp.org/index.php/Use_of_Obsolete_Methods)


### Configuration

No OWASP links available.

### Cryptographic

##### Algorithm Problems

- **Insecure Algorithm**
  - Use algorithms that are proven flawed or weak (DES, 3DES, MD5, Sha1, AES, Blowfish, Diffie Hellman)
  - Use non-standard (home-grown) algorithms
- **Wrong Algorithm Chosen**
  - Use hash function for encryption
  - Use encryption algorithm for hashing
- **Inappropriate Use of Algorithm**
  - Use insecure encryption modes (DES EBC)
  - Initial vector is not random
- **Implementation Errors**
  - Use non-standard cryptographic implementations/libraries

##### Key Management Problems

- **Weak Keys**
  - Too short or not random enough
  - Use human chosen passwords as cryptographic keys
- **Key Disclosure**
  - Keys not encrypted during storage or transmission
  - Keys not cleaned appropriately after use
  - Keys Hard-coded in the code or stored in configuration files
- **Key Updates**
  - Allow keys aging

##### Random Number Generator (RNG) Problems

- Poor random number generators (c: rand(), Java: java.util.Random())
- Forget to seed the random number generator
- Use the same seed for the random number generator every time
- Sniffing

##### Examples

- [Information Exposure Through Query Strings in URL](https://www.owasp.org/index.php/Information_exposure_through_query_strings_in_url)
- [Insecure Randomness](https://www.owasp.org/index.php/Insecure_Randomness)
- [Insufficient Entropy](https://www.owasp.org/index.php/Insufficient_Entropy)
- [Insufficient Session-ID Length](https://www.owasp.org/index.php/Insufficient_Session-ID_Length)
- [PRNG Seed Error](https://www.owasp.org/index.php/PRNG_Seed_Error)
- [Testing for SSL-TLS (OWASP-CM-001)](https://www.owasp.org/index.php/Testing_for_SSL-TLS_(OWASP-CM-001))
- [Testing for Weak SSL/TLS Ciphers, Insufficient Transport Layer Protection (OTG-CRYPST-001)](https://www.owasp.org/index.php/Testing_for_Weak_SSL/TLS_Ciphers,_Insufficient_Transport_Layer_Protection_(OTG-CRYPST-001))
- [Use of Hard-Coded Cryptographic Key](https://www.owasp.org/index.php/Use_of_hard-coded_cryptographic_key)
- [Using a Broken or Risky Cryptographic Algorithm](https://www.owasp.org/index.php/Using_a_broken_or_risky_cryptographic_algorithm)

### Encoding

No OWASP links available.

### Environmental

- [Empty String Password](https://www.owasp.org/index.php/Empty_String_Password)
- [Insecure Compiler Optimization](https://www.owasp.org/index.php/Insecure_Compiler_Optimization)
- [Insecure Transport](https://www.owasp.org/index.php/Insecure_Transport)
- [Insufficient Session-ID Length](https://www.owasp.org/index.php/Insufficient_Session-ID_Length)
- [Missing Error Handling](https://www.owasp.org/index.php/Missing_Error_Handling)


### Error Handling

- [Catch Null Pointer Exception](https://www.owasp.org/index.php/Catch_NullPointerException)
- [Empty Catch Block](https://www.owasp.org/index.php/Empty_Catch_Block)
- [Missing Error Handling](https://www.owasp.org/index.php/Missing_Error_Handling)
- [Return Inside Finally Block](https://www.owasp.org/index.php/Return_Inside_Finally_Block)
- [Unchecked Error Condition](https://www.owasp.org/index.php/Unchecked_Error_Condition)


### General Logic Error

- [Undefined Behaviour](https://www.owasp.org/index.php/Undefined_Behavior)


### Input Validation

- [Deserialization of Untrusted Data](https://www.owasp.org/index.php/Deserialization_of_untrusted_data)
- [Expression Language Injection](https://www.owasp.org/index.php/Expression_Language_Injection)
- [Form Action Hijacking](https://www.owasp.org/index.php/Form_action_hijacking)
- [Improper Data Validation](https://www.owasp.org/index.php/Improper_Data_Validation)
- [Missing XML Validation](https://www.owasp.org/index.php/Missing_XML_Validation)
- [Overly Permissive Regular Expression](https://www.owasp.org/index.php/Overly_Permissive_Regular_Expression)
- [Process Control](https://www.owasp.org/index.php/Process_Control)
- [String Termination Error](https://www.owasp.org/index.php/String_Termination_Error)
- [Unchecked Return Value: Missing Check against Null](https://www.owasp.org/index.php/Unchecked_Return_Value:_Missing_Check_against_Null)
- [Unsafe JNI](https://www.owasp.org/index.php/Unsafe_JNI)
- [Unsafe Use of Reflection](https://www.owasp.org/index.php/Unsafe_use_of_Reflection)


### Logging and Auditing

- [Poor Logging Practice](https://www.owasp.org/index.php/Poor_Logging_Practice)


### Password Management

- [Empty String Password](https://www.owasp.org/index.php/Empty_String_Password)
- [Password in Confirguration File](https://www.owasp.org/index.php/Password_in_Configuration_File)
- [Password Management: Hardcoded Password](https://www.owasp.org/index.php/Password_Management:_Hardcoded_Password)
- [Password Plaintext Storage](https://www.owasp.org/index.php/Password_Plaintext_Storage)


### Path

> This category is for tagging path issues that allow attackers to access files that are not intended to be accessed. Generally, this is due to dynamically construction of a file path using unvalidated user input.

Attacks that can exploit this vulnerability:

- [Path Traversal Attack](https://www.owasp.org/index.php?title=Path_Traversal_Attack&action=edit&redlink=1)
  - [Relative Path Traversal Attack](https://www.owasp.org/index.php?title=Relative_Path_Traversal_Attack&action=edit&redlink=1)
  - [Absolute Path Traversal Attack](https://www.owasp.org/index.php?title=Absolute_Path_Traversal_Attack&action=edit&redlink=1)
- [Path Equivalence Attack](https://www.owasp.org/index.php?title=Path_Equivalence_Attack&action=edit&redlink=1)
- [Link Following Attack](https://www.owasp.org/index.php?title=Link_Following_Attack&action=edit&redlink=1)
- [Virtual Files Attack](https://www.owasp.org/index.php?title=Virtual_Files_Attack&action=edit&redlink=1)


### Sensitive Data Protection

> Vulnerabilities that lead to insecure protection of sensitive data. The protection referred here includes confidentiality and integrity of data during its whole lifecycles, including storage and transmission. Protection for sensitive data that are not intended to be revealed to or modified by any application users.

> Examples of this kind of sensitive data can be cryptographic keys, passwords, security tokens or any information that an application relies on for critical decisions.

- [Information Exposure Through Query Strings in URL](https://www.owasp.org/index.php/Information_exposure_through_query_strings_in_url)
- [Password Management: Hardcoded Password](https://www.owasp.org/index.php/Password_Management:_Hardcoded_Password)
- [Password Plaintext Storage](https://www.owasp.org/index.php/Password_Plaintext_Storage)
- [Privacy Violation](https://www.owasp.org/index.php/Privacy_Violation)


### Session Management

- [Insufficient Session ID Length](https://www.owasp.org/index.php/Insufficient_Session-ID_Length)
- [Session Variable Overloading](https://www.owasp.org/index.php/Session_Variable_Overloading)


### Unsafe Mobile Code

No OWASP links available.

### Use of Dangerous API

- [Directory Restriction Error](https://www.owasp.org/index.php/Directory_Restriction_Error)
- [Insecure Temporary File](https://www.owasp.org/index.php/Insecure_Temporary_File)
- [Unrestricted File Upload](https://www.owasp.org/index.php/Unrestricted_File_Upload)
- [Unsafe Java Native Interface (JNI)](https://www.owasp.org/index.php/Unsafe_JNI)
- [Unsafe Use of Reflection](https://www.owasp.org/index.php/Unsafe_use_of_Reflection)
- [Use of Obsolete Methods](https://www.owasp.org/index.php/Use_of_Obsolete_Methods)

