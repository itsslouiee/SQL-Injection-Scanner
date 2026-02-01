# SQL Injection Vulnerability Scanner

⚠️ **FOR AUTHORIZED SECURITY TESTING ONLY**

This tool is designed for security professionals, penetration testers, and developers to identify SQL injection vulnerabilities in web applications. **Only use this scanner on systems you own or have explicit written permission to test.** Unauthorized testing is illegal and unethical.


## Overview

A Python-based SQL injection scanner that employs multiple detection techniques to identify vulnerabilities in web application forms. The scanner systematically tests input fields using various payloads and analyzes responses to determine if SQL injection is possible.


## How SQL Injection Works

SQL injection occurs when user input is incorporated into SQL queries without proper sanitization. Attackers can manipulate these queries to bypass authentication, access unauthorized data, modify databases, or execute administrative operations.


## Detection Methodologies

This scanner implements three basic SQL injection detection techniques:

### 1. Error-Based Detection

**Principle:** Injects malformed SQL syntax to trigger database error messages.

The scanner sends specially crafted payloads (such as single quotes, double quotes, or SQL-specific characters) that intentionally break SQL syntax. If the application returns database-specific error messages in the response, it indicates that user input is being directly incorporated into SQL queries without proper sanitization.

**Advantages:**
- Fast and reliable
- Definitively proves vulnerability when errors are exposed
- Enables database fingerprinting for targeted exploitation

### 2. Boolean-Based Blind SQL Injection

**Principle:** Exploits conditional logic by comparing responses to TRUE and FALSE SQL conditions.

This technique is used when error messages are suppressed. The scanner injects SQL conditions that evaluate to TRUE or FALSE and uses response comparison (diffing) to determine if the injected SQL is being executed. By analyzing differences in HTTP responses between TRUE and FALSE conditions, the scanner can confirm SQL injection even without visible error messages.

**Advantages:**
- Works when error messages are hidden
- Utilizes algorithmic response comparison for accuracy

### 3. Time-Based Blind SQL Injection

**Principle:** Measures response time delays to detect SQL execution.

When applications neither display errors nor show visible differences between TRUE/FALSE conditions, time-based detection can still identify vulnerabilities. The scanner injects database-specific sleep commands and measures response times. If the server delays its response by the specified duration, it proves that the injected SQL is being executed.

**Advantages:**
- Most comprehensive detection method
- Works when all other detection methods fail


## Additional Detection Techniques (Not Implemented)

While this scanner focuses on the three primary detection methods, several other advanced techniques exist in professional SQL injection testing:

- **UNION-based SQL Injection** - Combines query results to extract data directly
- **Out-of-Band SQL Injection** - Exfiltrates data through alternative channels (DNS, HTTP)
- **Second-Order SQL Injection** - Exploits stored data that is later used in vulnerable queries
- **Stack Queries** - Executes multiple SQL statements in a single injection

These techniques require more complex implementation and specific server configurations.


