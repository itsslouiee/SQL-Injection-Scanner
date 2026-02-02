# SQL Injection Vulnerability Scanner

⚠️ **FOR Educational and Authorized Use Only**

This project is a **SQL injection detection tool** written in Python.
It was built to understand how different SQL injection techniques work in practice, how web applications respond to them, and how automated scanners reason about evidence.
**Only use it  on systems you own or have explicit written permission to test.** Unauthorized testing is illegal and unethical.


## How SQL Injection Works

SQL injection occurs when user input is incorporated into SQL queries without proper sanitization. Attackers can manipulate these queries to:
- Bypass authentication
- Access unauthorized data
- Modify or delete database records
- Execute administrative operations on the database

**Example of a vulnerable query:**
```sql
SELECT * FROM users WHERE username = 'USER_INPUT' AND password = 'USER_INPUT'
```

If `USER_INPUT` is not sanitized, an attacker could inject into it: `' OR '1'='1`

**Resulting query:**
```sql
SELECT * FROM users WHERE username = '' OR '1'='1' AND password = '' OR '1'='1'
```
This returns all users, bypassing authentication.


## Detection Methodologies

This scanner implements four SQL injection detection techniques:

### 1. Error-Based Detection

**How it works:**  
Injects malformed SQL syntax to trigger database error messages that appear in the HTTP response.

**Technique:**  
The scanner sends payloads like `'`, `"`, `' OR '1'='1` that intentionally break SQL syntax. If the application returns database-specific error messages, it proves that user input is being directly incorporated into SQL queries without proper sanitization. This definitively proves that there's a vulnerability.


### 2. Boolean-Based Blind SQL Injection

**How it works:**  
This technique is used when error messages are suppressed. The scanner injects SQL conditions that evaluate to TRUE or FALSE and then compares these responses to determine if the injected SQL is being executed.

**Technique:**  
When error messages are suppressed, the scanner injects two payloads:
- `' AND '1'='1` (always TRUE)
- `' AND '1'='2` (always FALSE)

The scanner compares the responses using similarity analysis. If the TRUE response matches the baseline but the FALSE response differs significantly, it proves the SQL is being executed.

**Example:**
```sql
-- Original query
SELECT * FROM products WHERE id = 1

-- TRUE injection
SELECT * FROM products WHERE id = 1 AND '1'='1'  -- Returns product 1

-- FALSE injection
SELECT * FROM products WHERE id = 1 AND '1'='2'  -- Returns nothing
```


### 3. Time-Based Blind SQL Injection

**How it works:**  
Injects database-specific sleep commands and measures response time delays to detect SQL execution.

**Technique:**  
When applications show no visible differences between responses, the scanner injects time delay functions:
- MySQL: `' AND SLEEP(5)--`
- MSSQL: `'; WAITFOR DELAY '0:0:5'--`

The time delay is a side-channel signal. The database executes the SLEEP command, causing a measurable delay ( approximately 5 seconds), which proves that the injected SQL is being executed regardless of what the page displays.

**Example:**
```sql
-- Original query
SELECT * FROM products WHERE id = 1

-- Time-based injection
SELECT * FROM products WHERE id = 1 AND SLEEP(5)--
```


### 4. UNION-Based SQL Injection

**How it works:**  
Unlike other techniques that infer SQL execution from behavior, UNION-based detection Uses SQL UNION operator to combine the original query with an attacker-controlled query and provides direct evidence: if our unique markers appear in the response, the database definitely executed our SQL and returned our values. This is proof of SQL injection.

**Technique:**  
The scanner first determines the number of columns in the original query using `ORDER BY`, then tests UNION with unique marker values:

**Step 1 - Find column count:**
```sql
' ORDER BY 1--  
' ORDER BY 2--  
' ORDER BY 3--  --error
Conclusion: 2 columns
```

**Step 2 - Test UNION with markers:**
```sql
' UNION SELECT 1337,7331--
```

The scanner then checks if the unique markers (1337, 7331) appear in the HTTP response.

**Why markers are used:**
Markers don't need to exist in the database. They are literal values returned by the SQL engine itself. Their appearance in the response is direct proof of successful UNION execution.

**NOTE**  
Once a UNION-based injection is confirmed, it can be used to extract actual data from the database by replacing markers with real column names like `username` or `password`.



## Implementation Details

**Target Extraction:**  
The scanner automatically identifies:
- HTML forms (POST and GET methods)
- URL parameters (GET requests)
- Hidden form fields

**Request Handling:**  
- Maintains session state
- Uses realistic User-Agent headers
- Implements configurable timeouts
- Handles both GET and POST requests

**Detection Logic:**  
Each detection method runs independently and reports findings.


## Usage
```bash
python scanner.py
```

## Limitations
This scanner detects SQL injection by analyzing how the application responds to different inputs. It may not always produce accurate results and can miss certain vulnerabilities or report false positives depending on how the website behaves. Always manually verify any findings before reporting them.


## License 
This project is intended for educational and learning purposes only.

## Author 
**itsslouiee** 