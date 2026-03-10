import json
from collections import defaultdict
from datetime import datetime
from neo4j import GraphDatabase

URI = "bolt://localhost:7687"
USERNAME = "neo4j"
PASSWORD = "Phu05022005@"

BRUTE_FORCE_THRESHOLD = 3
SERVICE_SCAN_THRESHOLD = 3
PASSWORD_SPRAY_THRESHOLD = 3
TIME_WINDOW_SECONDS = 60

driver = GraphDatabase.driver(URI, auth=(USERNAME, PASSWORD))


def insert_log(tx, log):
    tx.run(
        """
        MERGE (ip:IP {address: $ip})
        MERGE (service:Service {name: $service})
        MERGE (user:User {username: $username})

        CREATE (event:AttackEvent {
            type: $type,
            timestamp: $timestamp,
            severity: $severity
        })

        MERGE (event)-[:FROM_IP]->(ip)
        MERGE (event)-[:TARGETS_SERVICE]->(service)
        MERGE (event)-[:USES_USERNAME]->(user)
        """,
        ip=log["source_ip"],
        service=log["target_service"],
        username=log["username"],
        type=log["event_type"],
        timestamp=log["timestamp"],
        severity=log["severity"],
    )


def insert_threat(tx, threat_type, ip, service=None, usernames=None, details=None):
    tx.run(
        """
        MERGE (source_ip:IP {address: $ip})
        CREATE (threat:Threat {
            type: $threat_type,
            details: $details,
            source_ip: $ip
        })
        MERGE (threat)-[:DETECTED_FROM]->(source_ip)
        WITH threat
        OPTIONAL MATCH (service:Service {name: $service})
        FOREACH (_ IN CASE WHEN service IS NOT NULL THEN [1] ELSE [] END |
            MERGE (threat)-[:TARGETS_SERVICE]->(service)
        )
        """,
        threat_type=threat_type,
        ip=ip,
        service=service,
        details=details,
    )

    if usernames:
        for username in usernames:
            tx.run(
                """
                MATCH (threat:Threat {type: $threat_type, details: $details, source_ip: $ip})
                MATCH (user:User {username: $username})
                MERGE (threat)-[:TARGETS_USER]->(user)
                """,
                threat_type=threat_type,
                details=details,
                ip=ip,
                username=username,
            )


def has_threshold_within_window(timestamps, threshold, window_seconds):
    timestamps = sorted(timestamps)

    for i in range(len(timestamps)):
        count = 1
        window_start = timestamps[i]

        for j in range(i + 1, len(timestamps)):
            delta = (timestamps[j] - window_start).total_seconds()

            if delta <= window_seconds:
                count += 1
            else:
                break

        if count >= threshold:
            return True, count, window_start

    return False, 0, None


def has_distinct_services_within_window(events, threshold, window_seconds):
    events = sorted(events, key=lambda x: x[0])

    for i in range(len(events)):
        window_start = events[i][0]
        distinct_services = {events[i][1]}

        for j in range(i + 1, len(events)):
            delta = (events[j][0] - window_start).total_seconds()

            if delta <= window_seconds:
                distinct_services.add(events[j][1])
            else:
                break

        if len(distinct_services) >= threshold:
            return True, distinct_services, window_start

    return False, set(), None


def has_distinct_usernames_within_window(events, threshold, window_seconds):
    events = sorted(events, key=lambda x: x[0])

    for i in range(len(events)):
        window_start = events[i][0]
        distinct_usernames = {events[i][1]}

        for j in range(i + 1, len(events)):
            delta = (events[j][0] - window_start).total_seconds()

            if delta <= window_seconds:
                distinct_usernames.add(events[j][1])
            else:
                break

        if len(distinct_usernames) >= threshold:
            return True, distinct_usernames, window_start

    return False, set(), None


def main():
    with open("data/sample_logs.json", "r") as f:
        logs = json.load(f)

    failed_login_by_ip_service = defaultdict(list)
    service_events_by_ip = defaultdict(list)
    username_events_by_ip_service = defaultdict(list)

    try:
        with driver.session() as session:
            for log in logs:
                session.execute_write(insert_log, log)

                ip = log["source_ip"]
                service = log["target_service"]
                username = log["username"]
                event_type = log["event_type"]
                timestamp = datetime.fromisoformat(log["timestamp"])

                if event_type == "failed_login":
                    failed_login_by_ip_service[(ip, service)].append(timestamp)
                    service_events_by_ip[ip].append((timestamp, service))
                    username_events_by_ip_service[(ip, service)].append((timestamp, username))

            # 1. Brute force
            for (ip, service), timestamps in failed_login_by_ip_service.items():
                detected, count, window_start = has_threshold_within_window(
                    timestamps,
                    BRUTE_FORCE_THRESHOLD,
                    TIME_WINDOW_SECONDS
                )

                if detected:
                    details = (
                        f"{count} failed logins within {TIME_WINDOW_SECONDS}s "
                        f"on {service}, starting at {window_start.isoformat()}"
                    )
                    session.execute_write(
                        insert_threat,
                        "BruteForceAttack",
                        ip,
                        service,
                        None,
                        details,
                    )
                    print(f"[ALERT] Brute force detected from {ip} on {service}")

            # 2. Service scanning
            for ip, events in service_events_by_ip.items():
                detected, services, window_start = has_distinct_services_within_window(
                    events,
                    SERVICE_SCAN_THRESHOLD,
                    TIME_WINDOW_SECONDS
                )

                if detected:
                    details = (
                        f"Targeted {len(services)} distinct services within "
                        f"{TIME_WINDOW_SECONDS}s starting at {window_start.isoformat()}: "
                        f"{', '.join(sorted(services))}"
                    )
                    session.execute_write(
                        insert_threat,
                        "ServiceScanning",
                        ip,
                        None,
                        None,
                        details,
                    )
                    print(f"[ALERT] Service scanning detected from {ip}")

            # 3. Password spraying
            for (ip, service), events in username_events_by_ip_service.items():
                detected, usernames, window_start = has_distinct_usernames_within_window(
                    events,
                    PASSWORD_SPRAY_THRESHOLD,
                    TIME_WINDOW_SECONDS
                )

                if detected:
                    details = (
                        f"Tried {len(usernames)} distinct usernames within "
                        f"{TIME_WINDOW_SECONDS}s on {service}, starting at "
                        f"{window_start.isoformat()}"
                    )
                    session.execute_write(
                        insert_threat,
                        "PasswordSpraying",
                        ip,
                        service,
                        sorted(list(usernames)),
                        details,
                    )
                    print(f"[ALERT] Password spraying detected from {ip} on {service}")

        print("Phase 3 completed.")

    finally:
        driver.close()


if __name__ == "__main__":
    main()