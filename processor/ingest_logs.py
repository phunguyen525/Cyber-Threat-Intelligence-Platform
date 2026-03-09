import json
from collections import defaultdict
from neo4j import GraphDatabase

URI = "bolt://localhost:7687"
USERNAME = "neo4j"
PASSWORD = "Phu05022005@"

BRUTE_FORCE_THRESHOLD = 3
SERVICE_SCAN_THRESHOLD = 3
PASSWORD_SPRAY_THRESHOLD = 3

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


def main():
    with open("data/sample_logs.json", "r") as f:
        logs = json.load(f)

    failed_login_by_ip_service = defaultdict(int)
    services_by_ip = defaultdict(set)
    usernames_by_ip_service = defaultdict(set)

    try:
        with driver.session() as session:
            for log in logs:
                session.execute_write(insert_log, log)

                ip = log["source_ip"]
                service = log["target_service"]
                username = log["username"]
                event_type = log["event_type"]

                services_by_ip[ip].add(service)

                if event_type == "failed_login":
                    failed_login_by_ip_service[(ip, service)] += 1
                    usernames_by_ip_service[(ip, service)].add(username)

            for (ip, service), count in failed_login_by_ip_service.items():
                if count >= BRUTE_FORCE_THRESHOLD:
                    details = f"{count} failed logins detected on {service}"
                    session.execute_write(
                        insert_threat,
                        "BruteForceAttack",
                        ip,
                        service,
                        None,
                        details,
                    )
                    print(f"[ALERT] Brute force detected from {ip} on {service}")

            for ip, services in services_by_ip.items():
                if len(services) >= SERVICE_SCAN_THRESHOLD:
                    details = f"Targeted {len(services)} distinct services: {', '.join(sorted(services))}"
                    session.execute_write(
                        insert_threat,
                        "ServiceScanning",
                        ip,
                        None,
                        None,
                        details,
                    )
                    print(f"[ALERT] Service scanning detected from {ip}")

            for (ip, service), usernames in usernames_by_ip_service.items():
                if len(usernames) >= PASSWORD_SPRAY_THRESHOLD:
                    details = f"Tried {len(usernames)} distinct usernames on {service}"
                    session.execute_write(
                        insert_threat,
                        "PasswordSpraying",
                        ip,
                        service,
                        sorted(list(usernames)),
                        details,
                    )
                    print(f"[ALERT] Password spraying detected from {ip} on {service}")

        print("Phase 2 detection completed.")

    finally:
        driver.close()


if __name__ == "__main__":
    main()