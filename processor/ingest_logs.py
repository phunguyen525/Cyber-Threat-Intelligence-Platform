import json
from neo4j import GraphDatabase

URI = "bolt://localhost:7687"
USERNAME = "neo4j"
PASSWORD = "Phu05022005@"

driver = GraphDatabase.driver(URI, auth=(USERNAME, PASSWORD))


def insert_log(tx, log):

    tx.run(
        """
        MERGE (ip:IP {address: $ip})
        MERGE (service:Service {name: $service}) 

        CREATE (event:AttackEvent {
            type: $type,
            timestamp: $timestamp,
            severity: $severity
        })

        MERGE (event)-[:FROM_IP]->(ip)
        MERGE (event)-[:TARGETS_SERVICE]->(service)
        """,
        ip=log["source_ip"],
        service=log["target_service"],
        type=log["event_type"],
        timestamp=log["timestamp"],
        severity=log["severity"],
    )


with open("data/sample_logs.json") as f:
    logs = json.load(f)

with driver.session() as session:
    for log in logs:
        session.execute_write(insert_log, log)

print("Logs inserted into Neo4j")