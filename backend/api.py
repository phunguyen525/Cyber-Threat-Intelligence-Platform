from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from neo4j import GraphDatabase

app = FastAPI(title="Cyber Threat Intelligence API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

URI = "bolt://localhost:7687"
USERNAME = "neo4j"
PASSWORD = "Phu05022005@"

driver = GraphDatabase.driver(URI, auth=(USERNAME, PASSWORD))


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/threats")
def get_threats():
    query = """
    MATCH (t:Threat)-[:DETECTED_FROM]->(ip:IP)
    OPTIONAL MATCH (t)-[:TARGETS_SERVICE]->(s:Service)
    RETURN t.type AS threat_type,
           t.details AS details,
           ip.address AS ip_address,
           s.name AS target_service
    ORDER BY ip.address
    """

    with driver.session() as session:
        result = session.run(query)
        threats = [record.data() for record in result]

    return {"threats": threats}


@app.get("/ips/suspicious")
def get_suspicious_ips():
    query = """
    MATCH (t:Threat)-[:DETECTED_FROM]->(ip:IP)
    RETURN ip.address AS ip_address,
           count(t) AS threat_count,
           collect(DISTINCT t.type) AS threat_types
    ORDER BY threat_count DESC
    """

    with driver.session() as session:
        result = session.run(query)
        suspicious_ips = [record.data() for record in result]

    return {"suspicious_ips": suspicious_ips}


@app.get("/events/recent")
def get_recent_events(limit: int = 20):
    query = """
    MATCH (e:AttackEvent)-[:FROM_IP]->(ip:IP)
    OPTIONAL MATCH (e)-[:TARGETS_SERVICE]->(s:Service)
    OPTIONAL MATCH (e)-[:USES_USERNAME]->(u:User)
    RETURN e.timestamp AS timestamp,
           e.type AS event_type,
           e.severity AS severity,
           ip.address AS source_ip,
           s.name AS target_service,
           u.username AS username
    ORDER BY e.timestamp DESC
    LIMIT $limit
    """

    with driver.session() as session:
        result = session.run(query, limit=limit)
        events = [record.data() for record in result]

    return {"events": events}


@app.get("/graph")
def get_graph():
    nodes_query = """
    MATCH (n)
    RETURN n
    """

    relationships_query = """
    MATCH (a)-[r]->(b)
    RETURN a, r, b
    """

    nodes = {}
    relationships = []

    with driver.session() as session:
        # Get all nodes
        node_result = session.run(nodes_query)
        for record in node_result:
            n = record["n"]
            nodes[n.element_id] = {
                "id": n.element_id,
                "labels": list(n.labels),
                "properties": dict(n)
            }

        # Get all relationships
        rel_result = session.run(relationships_query)
        for record in rel_result:
            a = record["a"]
            r = record["r"]
            b = record["b"]

            if a.element_id not in nodes:
                nodes[a.element_id] = {
                    "id": a.element_id,
                    "labels": list(a.labels),
                    "properties": dict(a)
                }

            if b.element_id not in nodes:
                nodes[b.element_id] = {
                    "id": b.element_id,
                    "labels": list(b.labels),
                    "properties": dict(b)
                }

            relationships.append({
                "id": r.element_id,
                "type": r.type,
                "source": a.element_id,
                "target": b.element_id,
                "properties": dict(r)
            })

    return {
        "nodes": list(nodes.values()),
        "relationships": relationships
    }