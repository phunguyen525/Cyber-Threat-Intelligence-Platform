import json
import time
from confluent_kafka import Producer

BOOTSTRAP_SERVERS = "localhost:9092"
TOPIC = "security_logs"
SIMULATION_DELAY_SECONDS = 1


def delivery_report(err, msg):
    if err is not None:
        print(f"[ERROR] Delivery failed: {err}")
    else:
        print(
            f"[SENT] topic={msg.topic()} partition={msg.partition()} "
            f"offset={msg.offset()}"
        )


def main():
    producer = Producer({"bootstrap.servers": BOOTSTRAP_SERVERS})

    with open("data/sample_logs.json", "r") as f:
        logs = json.load(f)

    for log in logs:
        payload = json.dumps(log)
        producer.produce(TOPIC, value=payload, callback=delivery_report)
        producer.poll(0)

        print(
            f"[PRODUCER] {log['timestamp']} | {log['event_type']} | "
            f"IP={log['source_ip']} | Service={log['target_service']} | "
            f"User={log['username']}"
        )

        time.sleep(SIMULATION_DELAY_SECONDS)

    producer.flush()
    print("Finished sending logs to Kafka.")


if __name__ == "__main__":
    main()