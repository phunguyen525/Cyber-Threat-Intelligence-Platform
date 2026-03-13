export default function RecentEvents({ events }) {
    return (
        <div className="card">
            <h2>Recent Events</h2>
            <table>
                <thead>
                    <tr>
                        <th>Timestamp</th>
                        <th>Type</th>
                        <th>Severity</th>
                        <th>IP</th>
                        <th>Service</th>
                        <th>User</th>
                    </tr>
                </thead>
                <tbody>
                    {events.map((event, index) => (
                        <tr key={index}>
                            <td>{event.timestamp}</td>
                            <td>{event.event_type}</td>
                            <td>{event.severity}</td>
                            <td>{event.source_ip}</td>
                            <td>{event.target_service || "-"}</td>
                            <td>{event.username || "-"}</td>
                        </tr>
                    ))}
                </tbody>
            </table>
        </div>
    );
}