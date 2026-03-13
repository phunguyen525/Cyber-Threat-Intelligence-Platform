export default function ThreatTable({ threats }) {
    return (
        <div className="card">
            <h2>Detected Threats</h2>
            <table>
                <thead>
                    <tr>
                        <th>Threat Type</th>
                        <th>IP</th>
                        <th>Service</th>
                        <th>Details</th>
                    </tr>
                </thead>
                <tbody>
                    {threats.map((threat, index) => (
                        <tr key={index}>
                            <td>{threat.threat_type}</td>
                            <td>{threat.ip_address}</td>
                            <td>{threat.target_service || "-"}</td>
                            <td>{threat.details}</td>
                        </tr>
                    ))}
                </tbody>
            </table>
        </div>
    );
}