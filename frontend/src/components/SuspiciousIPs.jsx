export default function SuspiciousIPs({ suspiciousIPs }) {
    return (
        <div className="card">
            <h2>Suspicious IPs</h2>
            <table>
                <thead>
                    <tr>
                        <th>IP Address</th>
                        <th>Threat Count</th>
                        <th>Threat Types</th>
                    </tr>
                </thead>
                <tbody>
                    {suspiciousIPs.map((ip, index) => (
                        <tr key={index}>
                            <td>{ip.ip_address}</td>
                            <td>{ip.threat_count}</td>
                            <td>{ip.threat_types.join(", ")}</td>
                        </tr>
                    ))}
                </tbody>
            </table>
        </div>
    );
}