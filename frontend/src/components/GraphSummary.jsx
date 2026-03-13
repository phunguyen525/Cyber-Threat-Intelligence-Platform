export default function GraphSummary({ graph }) {
    return (
        <div className="card">
            <h2>Graph Summary</h2>
            <p><strong>Total Nodes:</strong> {graph.nodes.length}</p>
            <p><strong>Total Relationships:</strong> {graph.relationships.length}</p>
        </div>
    );
}