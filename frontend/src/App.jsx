import { useEffect, useState } from "react";
import "./App.css";

import {
  fetchHealth,
  fetchThreats,
  fetchSuspiciousIPs,
  fetchRecentEvents,
  fetchGraph,
} from "./services/api";

import ThreatTable from "./components/ThreatTable";
import SuspiciousIPs from "./components/SuspiciousIPs";
import RecentEvents from "./components/RecentEvents";
import GraphSummary from "./components/GraphSummary";

export default function App() {
  const [health, setHealth] = useState(null);
  const [threats, setThreats] = useState([]);
  const [suspiciousIPs, setSuspiciousIPs] = useState([]);
  const [events, setEvents] = useState([]);
  const [graph, setGraph] = useState({ nodes: [], relationships: [] });
  const [loading, setLoading] = useState(true);

  async function loadDashboard() {
    try {
      const [healthData, threatsData, ipsData, eventsData, graphData] =
        await Promise.all([
          fetchHealth(),
          fetchThreats(),
          fetchSuspiciousIPs(),
          fetchRecentEvents(20),
          fetchGraph(),
        ]);

      setHealth(healthData.status);
      setThreats(threatsData.threats || []);
      setSuspiciousIPs(ipsData.suspicious_ips || []);
      setEvents(eventsData.events || []);
      setGraph(graphData || { nodes: [], relationships: [] });
    } catch (error) {
      console.error("Failed to load dashboard:", error);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadDashboard();

    const interval = setInterval(() => {
      loadDashboard();
    }, 3000);

    return () => clearInterval(interval);
  }, []);

  if (loading) {
    return <div className="app"><h1>Loading dashboard...</h1></div>;
  }

  return (
    <div className="app">
      <header className="header">
        <h1>Cyber Threat Intelligence Dashboard</h1>
        <p>API Status: <strong>{health}</strong></p>
      </header>

      <div className="grid">
        <GraphSummary graph={graph} />
        <SuspiciousIPs suspiciousIPs={suspiciousIPs} />
      </div>

      <ThreatTable threats={threats} />
      <RecentEvents events={events} />
    </div>
  );
}