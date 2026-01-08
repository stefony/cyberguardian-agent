import { useState, useEffect } from "react";
import "./App.css";

interface ProtectionStatus {
  monitoring: boolean;
  paths: string[];
}

interface FileEvent {
  event_type: string;
  path: string;
  timestamp: string;
  file_size: number | null;
  threat_score: number | null;
  threat_category: string | null;
}

function App() {
  const [status, setStatus] = useState<ProtectionStatus>({
    monitoring: false,
    paths: [],
  });
  const [events, setEvents] = useState<FileEvent[]>([]);

  // Poll Core Agent status every 5 seconds
  useEffect(() => {
    const fetchStatus = async () => {
      try {
        const response = await fetch("http://localhost:3000/status");
        const data = await response.json();
        setStatus(data);
      } catch (error) {
        console.error("Failed to fetch status:", error);
      }
    };

    fetchStatus();
    const interval = setInterval(fetchStatus, 5000);
    return () => clearInterval(interval);
  }, []);

  // Fetch events
  const fetchEvents = async () => {
    try {
      const response = await fetch("http://localhost:3000/events");
      const data = await response.json();
      setEvents(data);
    } catch (error) {
      console.error("Failed to fetch events:", error);
    }
  };

  useEffect(() => {
    fetchEvents();
    const interval = setInterval(fetchEvents, 5000);
    return () => clearInterval(interval);
  }, []);

  const startMonitoring = async () => {
    try {
      await fetch("http://localhost:3000/start-monitoring", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ paths: ["C:\\Users\\admin\\Downloads"] }),
      });
      fetchStatus();
    } catch (error) {
      console.error("Failed to start monitoring:", error);
    }
  };

  const stopMonitoring = async () => {
    try {
      await fetch("http://localhost:3000/stop-monitoring", {
        method: "POST",
      });
      fetchStatus();
    } catch (error) {
      console.error("Failed to stop monitoring:", error);
    }
  };

  return (
    <div className="container">
      <h1>CyberGuardian XDR</h1>

      {/* Protection Status */}
      <div className="card">
        <h2>Protection Status</h2>
        <div className="status-indicator">
          <span className={`status-dot ${status.monitoring ? "active" : ""}`}></span>
          <span>{status.monitoring ? "MONITORING" : "STOPPED"}</span>
        </div>
        
        {status.monitoring && (
          <div className="paths-list">
            <h3>Monitored Paths:</h3>
            {status.paths.map((path, i) => (
              <div key={i} className="path-item">{path}</div>
            ))}
          </div>
        )}

        <div className="button-group">
          <button onClick={startMonitoring} disabled={status.monitoring}>
            Start Protection
          </button>
          <button onClick={stopMonitoring} disabled={!status.monitoring}>
            Stop Protection
          </button>
        </div>
      </div>

      {/* Recent Events */}
      <div className="card">
        <h2>Recent Events ({events.length})</h2>
        <div className="events-table">
          <table>
            <thead>
              <tr>
                <th>Time</th>
                <th>Event</th>
                <th>File</th>
                <th>Threat Score</th>
              </tr>
            </thead>
            <tbody>
              {events.slice(0, 10).map((event, i) => (
                <tr key={i}>
                  <td>{new Date(event.timestamp).toLocaleTimeString()}</td>
                  <td>{event.event_type}</td>
                  <td className="path-cell">{event.path}</td>
                  <td>
                    <span className={`threat-badge threat-${getThreatLevel(event.threat_score)}`}>
                      {event.threat_score ?? "N/A"}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

function getThreatLevel(score: number | null): string {
  if (score === null) return "unknown";
  if (score >= 70) return "high";
  if (score >= 30) return "medium";
  return "low";
}

export default App;