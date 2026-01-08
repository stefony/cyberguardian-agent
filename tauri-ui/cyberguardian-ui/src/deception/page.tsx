"use client";

import { useEffect, useState } from "react";
import { Shield, Activity, AlertTriangle, Eye, Power, PowerOff, Filter } from "lucide-react";
import { deceptionApi } from "@/lib/api";
import type { HoneypotResponse } from "@/lib/types";
import ProtectedRoute from '@/components/ProtectedRoute';


export default function DeceptionPage() {
  const [honeypots, setHoneypots] = useState<HoneypotResponse[]>([]);
const [logs, setLogs] = useState<any[]>([]);
const [status, setStatus] = useState<any>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  
  // Filters
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const [typeFilter, setTypeFilter] = useState<string>("all");

  // Fetch status
 const fetchStatus = async () => {
  try {
    const response = await deceptionApi.getStatus();
    if (response.success && response.data) {
      setStatus(response.data);
    }
  } catch (err) {
    console.error("Error fetching status:", err);
  }
};

  // Fetch honeypots
const fetchHoneypots = async () => {
  try {
    setIsLoading(true);
    
    const response = await deceptionApi.getHoneypots();
    
    if (response.success && response.data) {
      // Apply filters on client side
      let filtered = response.data;
      if (statusFilter !== "all") {
        filtered = filtered.filter((h: any) => h.status === statusFilter);
      }
      if (typeFilter !== "all") {
        filtered = filtered.filter((h: any) => h.type === typeFilter);
      }
      
      setHoneypots(filtered || []);
      setError(null);
    } else {
      setError(response.error || "Failed to fetch honeypots");
    }
  } catch (err) {
    console.error("Error fetching honeypots:", err);
    setError("Could not load honeypots");
  } finally {
    setIsLoading(false);
  }
};

  // Fetch logs
const fetchLogs = async () => {
  try {
    const response = await deceptionApi.getLogs(20);
    if (response.success && response.data) {
      setLogs(response.data || []);
    }
  } catch (err) {
    console.error("Error fetching logs:", err);
  }
};

  // Toggle honeypot status
const toggleHoneypot = async (honeypot: HoneypotResponse) => {
  const action = honeypot.status === "active" ? "deactivate" : "activate";
  
  try {
    const response = await deceptionApi.toggleHoneypot(Number(honeypot.id), action);
    
    if (response.success) {
      // Refresh data
      await fetchHoneypots();
      await fetchStatus();
      
      alert(`Honeypot ${honeypot.name} ${action}d successfully!`);
    } else {
      alert(response.error || `Failed to ${action} honeypot`);
    }
  } catch (err) {
    console.error(`Error toggling honeypot:`, err);
    alert(`Failed to toggle honeypot`);
  }
};

  // Initial load
  useEffect(() => {
    fetchHoneypots();
    fetchLogs();
    fetchStatus();
  }, [statusFilter, typeFilter]);

  // Format timestamp
  const formatTime = (timestamp: string) => {
    const date = new Date(timestamp);
    return date.toLocaleString("en-US", { 
      month: "short", 
      day: "numeric", 
      hour: "2-digit", 
      minute: "2-digit" 
    });
  };

  // Type badge styling
  const getTypeBadge = (type: string) => {
    const badges: Record<string, string> = {
      ssh: "badge badge--warn",
      ftp: "badge badge--info",
      http: "badge badge--ok",
      smb: "badge",
      database: "badge badge--err"
    };
    return badges[type] || "badge";
  };

  // Status badge styling
  const getStatusBadge = (status: string) => {
    const badges: Record<string, string> = {
      active: "badge badge--ok",
      inactive: "badge",
      compromised: "badge badge--err"
    };
    return badges[status] || "badge";
  };

  return (
    <ProtectedRoute>
    <main className="pb-12">
      {/* Hero */}
      <div className="page-container page-hero pt-12 md:pt-16">
        <div>
          <h1 className="heading-accent gradient-cyber text-3xl md:text-4xl font-bold tracking-tight">
            Deception Layer
          </h1>
          <p className="mt-2 text-muted-foreground">
            Honeypots and decoy systems to trap and analyze attackers
          </p>
        </div>
      </div>

      {/* Status Cards */}
      {status && (
        <div className="section">
          <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
            <div className="card-premium p-5 transition-all duration-300 hover:scale-105 hover:shadow-lg hover:shadow-purple-500/30">
              <div className="flex items-center gap-3 mb-2">
                <Shield className="h-5 w-5 text-purple-500" />
                <div className="text-sm text-muted-foreground">Total Honeypots</div>
              </div>
              <div className="text-2xl font-bold text-purple-500">
                {status.total_honeypots}
              </div>
            </div>

            <div className="card-premium p-5 transition-all duration-300 hover:scale-105 hover:shadow-lg hover:shadow-purple-500/30">
              <div className="flex items-center gap-3 mb-2">
                <Activity className="h-5 w-5 text-green-500" />
                <div className="text-sm text-muted-foreground">Active Traps</div>
              </div>
              <div className="text-2xl font-bold text-green-500">
                {status.active_honeypots}
              </div>
            </div>

            <div className="card-premium p-5 transition-all duration-300 hover:scale-105 hover:shadow-lg hover:shadow-purple-500/30">
              <div className="flex items-center gap-3 mb-2">
                <Eye className="h-5 w-5 text-blue-500" />
                <div className="text-sm text-muted-foreground">Total Interactions</div>
              </div>
              <div className="text-2xl font-bold text-blue-500">
                {status.total_interactions}
              </div>
            </div>

            <div className="card-premium p-5 transition-all duration-300 hover:scale-105 hover:shadow-lg hover:shadow-purple-500/30">
              <div className="flex items-center gap-3 mb-2">
                <AlertTriangle className="h-5 w-5 text-yellow-500" />
                <div className="text-sm text-muted-foreground">Today</div>
              </div>
              <div className="text-2xl font-bold text-yellow-500">
                {status.interactions_today}
              </div>
            </div>

            <div className="card-premium p-5 transition-all duration-300 hover:scale-105 hover:shadow-lg hover:shadow-purple-500/30">
              <div className="flex items-center gap-3 mb-2">
                <AlertTriangle className="h-5 w-5 text-red-500" />
                <div className="text-sm text-muted-foreground">Compromised</div>
              </div>
              <div className="text-2xl font-bold text-red-500">
                {status.compromised_honeypots}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Filters */}
      <div className="section">
        <div className="flex flex-wrap items-center gap-4 mb-6">
          <h2 className="text-xl font-semibold">Active Honeypots</h2>

        <select
  value={typeFilter}
  onChange={(e) => setTypeFilter(e.target.value)}
  className="px-4 py-2 rounded-lg bg-card border-2 border-border text-foreground ml-auto transition-all duration-300 hover:border-purple-400 hover:bg-purple-500/5 focus:outline-none focus:ring-2 focus:ring-purple-500 cursor-pointer relative z-50"
  style={{ 
    pointerEvents: 'auto',
    colorScheme: 'dark'
  }}
>
  <option value="all" className="bg-[#0a0e27] text-white">All Types</option>
  <option value="ssh" className="bg-[#0a0e27] text-white">SSH</option>
  <option value="ftp" className="bg-[#0a0e27] text-white">FTP</option>
  <option value="http" className="bg-[#0a0e27] text-white">HTTP</option>
  <option value="smb" className="bg-[#0a0e27] text-white">SMB</option>
  <option value="database" className="bg-[#0a0e27] text-white">Database</option>
</select>

     <select
  value={statusFilter}
  onChange={(e) => setStatusFilter(e.target.value)}
  className="px-4 py-2 rounded-lg bg-card border-2 border-border text-foreground transition-all duration-300 hover:border-cyan-400 hover:bg-cyan-500/5 focus:outline-none focus:ring-2 focus:ring-cyan-500 cursor-pointer relative z-50"
  style={{ 
    pointerEvents: 'auto',
    colorScheme: 'dark'
  }}
>
  <option value="all" className="bg-[#0a0e27] text-white">All Statuses</option>
  <option value="active" className="bg-[#0a0e27] text-white">Active</option>
  <option value="inactive" className="bg-[#0a0e27] text-white">Inactive</option>
  <option value="compromised" className="bg-[#0a0e27] text-white">Compromised</option>
</select>
        </div>

        {/* Honeypot Cards */}
        {isLoading ? (
          <div className="text-center py-12">
            <Activity className="h-8 w-8 animate-spin mx-auto text-primary" />
            <p className="mt-4 text-muted-foreground">Loading honeypots...</p>
          </div>
        ) : error ? (
          <div className="text-center py-12">
            <AlertTriangle className="h-8 w-8 mx-auto text-red-500" />
            <p className="mt-4 text-red-500">{error}</p>
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {honeypots.map((honeypot) => (
                <div 
                 key={honeypot.id} 
                className="card-premium p-6 transition-all duration-300 hover:scale-[1.02] hover:shadow-2xl hover:shadow-purple-500/20"
  >
                <div className="flex items-start justify-between mb-4">
                  <div className="flex-1">
                    <h3 className="text-lg font-semibold mb-1">{honeypot.name}</h3>
                    <div className="flex gap-2 mb-2">
                      <span className={getTypeBadge(honeypot.type)}>
                        {honeypot.type.toUpperCase()}
                      </span>
                      <span className={getStatusBadge(honeypot.status)}>
                        {honeypot.status}
                      </span>
                    </div>
                  </div>
                  
                  <button
                    onClick={() => toggleHoneypot(honeypot)}
                    className={`
                      relative p-2 rounded-lg transition-all duration-300 
                      transform hover:scale-110 hover:shadow-lg
                      ${
                        honeypot.status === "active"
                          ? "bg-red-500/10 text-red-500 hover:bg-red-500/20 hover:shadow-red-500/50"
                          : "bg-green-500/10 text-green-500 hover:bg-green-500/20 hover:shadow-green-500/50"
                      }
                      ${honeypot.status === "active" ? "animate-pulse" : ""}
                    `}
                    title={honeypot.status === "active" ? "Deactivate" : "Activate"}
                  >
                    {honeypot.status === "active" ? (
                      <PowerOff className="h-5 w-5" />
                    ) : (
                      <Power className="h-5 w-5" />
                    )}
                  </button>
                </div>

                <p className="text-sm text-muted-foreground mb-4">
                  {honeypot.description}
                </p>

                <div className="grid grid-cols-2 gap-4 text-sm">
                  <div>
                    <div className="text-muted-foreground">IP Address</div>
                    <div className="font-mono">{honeypot.ip_address}</div>
                  </div>
                  <div>
                    <div className="text-muted-foreground">Port</div>
                    <div className="font-mono">{honeypot.port}</div>
                  </div>
                  <div>
                    <div className="text-muted-foreground">Interactions</div>
                    <div className="font-bold text-yellow-500">{honeypot.interactions}</div>
                  </div>
                  <div>
                    <div className="text-muted-foreground">Last Activity</div>
                    <div className="text-xs">
                      {honeypot.last_interaction ? formatTime(honeypot.last_interaction) : "Never"}
                    </div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Recent Logs */}
      <div className="section">
        <div className="card-premium p-6">
          <h2 className="text-xl font-semibold mb-6">Recent Interactions</h2>

          <div className="overflow-x-auto">
            <table className="table w-full">
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Source IP</th>
                  <th>Action</th>
                  <th>Details</th>
                </tr>
              </thead>
              <tbody>
                {logs.length === 0 ? (
                  <tr>
                    <td colSpan={4} className="text-center py-8 text-muted-foreground">
                      No interactions logged
                    </td>
                  </tr>
                ) : (
                  logs.map((log) => (
                    <tr key={log.id}>
                      <td className="text-sm">{formatTime(log.timestamp)}</td>
                      <td className="font-mono text-sm text-blue-400">{log.source_ip}</td>
                      <td>
                        <span className="badge badge--warn">{log.action}</span>
                      </td>
                      <td className="text-sm text-muted-foreground">
                        {log.details ? (
                          <span>
                            {log.details.username && `User: ${log.details.username}`}
                            {log.details.attempts && ` (${log.details.attempts} attempts)`}
                            {log.details.method && `Method: ${log.details.method}`}
                            {log.details.credentials_tried && ` (${log.details.credentials_tried} credentials)`}
                          </span>
                        ) : (
                          "—"
                        )}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </main>
    </ProtectedRoute>
  );
}