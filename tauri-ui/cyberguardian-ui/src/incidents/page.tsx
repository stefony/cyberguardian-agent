"use client";

import { useState, useEffect, useCallback } from "react";
import { Shield, AlertTriangle, Activity, Link, ChevronDown, ChevronUp } from "lucide-react";
import { processMonitorApi } from "@/lib/api";
import ProtectedRoute from "@/components/ProtectedRoute";

type Incident = {
  incident_id: string;
  event_count: number;
  first_seen: string;
  last_seen: string;
  pids: number[];
  types: string[];
  matched_chain: string | null;
  description: string;
  response_level: string;
  confidence_score: number;
  mitre_techniques: string[];
  suppressed: boolean;
  fp_score: number;
  fp_reasons: string[];
  events: any[];
};

const RESPONSE_LEVEL_COLORS: Record<string, string> = {
  observe:         "text-gray-400 bg-gray-500/10 border-gray-500/30",
  alert:           "text-blue-400 bg-blue-500/10 border-blue-500/30",
  suspicious:      "text-yellow-400 bg-yellow-500/10 border-yellow-500/30",
  high_confidence: "text-orange-400 bg-orange-500/10 border-orange-500/30",
  auto_response:   "text-red-400 bg-red-500/10 border-red-500/30",
};

const RESPONSE_LEVEL_LABELS: Record<string, string> = {
  observe:         "👁 Observe",
  alert:           "🔔 Alert",
  suspicious:      "⚠️ Suspicious",
  high_confidence: "🎯 High Confidence",
  auto_response:   "🚫 Auto-Response",
};

export default function IncidentsPage() {
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [stats, setStats] = useState<any>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const fetchIncidents = useCallback(async () => {
    try {
      const response = await fetch(
        `${import.meta.env.VITE_API_URL || ""}/api/correlation/incidents`,
        {
          headers: {
            Authorization: `Bearer ${localStorage.getItem("access_token")}`,
          },
        }
      );
      const data = await response.json();
      if (data.success) setIncidents(data.incidents || []);
    } catch (err) {
      console.error("Error fetching incidents:", err);
    }
  }, []);

  const fetchStats = useCallback(async () => {
    try {
      const response = await fetch(
        `${import.meta.env.VITE_API_URL || ""}/api/correlation/stats`,
        {
          headers: {
            Authorization: `Bearer ${localStorage.getItem("access_token")}`,
          },
        }
      );
      const data = await response.json();
      if (data.success) setStats(data.statistics);
    } catch (err) {
      console.error("Error fetching stats:", err);
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchIncidents();
    fetchStats();
    const interval = setInterval(() => {
      fetchIncidents();
      fetchStats();
    }, 30000);
    return () => clearInterval(interval);
  }, [fetchIncidents, fetchStats]);

  return (
    <ProtectedRoute>
      <main className="pb-12">
        {/* Hero */}
        <div className="page-container page-hero pt-12 md:pt-16">
          <div>
            <h1 className="heading-accent gradient-cyber text-3xl md:text-4xl font-bold tracking-tight">
              Correlated Incidents
            </h1>
            <p className="mt-2 text-muted-foreground">
              Attack chain reasoning — isolated signals connected into incidents
            </p>
          </div>
        </div>

        {/* Stats */}
        {stats && (
          <div className="section">
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <div className="card-premium p-5">
                <div className="text-sm text-muted-foreground mb-1">Active Incidents</div>
                <div className="text-2xl font-bold text-red-500">{stats.active_incidents}</div>
              </div>
              <div className="card-premium p-5">
                <div className="text-sm text-muted-foreground mb-1">Auto-Response</div>
                <div className="text-2xl font-bold text-orange-500">{stats.auto_response_count}</div>
              </div>
              <div className="card-premium p-5">
                <div className="text-sm text-muted-foreground mb-1">High Confidence</div>
                <div className="text-2xl font-bold text-yellow-500">{stats.high_confidence_count}</div>
              </div>
              <div className="card-premium p-5">
                <div className="text-sm text-muted-foreground mb-1">Suppressed (FP)</div>
                <div className="text-2xl font-bold text-gray-400">{stats.suppressed_count}</div>
              </div>
            </div>
          </div>
        )}

        {/* Incidents List */}
        <div className="section">
          <div className="bg-card border border-border rounded-lg p-6">
            <h2 className="text-xl font-semibold mb-6 flex items-center gap-2">
              <Link className="h-5 w-5 text-purple-500" />
              Active Incidents
            </h2>

            {isLoading ? (
              <div className="text-center py-12">
                <Activity className="h-8 w-8 animate-spin mx-auto text-purple-500" />
                <p className="mt-4 text-muted-foreground">Loading incidents...</p>
              </div>
            ) : incidents.length === 0 ? (
              <div className="text-center py-12">
                <Shield className="h-8 w-8 mx-auto text-green-500 mb-3" />
                <p className="text-muted-foreground">No active incidents — system is clean</p>
              </div>
            ) : (
              <div className="space-y-3">
                {incidents.map((incident) => (
                  <div
                    key={incident.incident_id}
                    className="border border-border rounded-lg overflow-hidden"
                  >
                    {/* Incident Header */}
                    <div
                      className="p-4 flex items-center justify-between cursor-pointer hover:bg-muted/30 transition-colors"
                      onClick={() => setExpandedId(
                        expandedId === incident.incident_id ? null : incident.incident_id
                      )}
                    >
                      <div className="flex items-center gap-4">
                        <span className="font-mono text-sm text-muted-foreground">
                          {incident.incident_id}
                        </span>
                        <span className={`px-3 py-1 rounded-full text-xs font-semibold border ${RESPONSE_LEVEL_COLORS[incident.response_level] || ""}`}>
                          {RESPONSE_LEVEL_LABELS[incident.response_level] || incident.response_level}
                        </span>
                        <span className="font-semibold">
                          {incident.matched_chain || incident.description}
                        </span>
                      </div>
                      <div className="flex items-center gap-4">
                        <div className="text-right">
  <div className="text-sm font-bold text-purple-400">
    {incident.confidence_score.toFixed(0)}%
  </div>
  <div className="text-xs text-muted-foreground">confidence</div>
</div>
<div className="text-right">
  <div className={`text-sm font-bold ${
    incident.fp_score >= 70 ? "text-green-400" :
    incident.fp_score >= 50 ? "text-yellow-400" :
    incident.fp_score >= 30 ? "text-orange-400" :
    "text-red-400"
  }`}>
    FP {incident.fp_score?.toFixed(0) ?? 0}%
  </div>
  <div className="text-xs text-muted-foreground">fp risk</div>
</div>
                        <div className="text-sm text-muted-foreground">
                          {incident.event_count} events
                        </div>
                        {expandedId === incident.incident_id
                          ? <ChevronUp className="h-4 w-4" />
                          : <ChevronDown className="h-4 w-4" />
                        }
                      </div>
                    </div>

                    {/* Expanded Details */}
                    {expandedId === incident.incident_id && (
                      <div className="border-t border-border p-4 bg-muted/10 space-y-4">
                        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                          <div>
                            <div className="text-muted-foreground mb-1">Description</div>
                            <div>{incident.description}</div>
                          </div>
                          <div>
                            <div className="text-muted-foreground mb-1">PIDs</div>
                            <div className="font-mono">{incident.pids.join(", ") || "—"}</div>
                          </div>
                          <div>
                            <div className="text-muted-foreground mb-1">MITRE</div>
                            <div className="flex flex-wrap gap-1">
                              {incident.mitre_techniques.map((t) => (
                                <span key={t} className="px-2 py-0.5 rounded bg-orange-500/10 text-orange-400 text-xs">
                                  {t}
                                </span>
                              ))}
                            </div>
                          </div>
                          <div>
  <div className="text-muted-foreground mb-1">First Seen</div>
  <div>{new Date(incident.first_seen).toLocaleString()}</div>
</div>
{incident.fp_reasons && incident.fp_reasons.length > 0 && (
  <div className="col-span-2 md:col-span-4">
    <div className="text-muted-foreground mb-1">FP Risk Reasons</div>
    <div className="flex flex-wrap gap-2">
      {incident.fp_reasons.map((reason, i) => (
        <span key={i} className="px-2 py-0.5 rounded bg-green-500/10 text-green-400 text-xs border border-green-500/20">
          ✓ {reason}
        </span>
      ))}
    </div>
  </div>
)}
                        </div>

                        {/* Events */}
                        {incident.events.length > 0 && (
                          <div>
                            <div className="text-sm font-semibold mb-2">Events in chain:</div>
                            <div className="space-y-1">
                              {incident.events.map((event, i) => (
                                <div key={i} className="flex items-center gap-3 text-xs p-2 rounded bg-muted/20">
                                  <span className={`px-2 py-0.5 rounded font-semibold ${
                                    event.severity === "critical" ? "bg-red-500/20 text-red-400" :
                                    event.severity === "high" ? "bg-orange-500/20 text-orange-400" :
                                    "bg-yellow-500/20 text-yellow-400"
                                  }`}>
                                    {event.severity}
                                  </span>
                                  <span className="text-muted-foreground">{event.type}</span>
                                  <span>{event.description}</span>
                                </div>
                              ))}
                            </div>
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </main>
    </ProtectedRoute>
  );
}