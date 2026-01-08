"use client";

import { useEffect, useState } from "react";
import {
  Shield,
  ToggleLeft,
  ToggleRight,
  FolderOpen,
  RefreshCw,
  AlertTriangle,
  CheckCircle,
  BarChart3,
  Clock,
  FileSearch,
} from "lucide-react";
import { protectionApi } from "@/lib/api";
import ExclusionsManager from '@/components/ExclusionsManager'
import SensitivityProfiles from '@/components/SensitivityProfiles'
import ProtectedRoute from '@/components/ProtectedRoute';

export default function ProtectionPage() {
  const [enabled, setEnabled] = useState(false);
  const [paths, setPaths] = useState<string>("");
  const [autoQuarantine, setAutoQuarantine] = useState(false);
  const [threatThreshold, setThreatThreshold] = useState(80);
  const [events, setEvents] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [toggling, setToggling] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const [stats, setStats] = useState({
    files_scanned: 0,
    threats_detected: 0,
    uptime_seconds: 0,
    last_scan: null,
  });

  useEffect(() => {
    loadStatus();
    loadEvents();
    loadStats();
  }, []);

const loadStatus = async () => {
  try {
    const res = await protectionApi.getStatus();
    console.log("🟣 STATUS RESPONSE:", res);

    const ok =
      (typeof res?.success === "boolean" ? res.success : true) && (res?.data || res);
    const data = res?.data ?? res;

    if (ok && data) {
      console.log("🔵 BEFORE setEnabled:", enabled);
      setEnabled(!!data.enabled);
      console.log("🔵 AFTER setEnabled, new value:", !!data.enabled);
      
      const pathStr = Array.isArray(data.paths) ? data.paths.join("; ") : (data.paths || "");
      setPaths(pathStr);
      setAutoQuarantine(!!(data.auto_quarantine ?? data.autoQuarantine));
      setThreatThreshold(Number(data.threat_threshold ?? data.threatThreshold ?? 80));
    }
  } catch (err) {
    console.error("❌ Error loading status:", err);
  } finally {
    setLoading(false);
  }
};

  const loadEvents = async (limit = 100) => {
    try {
      const res = await protectionApi.getEvents(limit);
      console.log("🟣 EVENTS RESPONSE:", res);

      const data = Array.isArray(res?.data)
        ? res.data
        : Array.isArray(res)
        ? res
        : [];

      setEvents(data);
    } catch (err) {
      console.error("❌ Error loading events:", err);
      setEvents([]);
    }
  };

  const loadStats = async () => {
    try {
      const res = await protectionApi.getStats();
      if (res.success && res.data) {
        setStats(res.data);
      }
    } catch (err) {
      console.error("❌ Error loading stats:", err);
    }
  };

const saveSettings = async (newAutoQuarantine?: boolean, newThreshold?: number) => {
  try {
    console.log("💾 Saving settings:", {
      autoQuarantine: newAutoQuarantine ?? autoQuarantine,
      threatThreshold: newThreshold ?? threatThreshold,
    });

    const res = await protectionApi.updateSettings(
      newAutoQuarantine ?? autoQuarantine,
      newThreshold ?? threatThreshold
    );

    console.log("✅ Settings saved:", res);
  } catch (err) {
    console.error("❌ Error saving settings:", err);
  }
};

  const refresh = async () => {
    console.log("🔄 REFRESH CLICKED");
    setRefreshing(true);
    await loadEvents();
    await loadStats();
    setRefreshing(false);
  };

  const formatUptime = (seconds: number | null | undefined) => {
    if (!seconds || isNaN(seconds)) return "00:00:00";
    
    const hours = Math.floor(seconds / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    const secs = seconds % 60;
    return `${hours.toString().padStart(2, "0")}:${minutes.toString().padStart(2, "0")}:${secs.toString().padStart(2, "0")}`;
  };

 const toggle = async () => {
  console.log("🔵 TOGGLE CLICKED!", {
    enabled,
    paths,
    autoQuarantine,
    threatThreshold,
  });

  setToggling(true);
  try {
    // Parse paths from input field
    const pathList = paths
      .split(";")
      .map((s) => s.trim())
      .filter(Boolean);

    console.log("🔵 PATH LIST:", pathList);

    // Toggle protection
    const res = await protectionApi.toggle(
      !enabled,
      pathList.length > 0 ? pathList : [],
      autoQuarantine,
      threatThreshold
    );

    console.log("🔵 API RESPONSE:", res);

    // ← НОВ КОД: Refresh status from backend instead of using response
    await loadStatus();
    
    // Refresh stats if enabled
    if (!enabled) {  // If we just enabled it (was false, now true)
      setTimeout(() => {
        refresh();
      }, 2000);
    } else {
      // Reset stats when disabled
      setStats({
        files_scanned: 0,
        threats_detected: 0,
        uptime_seconds: 0,
        last_scan: null,
      });
    }
  } catch (err) {
    console.error("❌ Error toggling protection:", err);
  } finally {
    setToggling(false);
  }
};

  const getSeverityColor = (level: string) => {
    switch (level?.toLowerCase()) {
      case "critical":
        return "text-red-500";
      case "high":
        return "text-orange-500";
      case "medium":
        return "text-yellow-500";
      case "low":
        return "text-green-500";
      default:
        return "text-gray-500";
    }
  };

  const getSeverityBg = (level: string) => {
    switch (level?.toLowerCase()) {
      case "critical":
        return "bg-red-500/10 border-red-500/30";
      case "high":
        return "bg-orange-500/10 border-orange-500/30";
      case "medium":
        return "bg-yellow-500/10 border-yellow-500/30";
      case "low":
        return "bg-green-500/10 border-green-500/30";
      default:
        return "bg-gray-500/10 border-gray-500/30";
    }
  };

  if (loading) {
    return (
      <ProtectedRoute>
      <main className="pb-12">
        <div className="flex items-center justify-center h-screen">
          <RefreshCw className="h-8 w-8 animate-spin text-primary" />
        </div>
      </main>
        </ProtectedRoute>
    );
  }

  return (
      <ProtectedRoute>
    <main className="pb-12">
      {/* Hero */}
      <div className="page-container page-hero pt-12 md:pt-16">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="heading-accent gradient-cyber text-3xl md:text-4xl font-bold tracking-tight">
              Real-Time Protection
            </h1>
            <p className="mt-2 text-muted-foreground">
              File system monitoring with ML-powered threat detection
            </p>
          </div>

          <button
            onClick={refresh}
            disabled={refreshing}
            className="btn btn-primary relative z-10 pointer-events-auto transition-all duration-200 hover:scale-105 active:scale-95 hover:shadow-lg hover:shadow-purple-500/50"
          >
            <RefreshCw className={`h-4 w-4 ${refreshing ? "animate-spin" : ""}`} />
            Refresh
          </button>
        </div>
      </div>

      {/* Status Cards */}
      <div className="section">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {/* Protection Status */}
          <div className="card-premium p-6 transition-all duration-300 hover:scale-[1.02] hover:shadow-xl hover:shadow-purple-500/20 relative">
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-3">
                <Shield
                  className={`h-6 w-6 ${
                    enabled ? "text-green-500" : "text-orange-500"
                  }`}
                />
                <span className="font-semibold text-lg">Protection Status</span>
              </div>
              <button
                onClick={(e) => {
                  e.stopPropagation();
                  console.log("🟢 BUTTON CLICKED - EVENT FIRED!");
                  toggle();
                }}
                disabled={toggling}
                className={`p-2 rounded-lg transition-all duration-200 z-50 pointer-events-auto cursor-pointer transform hover:scale-110 active:scale-95 ${
                  enabled
                    ? "bg-green-500/10 hover:bg-green-500/20 hover:shadow-lg hover:shadow-green-500/50"
                    : "bg-orange-500/10 hover:bg-orange-500/20 hover:shadow-lg hover:shadow-orange-500/50"
                }`}
                style={{ position: 'relative', zIndex: 9999 }}
              >
                {enabled ? (
                  <ToggleRight className="h-6 w-6 text-green-500" />
                ) : (
                  <ToggleLeft className="h-6 w-6 text-orange-500" />
                )}
              </button>
            </div>
            <div
              className={`text-2xl font-bold ${
                enabled ? "text-green-500" : "text-orange-500"
              }`}
            >
              {enabled ? "ACTIVE" : "DISABLED"}
            </div>
            <p className="text-sm text-muted-foreground mt-2">
              {enabled
                ? "File system is being monitored"
                : "Click to enable protection"}
            </p>
          </div>

          {/* Watch Paths */}
          <div className="card-premium p-6 transition-all duration-300 hover:scale-[1.02] hover:shadow-xl hover:shadow-blue-500/20 relative">
            <div className="flex items-center gap-3 mb-4">
              <FolderOpen className="h-6 w-6 text-blue-500" />
              <span className="font-semibold text-lg">Watch Paths</span>
            </div>
            <input
              type="text"
              value={paths}
              onChange={(e) => setPaths(e.target.value)}
              placeholder="C:\\Users\\Downloads; D:\\Projects"
              className="w-full px-3 py-2 rounded-lg bg-card border-2 border-border text-foreground focus:border-blue-500 focus:outline-none relative z-50"
              style={{ pointerEvents: 'auto' }}
            />
            <p className="text-xs text-muted-foreground mt-2">
              Separate multiple paths with semicolon (;)
            </p>
          </div>

          {/* Settings */}
          <div className="card-premium p-6 transition-all duration-300 hover:scale-[1.02] hover:shadow-xl hover:shadow-cyan-500/20 relative">
            <div className="flex items-center gap-3 mb-4">
              <AlertTriangle className="h-6 w-6 text-cyan-500" />
              <span className="font-semibold text-lg">Settings</span>
            </div>
            <div className="space-y-3">
              <label className="flex items-center justify-between cursor-pointer group">
                <span className="text-sm">Auto-Quarantine</span>
                <div className="relative">
                  <input
                    type="checkbox"
                    checked={autoQuarantine}
                    onChange={async (e) => {
                      const newValue = e.target.checked;
                      setAutoQuarantine(newValue);
                      saveSettings(newValue, undefined);
                    }}
                    className="peer sr-only"
                  />
                  <div className={`
                    w-5 h-5 rounded border-2 flex items-center justify-center
                    transition-all duration-200
                    ${enabled 
                      ? 'border-border/50 bg-card/50 cursor-not-allowed' 
                      : 'border-border bg-card cursor-pointer hover:border-purple-500'
                    }
                    ${autoQuarantine 
                      ? 'bg-purple-600 border-purple-600' 
                      : ''
                    }
                    peer-focus:ring-2 peer-focus:ring-purple-500/50
                  `}>
                    {autoQuarantine && (
                      <svg 
                        className="w-3 h-3 text-white" 
                        fill="none" 
                        strokeLinecap="round" 
                        strokeLinejoin="round" 
                        strokeWidth="3" 
                        viewBox="0 0 24 24" 
                        stroke="currentColor"
                      >
                        <path d="M5 13l4 4L19 7"></path>
                      </svg>
                    )}
                  </div>
                </div>
              </label>
              <div>
                <label className="text-sm block mb-1">Threat Threshold</label>
                <input
                  type="number"
                  value={threatThreshold}
                   onChange={(e) => {
                    const newValue = Number(e.target.value);
                    setThreatThreshold(newValue);
                    saveSettings(undefined, newValue);
                  }}
                  min={0}
                  max={100}
                  className="w-full px-3 py-1 rounded-lg bg-card border-2 border-border text-foreground focus:border-cyan-500 focus:outline-none relative z-50"
                  style={{ pointerEvents: 'auto' }}
                />
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Statistics Card */}
      <div className="section">
        <div className="card-premium p-6 transition-all duration-300 hover:scale-[1.01] hover:shadow-xl hover:shadow-purple-500/20">
          <h2 className="text-xl font-bold mb-4 flex items-center gap-2">
            <BarChart3 className="h-5 w-5 text-purple-500" />
            Protection Statistics
          </h2>
          
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            {/* Files Scanned */}
            <div className="p-4 bg-card/50 rounded-lg border border-border/50">
              <div className="flex items-center gap-2 mb-2">
                <FileSearch className="h-4 w-4 text-blue-400" />
                <span className="text-sm text-muted-foreground">Files Scanned</span>
              </div>
              <div className="text-2xl font-bold text-blue-400">
                {(stats.files_scanned || 0).toLocaleString()}
              </div>
            </div>

            {/* Threats Detected */}
            <div className="p-4 bg-card/50 rounded-lg border border-border/50">
              <div className="flex items-center gap-2 mb-2">
                <AlertTriangle className="h-4 w-4 text-red-400" />
                <span className="text-sm text-muted-foreground">Threats Detected</span>
              </div>
              <div className="text-2xl font-bold text-red-400">
                {(stats.threats_detected || 0).toLocaleString()}
              </div>
            </div>

            {/* Uptime */}
            <div className="p-4 bg-card/50 rounded-lg border border-border/50">
              <div className="flex items-center gap-2 mb-2">
                <Clock className="h-4 w-4 text-green-400" />
                <span className="text-sm text-muted-foreground">Uptime</span>
              </div>
              <div className="text-2xl font-bold font-mono text-green-400">
                {enabled ? formatUptime(stats.uptime_seconds) : "00:00:00"}
              </div>
            </div>

            {/* Last Scan */}
            <div className="p-4 bg-card/50 rounded-lg border border-border/50">
              <div className="flex items-center gap-2 mb-2">
                <CheckCircle className="h-4 w-4 text-purple-400" />
                <span className="text-sm text-muted-foreground">Last Scan</span>
              </div>
              <div className="text-sm font-mono text-purple-400">
                {stats.last_scan 
                  ? new Date(stats.last_scan).toLocaleTimeString() 
                  : "—"}
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Events Table */}
      <div className="section">
        <div className="card-premium p-6">
          <h2 className="text-xl font-bold mb-4 flex items-center gap-2">
            <CheckCircle className="h-5 w-5 text-purple-500" />
            File System Events ({events.length})
          </h2>

          <div className="overflow-x-auto">
            <table className="table w-full">
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Event</th>
                  <th>File Path</th>
                  <th>Size</th>
                  <th>Threat Score</th>
                  <th>Level</th>
                </tr>
              </thead>
              <tbody>
                {events.length === 0 ? (
                  <tr>
                    <td
                      colSpan={6}
                      className="text-center py-8 text-muted-foreground"
                    >
                      {enabled
                        ? "No events yet. Create or modify a file in watched directories."
                        : "Enable protection to start monitoring files."}
                    </td>
                  </tr>
                ) : (
                  events.map((ev, idx) => (
                    <tr key={idx}>
                      <td className="font-mono text-sm">
                        {new Date(ev.timestamp).toLocaleTimeString()}
                      </td>
                      <td>
                        <span className="badge badge--info">
                          {ev.event_type}
                        </span>
                      </td>
                      <td
                        className="font-mono text-xs truncate max-w-xs"
                        title={ev.file_path}
                      >
                        {ev.file_path}
                      </td>
                      <td className="text-sm">
                        {ev.file_size
                          ? `${(ev.file_size / 1024).toFixed(1)} KB`
                          : "—"}
                      </td>
                      <td
                        className={`font-bold ${getSeverityColor(
                          ev.threat_level
                        )}`}
                      >
                        {Math.round(ev.threat_score || 0)}
                      </td>
                      <td>
                        <span
                          className={`badge border-2 ${getSeverityBg(
                            ev.threat_level
                          )}`}
                        >
                          {ev.threat_level?.toUpperCase() || "UNKNOWN"}
                        </span>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      {/* Exclusions Management */}
      <div className="section">
        <div className="mb-6">
          <h2 className="text-2xl font-bold mb-2 flex items-center gap-3">
            <div className="p-2 bg-gradient-to-br from-purple-500 to-cyan-500 rounded-lg">
              <Shield className="h-6 w-6 text-white" />
            </div>
            <span className="bg-gradient-to-r from-purple-400 to-cyan-400 bg-clip-text text-transparent">
              Exclusions Manager
            </span>
          </h2>
          <p className="text-muted-foreground ml-14">
            Configure files, folders, extensions, and processes to exclude from real-time scanning
          </p>
        </div>
        <ExclusionsManager />
      </div>
      {/* Sensitivity Profiles */}
      <div className="section">
        <div className="mb-6">
          <h2 className="text-2xl font-bold mb-2 flex items-center gap-3">
            <div className="p-2 bg-gradient-to-br from-yellow-500 to-orange-500 rounded-lg">
              <Shield className="h-6 w-6 text-white" />
            </div>
            <span className="bg-gradient-to-r from-yellow-400 to-orange-400 bg-clip-text text-transparent">
              Sensitivity Profiles
            </span>
          </h2>
          <p className="text-muted-foreground ml-14">
            Adjust threat detection sensitivity based on your security requirements
          </p>
        </div>
        <SensitivityProfiles />
      </div>
    </main>
    </ProtectedRoute>
  );
}