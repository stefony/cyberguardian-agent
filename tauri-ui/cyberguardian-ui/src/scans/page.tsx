"use client";

import { useEffect, useState } from "react";
import {
  Calendar,
  Play,
  Pause,
  Trash2,
  Plus,
  CheckCircle,
  XCircle,
  RefreshCw,
  BarChart3,
  Upload, 
} from "lucide-react";
import FileScanner from '@/components/FileScanner'
import { scansApi } from "@/lib/api";
import ScanProfiles from '@/components/ScanProfiles'
import ProtectedRoute from '@/components/ProtectedRoute';

export default function ScansPage() {
  const [schedules, setSchedules] = useState<any[]>([]);
  const [history, setHistory] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [refreshing, setRefreshing] = useState(false);

  // Create form state
  const [formData, setFormData] = useState({
    name: "",
    scan_type: "quick",
    target_path: "",
    schedule_type: "daily",
    interval_days: 1,
  });

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    setLoading(true);
    await Promise.all([loadSchedules(), loadHistory()]);
    setLoading(false);
  };

 const loadSchedules = async () => {
  try {
    const res = await scansApi.getSchedules();
    console.log("🔵 Schedules response:", res);
    
    if (res.success && res.data) {
      // Handle both nested and direct array responses
      const schedulesData = Array.isArray(res.data) 
        ? res.data 
        : (res.data as any)?.data || [];
      
      console.log("✅ Setting schedules:", schedulesData);
      setSchedules(schedulesData);
    } else {
      setSchedules([]);
    }
  } catch (err) {
    console.error("❌ Error loading schedules:", err);
    setSchedules([]);
  }
};

const loadHistory = async () => {
  try {
    const res = await scansApi.getHistory(20);
    console.log("🔍 History response:", res);
    console.log("🔍 res.data:", res.data);
    if (res.success && res.data) {
      console.log("🔍 Is array?", Array.isArray(res.data));
      console.log("🔍 Array length:", res.data.length);
      const historyData = (res.data as any)?.data || res.data;
      setHistory(Array.isArray(historyData) ? historyData : []);
    } else {
      console.log("❌ No success or no data");
      setHistory([]);
    }
  } catch (err) {
    console.error("Error loading history:", err);
    setHistory([]);
  }
};

  const refresh = async () => {
    setRefreshing(true);
    await loadData();
    setRefreshing(false);
  };

  const handleCreateSchedule = async (e: React.FormEvent) => {
    e.preventDefault();
    
    try {
      const res = await scansApi.createSchedule({
        ...formData,
        enabled: true,
      });

      if (res.success) {
        setShowCreateModal(false);
        setFormData({
          name: "",
          scan_type: "quick",
          target_path: "",
          schedule_type: "daily",
          interval_days: 1,
        });
        await loadSchedules();
      }
    } catch (err) {
      console.error("Error creating schedule:", err);
    }
  };

  const toggleSchedule = async (id: number, currentlyEnabled: boolean) => {
    try {
      await scansApi.updateSchedule(id, { enabled: !currentlyEnabled });
      await loadSchedules();
    } catch (err) {
      console.error("Error toggling schedule:", err);
    }
  };

  const deleteSchedule = async (id: number) => {
    if (!confirm("Are you sure you want to delete this schedule?")) return;

    try {
      await scansApi.deleteSchedule(id);
      await loadSchedules();
    } catch (err) {
      console.error("Error deleting schedule:", err);
    }
  };

  const runManualScan = async () => {
    const path = prompt("Enter path to scan:", "/tmp");
    if (!path) return;

    try {
      const res = await scansApi.runScan({
        scan_type: "quick",
        target_path: path,
      });

      if (res.success) {
        alert("Scan started! Check history for results.");
        setTimeout(loadHistory, 3000);
      }
    } catch (err) {
      console.error("Error starting scan:", err);
    }
  };

  const getStatusColor = (status: string) => {
    switch (status.toLowerCase()) {
      case "completed": return "text-green-500";
      case "running": return "text-blue-500";
      case "failed": return "text-red-500";
      default: return "text-gray-500";
    }
  };

  const getStatusBg = (status: string) => {
    switch (status.toLowerCase()) {
      case "completed": return "bg-green-500/10 border-green-500/30";
      case "running": return "bg-blue-500/10 border-blue-500/30";
      case "failed": return "bg-red-500/10 border-red-500/30";
      default: return "bg-gray-500/10 border-gray-500/30";
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
              Scheduled Scans
            </h1>
            <p className="mt-2 text-muted-foreground">
              Automate security scans with flexible scheduling
            </p>
          </div>

          <div className="flex gap-2">
            <button
              onClick={refresh}
              disabled={refreshing}
              className="btn btn-secondary"
            >
              <RefreshCw className={`h-4 w-4 ${refreshing ? "animate-spin" : ""}`} />
              Refresh
            </button>
            <button
              onClick={() => setShowCreateModal(true)}
              className="btn btn-primary"
            >
              <Plus className="h-4 w-4" />
              New Schedule
            </button>
            <button onClick={runManualScan} className="btn btn-success">
              <Play className="h-4 w-4" />
              Run Scan Now
            </button>
          </div>
        </div>
      </div>

      {/* File Scanner - Multi-Engine Detection */}
<div className="section">
  <div className="mb-6">
    <h2 className="text-2xl font-bold mb-2 flex items-center gap-3">
      <div className="p-2 bg-gradient-to-br from-purple-500 to-pink-500 rounded-lg">
        <Upload className="h-6 w-6 text-white" />
      </div>
      <span className="bg-gradient-to-r from-purple-400 to-pink-400 bg-clip-text text-transparent">
        Advanced File Analysis
      </span>
    </h2>
    <p className="text-muted-foreground ml-14">
      Upload any file for comprehensive multi-engine detection (YARA + Heuristics + ML)
    </p>
  </div>
  <FileScanner />
</div>

       {/* Scan Profiles - NEW SECTION */}
      <div className="section">
        <div className="mb-6">
          <h2 className="text-2xl font-bold mb-2 flex items-center gap-3">
            <div className="p-2 bg-gradient-to-br from-blue-500 to-cyan-500 rounded-lg">
              <Calendar className="h-6 w-6 text-white" />
            </div>
            <span className="bg-gradient-to-r from-blue-400 to-cyan-400 bg-clip-text text-transparent">
              Quick Scan Profiles
            </span>
          </h2>
          <p className="text-muted-foreground ml-14">
            Start a scan instantly with predefined profiles optimized for different scenarios
          </p>
        </div>
        <ScanProfiles />
      </div>

      {/* Schedules Section */}
      <div className="section">
        <div className="card-premium p-6">
          <h2 className="text-xl font-bold mb-4 flex items-center gap-2">
            <Calendar className="h-5 w-5 text-purple-500" />
            Scan Schedules ({schedules.length})
          </h2>

          {schedules.length === 0 ? (
            <div className="text-center py-12">
              <Calendar className="h-12 w-12 text-muted-foreground/50 mx-auto mb-4" />
              <p className="text-muted-foreground">No scheduled scans yet.</p>
              <button
                onClick={() => setShowCreateModal(true)}
                className="btn btn-primary mt-4"
              >
                <Plus className="h-4 w-4" />
                Create First Schedule
              </button>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="table w-full">
                <thead>
                  <tr>
                    <th>Name</th>
                    <th>Type</th>
                    <th>Target</th>
                    <th>Schedule</th>
                    <th>Last Run</th>
                    <th>Status</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {schedules.map((schedule) => (
                    <tr key={schedule.id}>
                      <td className="font-medium">{schedule.name}</td>
                      <td>
                        <span className="badge badge--info">
                          {schedule.scan_type}
                        </span>
                      </td>
                      <td className="font-mono text-xs truncate max-w-xs">
                        {schedule.target_path}
                      </td>
                      <td>
                        <span className="badge badge--default">
                          {schedule.schedule_type}
                          {schedule.interval_days && ` (${schedule.interval_days}d)`}
                        </span>
                      </td>
                      <td className="text-sm">
                        {schedule.last_run
                          ? new Date(schedule.last_run).toLocaleString()
                          : "Never"}
                      </td>
                      <td>
                        <span
                          className={`badge ${
                            schedule.enabled
                              ? "badge--success"
                              : "badge--warning"
                          }`}
                        >
                          {schedule.enabled ? "Enabled" : "Disabled"}
                        </span>
                      </td>
                      <td>
                        <div className="flex gap-2">
                          <button
                            onClick={() =>
                              toggleSchedule(schedule.id, schedule.enabled)
                            }
                            className="p-2 rounded-lg hover:bg-card transition-colors"
                            title={
                              schedule.enabled ? "Disable" : "Enable"
                            }
                          >
                            {schedule.enabled ? (
                              <Pause className="h-4 w-4 text-orange-500" />
                            ) : (
                              <Play className="h-4 w-4 text-green-500" />
                            )}
                          </button>
                          <button
                            onClick={() => deleteSchedule(schedule.id)}
                            className="p-2 rounded-lg hover:bg-card transition-colors"
                            title="Delete"
                          >
                            <Trash2 className="h-4 w-4 text-red-500" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>

      {/* History Section */}
      <div className="section">
        <div className="card-premium p-6">
          <h2 className="text-xl font-bold mb-4 flex items-center gap-2">
            <BarChart3 className="h-5 w-5 text-blue-500" />
            Scan History ({history.length})
          </h2>

          {history.length === 0 ? (
            <div className="text-center py-8 text-muted-foreground">
              No scan history yet.
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="table w-full">
                <thead>
                  <tr>
                    <th>Started</th>
                    <th>Type</th>
                    <th>Target</th>
                    <th>Duration</th>
                    <th>Files</th>
                    <th>Threats</th>
                    <th>Status</th>
                  </tr>
                </thead>
                <tbody>
                  {history.map((item) => (
                    <tr key={item.id}>
                      <td className="font-mono text-sm">
                        {new Date(item.started_at).toLocaleString()}
                      </td>
                      <td>
                        <span className="badge badge--info">
                          {item.scan_type}
                        </span>
                      </td>
                      <td className="font-mono text-xs truncate max-w-xs">
                        {item.target_path}
                      </td>
                      <td className="text-sm">
                        {item.duration_seconds
                          ? `${item.duration_seconds}s`
                          : "—"}
                      </td>
                      <td className="text-sm">{item.files_scanned || 0}</td>
                      <td className="text-sm font-bold">
                        {item.threats_found || 0}
                      </td>
                      <td>
                        <span
                          className={`badge border-2 ${getStatusBg(
                            item.status
                          )}`}
                        >
                          <span className={getStatusColor(item.status)}>
                            {item.status.toUpperCase()}
                          </span>
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>

{/* Create Modal */}
{showCreateModal && (
  <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4" style={{ pointerEvents: 'auto' }}>
    <div className="card-premium p-6 max-w-md w-full relative z-50" style={{ pointerEvents: 'auto' }}>
      <h3 className="text-xl font-bold mb-4">Create Scan Schedule</h3>

      <form onSubmit={handleCreateSchedule} className="space-y-4">
        <div>
          <label className="block text-sm font-medium mb-1">Name</label>
          <input
            type="text"
            value={formData.name}
            onChange={(e) =>
              setFormData({ ...formData, name: e.target.value })
            }
            className="w-full px-3 py-2 rounded-lg bg-card border-2 border-border text-foreground focus:border-purple-500 focus:outline-none relative z-50"
            placeholder="Daily system scan"
            required
            style={{ pointerEvents: 'auto' }}
          />
        </div>

        <div>
          <label className="block text-sm font-medium mb-1">
            Scan Type
          </label>
          <select
            value={formData.scan_type}
            onChange={(e) =>
              setFormData({ ...formData, scan_type: e.target.value })
            }
            className="w-full px-3 py-2 rounded-lg bg-card border-2 border-border text-foreground focus:border-purple-500 focus:outline-none relative z-50 cursor-pointer"
            style={{ pointerEvents: 'auto', colorScheme: 'dark', backgroundColor: 'rgb(15, 23, 42)', color: 'white' }}
          >
            <option value="quick" style={{ backgroundColor: 'rgb(15, 23, 42)', color: 'white' }}>Quick Scan</option>
            <option value="full" style={{ backgroundColor: 'rgb(15, 23, 42)', color: 'white' }}>Full Scan</option>
            <option value="custom" style={{ backgroundColor: 'rgb(15, 23, 42)', color: 'white' }}>Custom Scan</option>
          </select>
        </div>

       <div>
          <label className="block text-sm font-medium mb-1">
            Target Path
          </label>
          <input
            type="text"
            value={formData.target_path}
            onChange={(e) =>
              setFormData({ ...formData, target_path: e.target.value })
            }
            className="w-full px-3 py-2 rounded-lg bg-card border-2 border-border text-foreground focus:border-purple-500 focus:outline-none relative z-50"
            placeholder="/tmp"
            required
            style={{ pointerEvents: 'auto' }}
          />
          <p className="text-xs text-orange-400 mt-1">
            ⚠️ Use Linux paths: /tmp, /app, /home (Railway backend runs on Linux)
          </p>
        </div>

        <div>
          <label className="block text-sm font-medium mb-1">
            Schedule Type
          </label>
          <select
            value={formData.schedule_type}
            onChange={(e) =>
              setFormData({
                ...formData,
                schedule_type: e.target.value,
              })
            }
            className="w-full px-3 py-2 rounded-lg bg-card border-2 border-border text-foreground focus:border-purple-500 focus:outline-none relative z-50 cursor-pointer"
            style={{ pointerEvents: 'auto', colorScheme: 'dark', backgroundColor: 'rgb(15, 23, 42)', color: 'white' }}
          >
            <option value="daily" style={{ backgroundColor: 'rgb(15, 23, 42)', color: 'white' }}>Daily</option>
            <option value="weekly" style={{ backgroundColor: 'rgb(15, 23, 42)', color: 'white' }}>Weekly</option>
            <option value="monthly" style={{ backgroundColor: 'rgb(15, 23, 42)', color: 'white' }}>Monthly</option>
            <option value="interval" style={{ backgroundColor: 'rgb(15, 23, 42)', color: 'white' }}>Custom Interval</option>
          </select>
        </div>

        {formData.schedule_type === "interval" && (
          <div>
            <label className="block text-sm font-medium mb-1">
              Interval (days)
            </label>
            <input
              type="number"
              min="1"
              value={formData.interval_days}
              onChange={(e) =>
                setFormData({
                  ...formData,
                  interval_days: Number(e.target.value),
                })
              }
              className="w-full px-3 py-2 rounded-lg bg-card border-2 border-border text-foreground focus:border-purple-500 focus:outline-none relative z-50"
              style={{ pointerEvents: 'auto' }}
            />
          </div>
        )}

        <div className="flex gap-2 pt-4">
          <button type="submit" className="btn btn-primary flex-1 relative z-50 cursor-pointer" style={{ pointerEvents: 'auto' }}>
            Create Schedule
          </button>
          <button
            type="button"
            onClick={() => setShowCreateModal(false)}
            className="btn btn-secondary flex-1 relative z-50 cursor-pointer"
            style={{ pointerEvents: 'auto' }}
          >
            Cancel
          </button>
        </div>
      </form>
    </div>
  </div>
)}
    </main>
    </ProtectedRoute>
  );
}