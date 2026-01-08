"use client";

import { useState, useEffect } from "react";
import { toast } from "sonner";
import { 
  Shield, 
  ShieldAlert,
  ShieldCheck,
  Power,
  PowerOff,
  Activity,
  AlertTriangle,
  Lock,
  Unlock,
  RefreshCw,
  Clock,
  Zap,
  Eye,
  CheckCircle2,
  XCircle,
  TrendingUp,
  Server
} from "lucide-react";
import ProtectedRoute from '@/components/ProtectedRoute';

interface ProtectionStatus {
  overall_status: string;
  watchdog_active: boolean;
  config_encrypted: boolean;
  config_integrity: string;
  active_alerts: number;
  restart_count: number;
}

interface WatchdogStatus {
  is_running: boolean;
  monitored_process: {
    pid: number;
    status: string;
    cpu_percent: number;
    memory_mb: number;
    create_time: string;
  } | null;
  restart_count: number;
  recent_restarts: any[];
}

interface TamperAlert {
  id: number;
  alert_type: string;
  severity: string;
  file_path: string | null;
  message: string;
  resolved: boolean;
  created_at: string;
}

interface RestartRecord {
  timestamp: string;
  reason: string;
}

interface ProcessProtectionStatus {
  platform: string;
  is_protected: boolean;
  service_installed: boolean;
  can_protect: boolean;
  is_admin: boolean;
  is_root: boolean;
  username: string;
  recommendations: string[];
}

interface Privileges {
  platform: string;
  is_admin: boolean;
  is_root: boolean;
  can_protect: boolean;
  username: string;
}
// API configuration
const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

// Helper to make authenticated requests
const fetchWithAuth = async (endpoint: string, options?: RequestInit) => {
  const token = typeof window !== 'undefined' ? localStorage.getItem('access_token') : null;
  
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  };
  
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }
  
  const response = await fetch(`${API_BASE_URL}${endpoint}`, {
    ...options,
    headers: {
      ...headers,
      ...(options?.headers || {}),
    }
  });
  
  if (!response.ok) {
    throw new Error(`HTTP error! status: ${response.status}`);
  }
  
  return response.json();
};

export default function TamperProtectionPage() {
  const [protectionStatus, setProtectionStatus] = useState<ProtectionStatus | null>(null);
  const [watchdogStatus, setWatchdogStatus] = useState<WatchdogStatus | null>(null);
  const [alerts, setAlerts] = useState<TamperAlert[]>([]);
  const [restarts, setRestarts] = useState<RestartRecord[]>([]);
  const [processProtection, setProcessProtection] = useState<ProcessProtectionStatus | null>(null);
  const [privileges, setPrivileges] = useState<Privileges | null>(null);
  const [loading, setLoading] = useState(false);
  const [actionLoading, setActionLoading] = useState(false);

   

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 15000); // Refresh every 15 seconds
    return () => clearInterval(interval);
  }, []);

  const fetchData = async () => {
    try {
      // Fetch protection status
      // Fetch protection status
    const protectionData = await fetchWithAuth('/api/watchdog/protection/status');

      if (protectionData.success) {
        setProtectionStatus(protectionData.protection);
      }

      // Fetch watchdog status
      const watchdogData = await fetchWithAuth('/api/watchdog/status');
      if (watchdogData.success) {
        setWatchdogStatus(watchdogData.watchdog);
      }

      // Fetch tamper alerts
      const alertsData = await fetchWithAuth('/api/watchdog/tamper/alerts?resolved=false');
      if (alertsData.success) {
        setAlerts(alertsData.alerts);
      }

      // Fetch restart history
     const restartsData = await fetchWithAuth('/api/watchdog/restarts?limit=10');
      if (restartsData.success) {
        setRestarts(restartsData.restarts);
      }

      // Fetch process protection status
      const processProtectionData = await fetchWithAuth('/api/process-protection/status');
      if (processProtectionData.success) {
        setProcessProtection(processProtectionData.protection);
      }

      // Fetch privileges
      // Fetch privileges
    const privilegesData = await fetchWithAuth('/api/process-protection/privileges');
      if (privilegesData.success) {
        setPrivileges(privilegesData.privileges);
      }
    } catch (error) {
      console.error("Error fetching data:", error);
    }
  };

  const startWatchdog = async () => {
    setActionLoading(true);
    try {
      const data = await fetchWithAuth('/api/watchdog/start', {
      method: "POST",
    });

      if (data.success) {
        toast.success("Watchdog Started", {
          description: "Process monitoring is now active",
        });
        fetchData();
      } else {
        toast.error("Failed to start watchdog", {
          description: data.message,
        });
      }
    } catch (error) {
      console.error("Error starting watchdog:", error);
      toast.error("Failed to start watchdog");
    } finally {
      setActionLoading(false);
    }
  };

  const stopWatchdog = async () => {
    setActionLoading(true);
    try {
      const data = await fetchWithAuth('/api/watchdog/stop', {
      method: "POST",
    });

      if (data.success) {
        toast.success("Watchdog Stopped", {
          description: "Process monitoring has been disabled",
        });
        fetchData();
      } else {
        toast.error("Failed to stop watchdog", {
          description: data.message,
        });
      }
    } catch (error) {
      console.error("Error stopping watchdog:", error);
      toast.error("Failed to stop watchdog");
    } finally {
      setActionLoading(false);
    }
  };

  const verifyConfig = async () => {
    setLoading(true);
    try {
     const data = await fetchWithAuth('/api/watchdog/config/verify', {
      method: "POST",
    });

      if (data.success) {
        if (data.is_valid) {
          toast.success("Config Verified", {
            description: "Configuration integrity is intact",
          });
        } else {
          toast.error("Config Compromised", {
            description: "Configuration integrity check failed!",
          });
        }
        fetchData();
      }
    } catch (error) {
      console.error("Error verifying config:", error);
      toast.error("Failed to verify config");
    } finally {
      setLoading(false);
    }
  };

  const enableAntiTermination = async () => {
    setActionLoading(true);
    try {
       const data = await fetchWithAuth('/api/process-protection/enable-anti-termination', {
      method: "POST",
    });

      if (data.success) {
        toast.success("Anti-Termination Enabled", {
          description: "Process protection is now active",
        });
        fetchData();
      } else {
        toast.error("Failed to enable anti-termination", {
          description: data.message,
        });
      }
    } catch (error) {
      console.error("Error enabling anti-termination:", error);
      toast.error("Failed to enable anti-termination");
    } finally {
      setActionLoading(false);
    }
  };

  const enableMaxProtection = async () => {
    setActionLoading(true);
    try {
      const data = await fetchWithAuth('/api/process-protection/enable-maximum-protection', {
      method: "POST",
    });

      if (data.success) {
        toast.success("Maximum Protection Enabled", {
          description: "All available protection features activated",
        });
        fetchData();
      } else {
        toast.warning("Partial Protection Enabled", {
          description: data.message,
        });
        fetchData();
      }
    } catch (error) {
      console.error("Error enabling max protection:", error);
      toast.error("Failed to enable maximum protection");
    } finally {
      setActionLoading(false);
    }
  };

  const installService = async () => {
    setActionLoading(true);
    try {
      const data = await fetchWithAuth('/api/process-protection/install-service', {
      method: "POST",
    });

      if (data.success) {
        toast.success("Service Installed", {
          description: `Service '${data.service_name}' installed successfully`,
        });
        fetchData();
      } else {
        toast.error("Failed to install service", {
          description: data.message,
        });
      }
    } catch (error) {
      console.error("Error installing service:", error);
      toast.error("Failed to install service");
    } finally {
      setActionLoading(false);
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case "PROTECTED":
        return "from-emerald-500 via-teal-500 to-cyan-500";
      case "MONITORING_DISABLED":
        return "from-amber-500 via-orange-500 to-red-500";
      case "WARNING":
        return "from-yellow-500 via-amber-500 to-orange-500";
      case "CRITICAL":
        return "from-rose-600 via-red-600 to-pink-600";
      default:
        return "from-gray-500 via-gray-600 to-gray-700";
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case "PROTECTED":
        return <ShieldCheck className="w-20 h-20 text-white drop-shadow-lg" />;
      case "MONITORING_DISABLED":
        return <ShieldAlert className="w-20 h-20 text-white drop-shadow-lg animate-pulse" />;
      case "WARNING":
        return <AlertTriangle className="w-20 h-20 text-white drop-shadow-lg animate-pulse" />;
      case "CRITICAL":
        return <ShieldAlert className="w-20 h-20 text-white drop-shadow-lg animate-bounce" />;
      default:
        return <Shield className="w-20 h-20 text-white drop-shadow-lg" />;
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case "CRITICAL":
        return "text-rose-600 bg-rose-50 border-rose-200";
      case "HIGH":
        return "text-orange-600 bg-orange-50 border-orange-200";
      case "MEDIUM":
        return "text-amber-600 bg-amber-50 border-amber-200";
      case "LOW":
        return "text-blue-600 bg-blue-50 border-blue-200";
      default:
        return "text-gray-600 bg-gray-50 border-gray-200";
    }
  };

  return (
    <ProtectedRoute>
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-red-900 to-slate-900 p-8">
      <div className="max-w-7xl mx-auto space-y-8">
        
        {/* Hero Section with Protection Status */}
        <div className={`relative bg-gradient-to-r ${getStatusColor(protectionStatus?.overall_status || "MONITORING_DISABLED")} rounded-3xl p-12 shadow-2xl overflow-hidden`}>
          {/* Animated Background */}
          <div className="absolute inset-0 opacity-10">
            <div className="absolute top-0 left-0 w-96 h-96 bg-white rounded-full blur-3xl animate-pulse"></div>
            <div className="absolute bottom-0 right-0 w-96 h-96 bg-white rounded-full blur-3xl animate-pulse delay-1000"></div>
          </div>
          
          <div className="relative z-10 flex items-center justify-between">
            <div className="flex items-center gap-8">
              {/* Status Icon */}
              <div className="relative">
                <div className="absolute inset-0 bg-white/20 rounded-full blur-xl animate-ping"></div>
                {getStatusIcon(protectionStatus?.overall_status || "MONITORING_DISABLED")}
              </div>
              
              <div>
                <h1 className="text-5xl font-black text-white mb-3 tracking-tight">
                  Tamper Protection
                </h1>
                <p className="text-2xl font-semibold text-white/90 mb-2">
                  {protectionStatus?.overall_status === "PROTECTED" && "🛡️ System Protected"}
                  {protectionStatus?.overall_status === "MONITORING_DISABLED" && "⚠️ Monitoring Disabled"}
                  {protectionStatus?.overall_status === "WARNING" && "⚠️ Warning Detected"}
                  {protectionStatus?.overall_status === "CRITICAL" && "🚨 Critical Alert"}
                </p>
                <p className="text-white/80 text-lg">
                  Real-time process monitoring & tamper detection
                </p>
              </div>
            </div>
            
            {/* Action Buttons */}
            <div className="flex flex-col gap-3">
              {watchdogStatus?.is_running ? (
                <button
                  onClick={stopWatchdog}
                  disabled={actionLoading}
                  className="px-8 py-4 bg-white/20 backdrop-blur-lg text-white rounded-2xl hover:bg-white/30 transition-all disabled:opacity-50 flex items-center gap-3 border border-white/30 shadow-xl"
                >
                  <PowerOff className="w-6 h-6" />
                  <span className="font-semibold">Stop Watchdog</span>
                </button>
              ) : (
                <button
                  onClick={startWatchdog}
                  disabled={actionLoading}
                  className="px-8 py-4 bg-white text-red-600 rounded-2xl hover:shadow-2xl transition-all disabled:opacity-50 flex items-center gap-3 font-bold"
                >
                  <Power className="w-6 h-6" />
                  <span>Start Watchdog</span>
                </button>
              )}

              <button
                onClick={verifyConfig}
                disabled={loading}
                className="px-8 py-4 bg-white/20 backdrop-blur-lg text-white rounded-2xl hover:bg-white/30 transition-all disabled:opacity-50 flex items-center gap-3 border border-white/30"
              >
                {loading ? (
                  <>
                    <RefreshCw className="w-6 h-6 animate-spin" />
                    <span className="font-semibold">Verifying...</span>
                  </>
                ) : (
                  <>
                    <Eye className="w-6 h-6" />
                    <span className="font-semibold">Verify Config</span>
                  </>
                )}
              </button>
            </div>
          </div>
        </div>

        {/* Statistics Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
          {/* Watchdog Status */}
          <div className="group relative bg-white/10 backdrop-blur-xl rounded-2xl p-6 border border-white/20 hover:bg-white/20 transition-all hover:scale-105 hover:shadow-2xl">
            <div className="absolute inset-0 bg-gradient-to-br from-red-500/20 to-orange-500/20 rounded-2xl opacity-0 group-hover:opacity-100 transition-opacity"></div>
            <div className="relative z-10">
              <div className="flex items-center justify-between mb-4">
                <Activity className="w-8 h-8 text-red-400" />
                <div className="w-12 h-12 bg-red-500/20 rounded-xl flex items-center justify-center">
                  <span className="text-2xl">{watchdogStatus?.is_running ? "🟢" : "🔴"}</span>
                </div>
              </div>
              <p className="text-sm text-gray-300 font-medium mb-1">Watchdog</p>
              <p className="text-4xl font-black text-white">
                {watchdogStatus?.is_running ? "ACTIVE" : "OFF"}
              </p>
            </div>
          </div>

          {/* Config Status */}
          <div className="group relative bg-white/10 backdrop-blur-xl rounded-2xl p-6 border border-white/20 hover:bg-white/20 transition-all hover:scale-105 hover:shadow-2xl">
            <div className="absolute inset-0 bg-gradient-to-br from-blue-500/20 to-cyan-500/20 rounded-2xl opacity-0 group-hover:opacity-100 transition-opacity"></div>
            <div className="relative z-10">
              <div className="flex items-center justify-between mb-4">
                {protectionStatus?.config_integrity === "VALID" ? (
                  <Lock className="w-8 h-8 text-cyan-400" />
                ) : (
                  <Unlock className="w-8 h-8 text-rose-400" />
                )}
                <div className="w-12 h-12 bg-cyan-500/20 rounded-xl flex items-center justify-center">
                  <span className="text-2xl">🔐</span>
                </div>
              </div>
              <p className="text-sm text-gray-300 font-medium mb-1">Config Integrity</p>
              <p className="text-4xl font-black text-cyan-400">
                {protectionStatus?.config_integrity || "N/A"}
              </p>
            </div>
          </div>

          {/* Active Alerts */}
          <div className="group relative bg-white/10 backdrop-blur-xl rounded-2xl p-6 border border-white/20 hover:bg-white/20 transition-all hover:scale-105 hover:shadow-2xl">
            <div className="absolute inset-0 bg-gradient-to-br from-rose-500/20 to-pink-500/20 rounded-2xl opacity-0 group-hover:opacity-100 transition-opacity"></div>
            <div className="relative z-10">
              <div className="flex items-center justify-between mb-4">
                <AlertTriangle className="w-8 h-8 text-rose-400" />
                <div className="w-12 h-12 bg-rose-500/20 rounded-xl flex items-center justify-center">
                  <span className="text-2xl">🚨</span>
                </div>
              </div>
              <p className="text-sm text-gray-300 font-medium mb-1">Active Alerts</p>
              <p className="text-4xl font-black text-rose-400">
                {protectionStatus?.active_alerts || 0}
              </p>
            </div>
          </div>

          {/* Total Restarts */}
          <div className="group relative bg-white/10 backdrop-blur-xl rounded-2xl p-6 border border-white/20 hover:bg-white/20 transition-all hover:scale-105 hover:shadow-2xl">
            <div className="absolute inset-0 bg-gradient-to-br from-amber-500/20 to-yellow-500/20 rounded-2xl opacity-0 group-hover:opacity-100 transition-opacity"></div>
            <div className="relative z-10">
              <div className="flex items-center justify-between mb-4">
                <RefreshCw className="w-8 h-8 text-amber-400" />
                <div className="w-12 h-12 bg-amber-500/20 rounded-xl flex items-center justify-center">
                  <span className="text-2xl">🔄</span>
                </div>
              </div>
              <p className="text-sm text-gray-300 font-medium mb-1">Total Restarts</p>
              <p className="text-4xl font-black text-amber-400">
                {protectionStatus?.restart_count || 0}
              </p>
            </div>
          </div>
        </div>

        {/* Process Info */}
        {watchdogStatus?.monitored_process && (
          <div className="bg-gradient-to-br from-purple-600/30 via-pink-600/30 to-rose-600/30 backdrop-blur-xl rounded-3xl p-8 border border-white/20 shadow-2xl">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-6">
                <div className="w-20 h-20 bg-white/20 rounded-2xl flex items-center justify-center backdrop-blur-lg">
                  <Server className="w-10 h-10 text-white" />
                </div>
                <div>
                  <p className="text-purple-200 font-semibold text-sm mb-1">🖥️ Monitored Process</p>
                  <p className="text-3xl font-black text-white mb-2">
                    PID {watchdogStatus.monitored_process.pid}
                  </p>
                  <p className="text-white/80 text-sm">
                    Status: {watchdogStatus.monitored_process.status} • 
                    CPU: {watchdogStatus.monitored_process.cpu_percent.toFixed(1)}% • 
                    Memory: {watchdogStatus.monitored_process.memory_mb.toFixed(0)} MB
                  </p>
                </div>
              </div>
              <div className="text-right">
                <div className="inline-block px-6 py-3 bg-white/20 backdrop-blur-lg rounded-xl border border-white/30">
                  <p className="text-xs text-white/70 mb-1">Process Health</p>
                  <p className="text-2xl font-black text-white">HEALTHY</p>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Process Protection Status */}
        <div className="bg-gradient-to-br from-indigo-600/30 via-blue-600/30 to-cyan-600/30 backdrop-blur-xl rounded-3xl p-8 border border-white/20 shadow-2xl">
          <div className="flex items-center justify-between mb-6">
            <div className="flex items-center gap-4">
              <div className="w-16 h-16 bg-white/20 rounded-2xl flex items-center justify-center backdrop-blur-lg">
                <Shield className="w-8 h-8 text-white" />
              </div>
              <div>
                <p className="text-blue-200 font-semibold text-sm mb-1">🛡️ Process Protection</p>
                <p className="text-3xl font-black text-white">
                  {processProtection?.platform || "Unknown"}
                </p>
              </div>
            </div>
            
            <div className="flex gap-3">
              {privileges?.can_protect ? (
                <>
                  <button
                    onClick={enableAntiTermination}
                    disabled={actionLoading || processProtection?.is_protected}
                    className="px-6 py-3 bg-white/20 backdrop-blur-lg text-white rounded-xl hover:bg-white/30 transition-all disabled:opacity-50 flex items-center gap-2 border border-white/30"
                  >
                    <Lock className="w-5 h-5" />
                    <span className="font-semibold">
                      {processProtection?.is_protected ? "Protected" : "Enable Protection"}
                    </span>
                  </button>
                  
                  <button
                    onClick={enableMaxProtection}
                    disabled={actionLoading}
                    className="px-6 py-3 bg-gradient-to-r from-rose-500 to-pink-500 text-white rounded-xl hover:shadow-2xl transition-all disabled:opacity-50 flex items-center gap-2 font-bold"
                  >
                    <Zap className="w-5 h-5" />
                    <span>Max Protection</span>
                  </button>
                </>
              ) : (
                <div className="px-6 py-3 bg-amber-500/20 backdrop-blur-lg text-amber-200 rounded-xl border border-amber-400/30 flex items-center gap-2">
                  <AlertTriangle className="w-5 h-5" />
                  <span className="font-semibold">
                    {processProtection?.platform === "Windows" ? "Requires Administrator" : "Requires Root"}
                  </span>
                </div>
              )}
            </div>
          </div>
          
          {/* Protection Status Grid */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
            <div className="bg-white/10 backdrop-blur-lg rounded-xl p-4 border border-white/20">
              <div className="flex items-center justify-between mb-2">
                <span className="text-sm text-blue-200">Protection Status</span>
                {processProtection?.is_protected ? (
                  <CheckCircle2 className="w-5 h-5 text-emerald-400" />
                ) : (
                  <XCircle className="w-5 h-5 text-rose-400" />
                )}
              </div>
              <p className="text-2xl font-bold text-white">
                {processProtection?.is_protected ? "ACTIVE" : "INACTIVE"}
              </p>
            </div>
            
            <div className="bg-white/10 backdrop-blur-lg rounded-xl p-4 border border-white/20">
              <div className="flex items-center justify-between mb-2">
                <span className="text-sm text-blue-200">Service Status</span>
                {processProtection?.service_installed ? (
                  <CheckCircle2 className="w-5 h-5 text-emerald-400" />
                ) : (
                  <XCircle className="w-5 h-5 text-rose-400" />
                )}
              </div>
              <p className="text-2xl font-bold text-white">
                {processProtection?.service_installed ? "INSTALLED" : "NOT INSTALLED"}
              </p>
            </div>
            
            <div className="bg-white/10 backdrop-blur-lg rounded-xl p-4 border border-white/20">
              <div className="flex items-center justify-between mb-2">
                <span className="text-sm text-blue-200">Privileges</span>
                {privileges?.can_protect ? (
                  <CheckCircle2 className="w-5 h-5 text-emerald-400" />
                ) : (
                  <XCircle className="w-5 h-5 text-rose-400" />
                )}
              </div>
              <p className="text-2xl font-bold text-white">
                {privileges?.is_admin && "ADMIN"}
                {privileges?.is_root && "ROOT"}
                {!privileges?.can_protect && "USER"}
              </p>
            </div>
          </div>
          
          {/* Recommendations */}
          {processProtection && processProtection.recommendations.length > 0 && (
            <div className="bg-white/5 backdrop-blur-lg rounded-xl p-4 border border-white/10">
              <p className="text-white font-semibold mb-3 flex items-center gap-2">
                <TrendingUp className="w-5 h-5 text-blue-400" />
                Security Recommendations
              </p>
              <div className="space-y-2">
                {processProtection.recommendations.map((rec, index) => (
                  <div key={index} className="flex items-start gap-2 text-sm text-blue-200">
                    <span className="text-blue-400 mt-0.5">•</span>
                    <span>{rec}</span>
                  </div>
                ))}
              </div>
              
              {!processProtection.service_installed && privileges?.can_protect && (
                <button
                  onClick={installService}
                  disabled={actionLoading}
                  className="mt-4 w-full px-4 py-3 bg-white/10 backdrop-blur-lg text-white rounded-lg hover:bg-white/20 transition-all disabled:opacity-50 flex items-center justify-center gap-2 border border-white/20"
                >
                  <Server className="w-5 h-5" />
                  <span className="font-semibold">Install as System Service</span>
                </button>
              )}
            </div>
          )}
        </div>

        {/* Tamper Alerts */}
        {alerts.length > 0 && (
          <div className="bg-white/10 backdrop-blur-xl rounded-3xl border border-white/20 overflow-hidden shadow-2xl">
            <div className="bg-gradient-to-r from-rose-600/50 to-pink-600/50 p-6 border-b border-white/10">
              <h2 className="text-2xl font-bold text-white flex items-center gap-3">
                <ShieldAlert className="w-7 h-7" />
                Tamper Detection Alerts
                <span className="ml-auto px-4 py-2 bg-white/20 rounded-xl text-sm font-black">
                  {alerts.length}
                </span>
              </h2>
            </div>
            <div className="divide-y divide-white/10">
              {alerts.map((alert) => (
                <div key={alert.id} className="p-6 hover:bg-white/5 transition-colors">
                  <div className="flex items-start justify-between">
                    <div className="flex-1">
                      <div className="flex items-center gap-3 mb-3">
                        <span className={`px-4 py-2 rounded-xl text-xs font-bold border ${getSeverityColor(alert.severity)}`}>
                          {alert.severity}
                        </span>
                        <span className="text-sm text-gray-300 font-medium">
                          {alert.alert_type.replace(/_/g, " ")}
                        </span>
                      </div>
                      <p className="text-white font-semibold text-lg mb-2">{alert.message}</p>
                      {alert.file_path && (
                        <p className="text-sm text-rose-300 font-mono bg-white/5 px-3 py-2 rounded-lg inline-block">
                          📁 {alert.file_path}
                        </p>
                      )}
                      <p className="text-xs text-gray-400 mt-3">
                        🕐 {new Date(alert.created_at).toLocaleString()}
                      </p>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Restart History */}
        {restarts.length > 0 && (
          <div className="bg-white/10 backdrop-blur-xl rounded-3xl border border-white/20 overflow-hidden shadow-2xl">
            <div className="bg-gradient-to-r from-amber-600/50 to-orange-600/50 p-6 border-b border-white/10">
              <h2 className="text-2xl font-bold text-white flex items-center gap-3">
                <Clock className="w-7 h-7" />
                Restart History
              </h2>
            </div>
            <div className="p-6 space-y-4">
              {restarts.map((restart, index) => (
                <div key={index} className="flex items-start gap-4 p-4 bg-white/5 rounded-xl border border-white/10">
                  <div className="w-10 h-10 bg-amber-500/20 rounded-lg flex items-center justify-center flex-shrink-0">
                    <RefreshCw className="w-5 h-5 text-amber-400" />
                  </div>
                  <div className="flex-1">
                    <p className="text-white font-semibold mb-1">{restart.reason}</p>
                    <p className="text-sm text-gray-400">
                      {new Date(restart.timestamp).toLocaleString()}
                    </p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

      </div>
    </div>
    </ProtectedRoute>
  );
}