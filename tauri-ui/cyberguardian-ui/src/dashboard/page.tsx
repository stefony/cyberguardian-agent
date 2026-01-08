"use client";

import { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  Shield,
  Activity,
  AlertTriangle,
  Eye,
  Wifi,
  WifiOff,
} from "lucide-react";
import { dashboardApi, threatsApi, analyticsApi, honeypotApi } from "@/lib/api";
import type { HealthData } from "@/lib/types";
import { useWebSocketContext } from "@/lib/contexts/WebSocketContext";
import { LiveThreatNotification } from "@/components/LiveThreatNotification";
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
} from "recharts";
import ProtectedRoute from "@/components/ProtectedRoute";

/* ===== CountUp: анимира „изкачване" на числата ===== */
function CountUp({
  end,
  duration = 1200,
  prefix = "",
  suffix = "",
}: {
  end: number;
  duration?: number;
  prefix?: string;
  suffix?: string;
}) {
  const [val, setVal] = useState(0);
  const raf = useRef<number | null>(null);
  const start = useRef<number | null>(null);

  useEffect(() => {
    const target = end;
    const run = (t: number) => {
      if (start.current === null) start.current = t;
      const p = Math.min((t - start.current) / duration, 1);
      const eased = 1 - Math.pow(1 - p, 2); // easeOutQuad
      setVal(Math.round(target * eased));
      if (p < 1) raf.current = requestAnimationFrame(run);
    };
    raf.current = requestAnimationFrame(run);
    return () => {
      if (raf.current) cancelAnimationFrame(raf.current);
    };
  }, [end, duration]);

  return (
    <span>
      {prefix}
      {val}
      {suffix}
    </span>
  );
}

/* ===== CardTilt: лек parallax/tilt при мишка ===== */
function CardTilt({
  children,
  className = "",
}: {
  children: React.ReactNode;
  className?: string;
}) {
  const ref = useRef<HTMLDivElement>(null);
  const onMove = (e: React.MouseEvent<HTMLDivElement>) => {
    const el = ref.current;
    if (!el) return;
    const r = el.getBoundingClientRect();
    const px = (e.clientX - r.left) / r.width,
      py = (e.clientY - r.top) / r.height;
    const rotX = (py - 0.5) * -6,
      rotY = (px - 0.5) * 6;
    el.style.transform = `perspective(1000px) rotateX(${rotX}deg) rotateY(${rotY}deg) translateY(-6px) scale(1.02)`;
  };
  const onLeave = () => {
    const el = ref.current;
    if (el) el.style.transform = "";
  };

  return (
    <div
      ref={ref}
      className={`tilt ${className}`}
      onMouseMove={onMove}
      onMouseLeave={onLeave}
    >
      {children}
    </div>
  );
}

/* ===== Threat Activity Chart (Recharts) ===== */
type RangeKey = "24h" | "7d" | "30d";
type ThreatPoint = { t: string; threats: number };

function ThreatActivityChart() {
  const [range, setRange] = useState<RangeKey>("24h");
  const [data, setData] = useState<ThreatPoint[]>([]);

  useEffect(() => {
    const basePoints: Record<RangeKey, number> = {
      "24h": 15,
      "7d": 7,
      "30d": 30,
    };
    const newData: ThreatPoint[] = Array.from(
      { length: basePoints[range] },
      (_, i) => ({
        t: range === "24h" ? `${i + 1}h` : `Day ${i + 1}`,
        threats: Math.floor(Math.random() * 20 + 10) + i * 2,
      })
    );
    setData(newData);
  }, [range]);

  return (
    <div className="chart-card p-6 transition-all duration-700 ease-out opacity-0 translate-y-6 animate-[fadeInUp_1s_ease-out_forwards]">
      <div className="flex items-center justify-between mb-3">
        <h3 className="text-lg font-semibold">Threat Activity</h3>
        <div className="flex gap-2">
          {(["24h", "7d", "30d"] as RangeKey[]).map((label) => (
            <button
              key={label}
              onClick={() => setRange(label)}
              className={`group relative px-4 py-2 rounded-lg font-semibold text-sm transition-all duration-300 overflow-hidden ${
                range === label
                  ? "bg-gradient-to-r from-purple-600 to-cyan-600 text-white shadow-lg shadow-purple-500/50 scale-105"
                  : "bg-slate-800/50 text-slate-400 border border-slate-700 hover:border-purple-500/50 hover:text-slate-200 hover:shadow-lg hover:shadow-purple-500/20 hover:scale-105"
              }`}
            >
              {/* Active state glow */}
              {range === label && (
                <div className="absolute inset-0 bg-gradient-to-r from-cyan-600 to-purple-600 opacity-0 group-hover:opacity-100 transition-opacity duration-300"></div>
              )}

              {/* Button text */}
              <span className="relative z-10">{label}</span>

              {/* Pulse indicator for active */}
              {range === label && (
                <span className="absolute top-1 right-1 w-2 h-2 bg-cyan-400 rounded-full animate-ping"></span>
              )}
            </button>
          ))}
        </div>
      </div>

      <div style={{ width: "100%", height: 300 }}>
        <ResponsiveContainer>
          <AreaChart
            data={data}
            margin={{ top: 10, right: 12, bottom: 0, left: -10 }}
          >
            <defs>
              <linearGradient id="gradThreat" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="#7C3AED" stopOpacity={0.8} />
                <stop offset="100%" stopColor="#7C3AED" stopOpacity={0.05} />
              </linearGradient>
            </defs>

            <CartesianGrid
              vertical={false}
              stroke="rgba(255,255,255,.06)"
              strokeDasharray="3 3"
            />
            <XAxis
              dataKey="t"
              tick={{ fill: "rgba(226,232,240,.7)", fontSize: 12 }}
              tickMargin={8}
              axisLine={false}
              tickLine={false}
            />
            <YAxis
              tick={{ fill: "rgba(226,232,240,.6)", fontSize: 12 }}
              axisLine={false}
              tickLine={false}
              width={30}
            />
            <Tooltip
              contentStyle={{
                background: "rgba(17,27,46,.95)",
                border: "1px solid rgba(255,255,255,.08)",
                borderRadius: 12,
                color: "rgb(226 232 240)",
                boxShadow: "0 8px 24px rgba(0,0,0,.45)",
                padding: "10px 12px",
              }}
              labelStyle={{ color: "rgba(148,163,184,1)" }}
              cursor={{ stroke: "rgba(124,58,237,.4)", strokeWidth: 1 }}
            />
            <Area
              type="monotone"
              dataKey="threats"
              stroke="#7C3AED"
              strokeWidth={2}
              fill="url(#gradThreat)"
              animationDuration={900}
              dot={false}
              activeDot={{ r: 5 }}
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}

/* ===== MAIN DASHBOARD PAGE WITH WEBSOCKET ===== */
export default function DashboardPage() {
  const router = useNavigate();
  const [health, setHealth] = useState<HealthData | null>(null);
  const [loading, setLoading] = useState(true);
  // Real stats from API
  const [threatCount, setThreatCount] = useState(0);
  const [honeypotCount, setHoneypotCount] = useState(0);
  const [monitorCount, setMonitorCount] = useState(5); // Default monitors
  // Security Posture & Recent Incidents
  const [securityPosture, setSecurityPosture] = useState<any>(null);
  const [recentIncidents, setRecentIncidents] = useState<any[]>([]);

  // Threat notification state
  const [currentThreat, setCurrentThreat] = useState<{
    id: string;
    title: string;
    severity: string;
    timestamp: string;
  } | null>(null);

  /// WebSocket integration
  const { isConnected, lastMessage } = useWebSocketContext();

  // Fetch initial data
  const fetchHealth = async () => {
    try {
      const response = await dashboardApi.getHealth();
      if (response.success && response.data) {
        setHealth(response.data);
      }
    } catch (error) {
      console.error("Failed to fetch health:", error);
    } finally {
      setLoading(false);
    }
  };

  // Fetch real threat count
  const fetchThreatsCount = async () => {
    try {
      const response = await threatsApi.getStats();
      if (response.success && response.data) {
        setThreatCount(response.data.total_threats || 0);
      }
    } catch (err) {
      console.error("Error fetching threat count:", err);
    }
  };

  // Fetch real honeypot count
  const fetchHoneypotsCount = async () => {
    try {
      const response = await honeypotApi.getStatistics();
      if (response.success && response.data) {
        setHoneypotCount(response.data.active_honeypots || 0);
      }
    } catch (err) {
      console.error("Error fetching honeypot count:", err);
      setHoneypotCount(0);
    }
  };

  // Fetch security posture score
  const fetchSecurityPosture = async () => {
    try {
      const response = await analyticsApi.getSecurityPosture();
      if (response.success && response.data) {
        setSecurityPosture(response.data);
      }
    } catch (err) {
      console.error("Error fetching security posture:", err);
    }
  };

  // Fetch recent incidents
  const fetchRecentIncidents = async () => {
    try {
      const response = await analyticsApi.getRecentIncidents(5);
      if (response.success && response.data) {
        setRecentIncidents(response.data);
      }
    } catch (err) {
      console.error("Error fetching recent incidents:", err);
    }
  };

  // Check authentication
  useEffect(() => {
    const token = localStorage.getItem("access_token");
    if (!token) {
      navigate("/auth/login");
    }
  }, [router]);

  // Initial load
  useEffect(() => {
    fetchHealth();
    fetchThreatsCount();
    fetchHoneypotsCount();
    fetchSecurityPosture();
    fetchRecentIncidents();
  }, []);

  // Listen for WebSocket updates
  useEffect(() => {
    if (!lastMessage) return;

    console.log("📡 Dashboard received WebSocket message:", lastMessage);

    // Handle different message types
    switch (lastMessage.type) {
      case "stats_update":
        // Update stats from WebSocket
        if (lastMessage.data && health) {
          setHealth((prev) => ({
            ...prev!,
            ...lastMessage.data,
          }));
        }
        break;

      case "threat_update":
        // Show notification for new threat
        if (lastMessage.data) {
          setCurrentThreat({
            id: lastMessage.data.id || Date.now().toString(),
            title:
              lastMessage.data.title ||
              lastMessage.data.threat_type ||
              "Unknown Threat",
            severity:
              lastMessage.data.severity || lastMessage.data.level || "medium",
            timestamp: lastMessage.data.timestamp || new Date().toISOString(),
          });

          // Play sound alert (optional)
          if (typeof Audio !== "undefined") {
            try {
              const audio = new Audio("/alert.mp3");
              audio.volume = 0.3;
              audio.play().catch(() => {});
            } catch (e) {}
          }
        }

        // Refresh all stats when new threat detected
        fetchHealth();
        fetchThreatsCount();
        fetchHoneypotsCount();
        break;
    }
  }, [lastMessage, health]);

  // Auto-refresh every 30 seconds (fallback)
  useEffect(() => {
    const interval = setInterval(() => {
      fetchHealth();
    }, 30000);

    return () => clearInterval(interval);
  }, []);

  if (loading) {
    return (
      <ProtectedRoute>
        <div className="flex items-center justify-center min-h-screen">
          <div className="text-center">
            <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary mx-auto mb-4"></div>
            <p className="text-slate-400">Loading dashboard...</p>
          </div>
        </div>
      </ProtectedRoute>
    );
  }

  return (
    <ProtectedRoute>
      <div className="p-6 space-y-6">
        {/* Hero Section - CYBER COMMAND CENTER */}
        <div className="relative overflow-hidden rounded-2xl p-1 group">
          {/* Animated border gradient */}
          <div className="absolute inset-0 bg-gradient-to-r from-purple-600 via-cyan-500 to-purple-600 opacity-75 blur-xl group-hover:opacity-100 transition-opacity duration-500 animate-pulse"></div>

          <div className="relative bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 rounded-2xl p-8 border border-purple-500/30">
            {/* Animated background particles */}
            <div className="absolute inset-0 overflow-hidden rounded-2xl pointer-events-none">
              <div className="absolute top-1/4 left-1/4 w-64 h-64 bg-purple-500/20 rounded-full blur-3xl animate-float"></div>
              <div className="absolute top-3/4 right-1/4 w-48 h-48 bg-cyan-500/20 rounded-full blur-3xl animate-float-delayed"></div>
              <div className="absolute bottom-1/4 left-3/4 w-56 h-56 bg-blue-500/20 rounded-full blur-3xl animate-float-slow"></div>
            </div>

            <div className="relative z-10">
              <div className="flex items-center justify-between mb-6">
                {/* Logo + Title with gradient animation */}
                <div className="space-y-2">
                  <div className="flex items-center gap-4">
                    <div className="relative">
                      <Shield className="w-12 h-12 text-purple-400 animate-pulse" />
                      <div className="absolute inset-0 bg-purple-500/20 blur-xl rounded-full animate-ping"></div>
                    </div>
                    <div>
                      <h1 className="text-5xl font-bold bg-gradient-to-r from-purple-400 via-cyan-400 to-purple-400 bg-clip-text text-transparent animate-gradient bg-300">
                        CyberGuardian AI
                      </h1>
                      <p className="text-sm text-cyan-400/80 font-mono tracking-wider animate-pulse">
                        Security Operations Center
                      </p>
                    </div>
                  </div>
                </div>

                {/* Enhanced WebSocket Status with Glow */}
                <div className="relative group">
                  <div
                    className={`absolute inset-0 blur-xl rounded-full ${
                      isConnected
                        ? "bg-green-500/50 animate-pulse"
                        : "bg-red-500/50"
                    }`}
                  ></div>
                  <div
                    className={`relative flex items-center gap-3 px-5 py-3 rounded-full backdrop-blur-sm border-2 transition-all duration-300 ${
                      isConnected
                        ? "bg-green-500/10 border-green-500/50 hover:border-green-400 hover:shadow-lg hover:shadow-green-500/50"
                        : "bg-red-500/10 border-red-500/50 hover:border-red-400"
                    }`}
                  >
                    {isConnected ? (
                      <>
                        <div className="relative">
                          <Wifi className="w-5 h-5 text-green-400 animate-pulse" />
                          <div className="absolute inset-0 bg-green-400/30 blur-md rounded-full"></div>
                        </div>
                        <div>
                          <span className="text-sm text-green-400 font-bold">
                            LIVE
                          </span>
                          <p className="text-xs text-green-400/60">
                            Real-time Protection
                          </p>
                        </div>
                      </>
                    ) : (
                      <>
                        <WifiOff className="w-5 h-5 text-red-400" />
                        <div>
                          <span className="text-sm text-red-400 font-bold">
                            OFFLINE
                          </span>
                          <p className="text-xs text-red-400/60">
                            Reconnecting...
                          </p>
                        </div>
                      </>
                    )}
                  </div>
                </div>
              </div>

              {/* Enhanced Tagline with Typing Effect */}
              <div className="mb-8 max-w-3xl">
                <p className="text-lg text-slate-300 leading-relaxed">
                  Your{" "}
                  <span className="text-transparent bg-clip-text bg-gradient-to-r from-purple-400 to-cyan-400 font-semibold">
                    advanced, AI-powered
                  </span>{" "}
                  security operations center — combining{" "}
                  <span className="text-cyan-400 font-semibold">
                    real-time threat detection
                  </span>
                  ,{" "}
                  <span className="text-purple-400 font-semibold">
                    behavioral analytics
                  </span>
                  ,{" "}
                  <span className="text-blue-400 font-semibold">
                    deception layers
                  </span>
                  , and{" "}
                  <span className="text-green-400 font-semibold">
                    predictive defense
                  </span>
                  .
                </p>
              </div>

              {/* Enhanced CTA Buttons with Neon Glow */}
              <div className="flex flex-wrap gap-4">
                {/* Primary CTA */}
                <button
                  onClick={() => navigate("/detection")}
                  className="group relative px-6 py-3 bg-gradient-to-r from-purple-600 to-cyan-600 rounded-lg font-semibold text-white overflow-hidden transition-all duration-300 hover:scale-105 hover:shadow-2xl hover:shadow-purple-500/50"
                >
                  <div className="absolute inset-0 bg-gradient-to-r from-cyan-600 to-purple-600 opacity-0 group-hover:opacity-100 transition-opacity duration-300"></div>
                  <div className="relative flex items-center gap-2">
                    <Activity className="w-5 h-5 animate-pulse" />
                    <span>Get Started</span>
                  </div>
                </button>

                {/* Secondary CTA */}
                <button
                  onClick={() => navigate("/analytics")}
                  className="group relative px-6 py-3 bg-slate-800/50 backdrop-blur-sm border-2 border-purple-500/30 rounded-lg font-semibold text-slate-300 overflow-hidden transition-all duration-300 hover:scale-105 hover:border-purple-400 hover:shadow-lg hover:shadow-purple-500/30"
                >
                  <div className="absolute inset-0 bg-gradient-to-r from-purple-600/10 to-cyan-600/10 opacity-0 group-hover:opacity-100 transition-opacity duration-300"></div>
                  <span className="relative">Learn More</span>
                </button>

                {/* Beta Badge */}
                <button className="group relative px-6 py-3 bg-gradient-to-r from-green-500/20 to-emerald-500/20 backdrop-blur-sm border-2 border-green-500/50 rounded-lg font-semibold text-green-400 overflow-hidden transition-all duration-300 hover:scale-105 hover:shadow-lg hover:shadow-green-500/50">
                  <div className="absolute inset-0 bg-gradient-to-r from-green-500/30 to-emerald-500/30 opacity-0 group-hover:opacity-100 transition-opacity duration-300"></div>
                  <div className="relative flex items-center gap-2">
                    <Shield className="w-5 h-5 animate-pulse" />
                    <span>Live Beta</span>
                    <span className="absolute -top-1 -right-1 w-2 h-2 bg-green-400 rounded-full animate-ping"></span>
                  </div>
                </button>
              </div>

              {/* Quick Stats Bar */}
              <div className="mt-8 grid grid-cols-3 gap-4 pt-6 border-t border-slate-700/50">
                <div className="text-center group hover:scale-105 transition-transform duration-300">
                  <div className="text-3xl font-bold bg-gradient-to-r from-green-400 to-emerald-400 bg-clip-text text-transparent">
                    99.8%
                  </div>
                  <div className="text-xs text-slate-400 mt-1">
                    Detection Rate
                  </div>
                </div>
                <div className="text-center group hover:scale-105 transition-transform duration-300">
                  <div className="text-3xl font-bold bg-gradient-to-r from-blue-400 to-cyan-400 bg-clip-text text-transparent">
                    &lt;100ms
                  </div>
                  <div className="text-xs text-slate-400 mt-1">
                    Response Time
                  </div>
                </div>
                <div className="text-center group hover:scale-105 transition-transform duration-300">
                  <div className="text-3xl font-bold bg-gradient-to-r from-purple-400 to-pink-400 bg-clip-text text-transparent">
                    24/7
                  </div>
                  <div className="text-xs text-slate-400 mt-1">
                    Active Protection
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Stats Grid - Enhanced */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
          {/* Protected Card */}
          <CardTilt>
            <div className="group relative stat-card p-6 overflow-hidden transition-all duration-500 hover:shadow-2xl hover:shadow-green-500/20">
              {/* Glow effect on hover */}
              <div className="absolute inset-0 bg-gradient-to-br from-green-500/0 to-green-500/0 group-hover:from-green-500/10 group-hover:to-transparent transition-all duration-500 rounded-xl"></div>

              <div className="relative z-10">
                <div className="flex items-center justify-between mb-4">
                  <div className="relative">
                    {/* Icon with animated glow */}
                    <div className="p-3 bg-green-500/20 rounded-xl group-hover:bg-green-500/30 transition-all duration-300 group-hover:scale-110">
                      <Shield className="w-6 h-6 text-green-400 group-hover:animate-pulse" />
                    </div>
                    {/* Pulsing ring */}
                    <div className="absolute inset-0 bg-green-500/20 rounded-xl blur-xl opacity-0 group-hover:opacity-100 animate-pulse"></div>
                  </div>
                  <span className="text-xs text-slate-400 uppercase tracking-wider font-semibold">
                    System
                  </span>
                </div>

                <h3 className="text-2xl font-bold mb-1 group-hover:text-green-400 transition-colors duration-300">
                  {health?.status === "healthy" ? "Protected" : "Warning"}
                </h3>
                <p className="text-sm text-slate-400">
                  {health?.system?.platform || health?.platform || "Linux"}
                </p>
              </div>

              {/* Decorative corner glow */}
              <div className="absolute -bottom-4 -right-4 w-24 h-24 bg-green-500/20 rounded-full blur-2xl opacity-0 group-hover:opacity-100 transition-opacity duration-500"></div>
            </div>
          </CardTilt>

          {/* Monitors Card */}
          <CardTilt>
            <div className="group relative stat-card p-6 overflow-hidden transition-all duration-500 hover:shadow-2xl hover:shadow-blue-500/20">
              <div className="absolute inset-0 bg-gradient-to-br from-blue-500/0 to-blue-500/0 group-hover:from-blue-500/10 group-hover:to-transparent transition-all duration-500 rounded-xl"></div>

              <div className="relative z-10">
                <div className="flex items-center justify-between mb-4">
                  <div className="relative">
                    <div className="p-3 bg-blue-500/20 rounded-xl group-hover:bg-blue-500/30 transition-all duration-300 group-hover:scale-110">
                      <Activity className="w-6 h-6 text-blue-400 group-hover:animate-pulse" />
                    </div>
                    <div className="absolute inset-0 bg-blue-500/20 rounded-xl blur-xl opacity-0 group-hover:opacity-100 animate-pulse"></div>
                  </div>
                  <span className="text-xs text-slate-400 uppercase tracking-wider font-semibold">
                    Monitors
                  </span>
                </div>

                <h3 className="text-2xl font-bold mb-1 group-hover:text-blue-400 transition-colors duration-300">
                  <CountUp end={monitorCount} />
                </h3>
                <p className="text-sm text-slate-400">Real-time scanning</p>
              </div>

              <div className="absolute -bottom-4 -right-4 w-24 h-24 bg-blue-500/20 rounded-full blur-2xl opacity-0 group-hover:opacity-100 transition-opacity duration-500"></div>
            </div>
          </CardTilt>

          {/* Threats Card */}
          <CardTilt>
            <div className="group relative stat-card p-6 overflow-hidden transition-all duration-500 hover:shadow-2xl hover:shadow-red-500/20">
              <div className="absolute inset-0 bg-gradient-to-br from-red-500/0 to-red-500/0 group-hover:from-red-500/10 group-hover:to-transparent transition-all duration-500 rounded-xl"></div>

              <div className="relative z-10">
                <div className="flex items-center justify-between mb-4">
                  <div className="relative">
                    <div className="p-3 bg-red-500/20 rounded-xl group-hover:bg-red-500/30 transition-all duration-300 group-hover:scale-110">
                      <AlertTriangle className="w-6 h-6 text-red-400 group-hover:animate-pulse" />
                    </div>
                    <div className="absolute inset-0 bg-red-500/20 rounded-xl blur-xl opacity-0 group-hover:opacity-100 animate-pulse"></div>
                  </div>
                  <span className="text-xs text-slate-400 uppercase tracking-wider font-semibold">
                    Threats
                  </span>
                </div>

                <h3 className="text-2xl font-bold mb-1 group-hover:text-red-400 transition-colors duration-300">
                  <CountUp end={threatCount} />
                </h3>
                <p className="text-sm text-slate-400">Last 24 hours</p>
              </div>

              <div className="absolute -bottom-4 -right-4 w-24 h-24 bg-red-500/20 rounded-full blur-2xl opacity-0 group-hover:opacity-100 transition-opacity duration-500"></div>
            </div>
          </CardTilt>

          {/* Honeypots Card */}
          <CardTilt>
            <div className="group relative stat-card p-6 overflow-hidden transition-all duration-500 hover:shadow-2xl hover:shadow-purple-500/20">
              <div className="absolute inset-0 bg-gradient-to-br from-purple-500/0 to-purple-500/0 group-hover:from-purple-500/10 group-hover:to-transparent transition-all duration-500 rounded-xl"></div>

              <div className="relative z-10">
                <div className="flex items-center justify-between mb-4">
                  <div className="relative">
                    <div className="p-3 bg-purple-500/20 rounded-xl group-hover:bg-purple-500/30 transition-all duration-300 group-hover:scale-110">
                      <Eye className="w-6 h-6 text-purple-400 group-hover:animate-pulse" />
                    </div>
                    <div className="absolute inset-0 bg-purple-500/20 rounded-xl blur-xl opacity-0 group-hover:opacity-100 animate-pulse"></div>
                  </div>
                  <span className="text-xs text-slate-400 uppercase tracking-wider font-semibold">
                    Honeypots
                  </span>
                </div>

                <h3 className="text-2xl font-bold mb-1 group-hover:text-purple-400 transition-colors duration-300">
                  <CountUp end={honeypotCount} />
                </h3>
                <p className="text-sm text-slate-400">Deception layer ready</p>
              </div>

              <div className="absolute -bottom-4 -right-4 w-24 h-24 bg-purple-500/20 rounded-full blur-2xl opacity-0 group-hover:opacity-100 transition-opacity duration-500"></div>
            </div>
          </CardTilt>
        </div>
        {/* License Info Card */}
        <div className="card-premium p-6 transition-all duration-300 hover:shadow-lg hover:shadow-cyan-500/20">
          <div className="flex items-center justify-between mb-6">
            <h3 className="text-xl font-bold flex items-center gap-2">
              <Shield className="h-6 w-6 text-cyan-400" />
              License Information
            </h3>
            <span
              className={`px-3 py-1 rounded-full text-xs font-bold border ${
                localStorage.getItem("license_plan") === "enterprise"
                  ? "bg-purple-500/20 text-purple-400 border-purple-500/50"
                  : localStorage.getItem("license_plan") === "business"
                  ? "bg-blue-500/20 text-blue-400 border-blue-500/50"
                  : "bg-green-500/20 text-green-400 border-green-500/50"
              }`}
            >
              {(localStorage.getItem("license_plan") || "FREE").toUpperCase()}
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
            {/* License Key */}
            <div className="p-4 rounded-lg bg-slate-800/50 border border-slate-700">
              <div className="text-sm text-slate-400 mb-1">License Key</div>
              <div className="font-mono text-xs text-cyan-400 break-all">
                {localStorage.getItem("license_key") || "Not activated"}
              </div>
            </div>

            {/* Expiry Date */}
            <div className="p-4 rounded-lg bg-slate-800/50 border border-slate-700">
              <div className="text-sm text-slate-400 mb-1">Expires</div>
              <div className="font-semibold text-white">
                {localStorage.getItem("license_expires")
                  ? new Date(
                      localStorage.getItem("license_expires")!
                    ).toLocaleDateString()
                  : "Never"}
              </div>
            </div>

            {/* Days Remaining */}
            <div className="p-4 rounded-lg bg-slate-800/50 border border-slate-700">
              <div className="text-sm text-slate-400 mb-1">Days Remaining</div>
              <div className="font-semibold text-green-400">
                {localStorage.getItem("license_expires")
                  ? Math.max(
                      0,
                      Math.floor(
                        (new Date(
                          localStorage.getItem("license_expires")!
                        ).getTime() -
                          Date.now()) /
                          (1000 * 60 * 60 * 24)
                      )
                    )
                  : "∞"}
              </div>
            </div>
          </div>

          {/* Device Usage */}
          <div className="mb-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-slate-400">Device Usage</span>
              <span className="text-sm font-semibold">
                1 /{" "}
                {localStorage.getItem("license_plan") === "enterprise"
                  ? "100"
                  : localStorage.getItem("license_plan") === "business"
                  ? "5"
                  : "1"}{" "}
                devices
              </span>
            </div>
            <div className="w-full bg-slate-700/50 rounded-full h-3 overflow-hidden">
              <div
                className="bg-gradient-to-r from-cyan-500 to-blue-500 h-3 rounded-full transition-all duration-500"
                style={{
                  width: `${
                    (1 /
                      (localStorage.getItem("license_plan") === "enterprise"
                        ? 100
                        : localStorage.getItem("license_plan") === "business"
                        ? 5
                        : 1)) *
                    100
                  }%`,
                }}
              />
            </div>
          </div>

          {/* Status Indicator */}
          <div className="flex items-center gap-2 p-3 rounded-lg bg-green-500/10 border border-green-500/30">
            <div className="w-2 h-2 bg-green-400 rounded-full animate-pulse"></div>
            <span className="text-sm font-medium text-green-400">
              License Active
            </span>
          </div>
        </div>

        {/* Dashboard Connected Indicator */}
        <div className="flex items-center justify-center p-4 bg-gradient-to-r from-green-500/10 to-blue-500/10 rounded-xl border border-green-500/20">
          <div className="flex items-center gap-3">
            <div
              className={`w-3 h-3 rounded-full ${
                isConnected ? "bg-green-400 animate-pulse" : "bg-gray-400"
              }`}
            ></div>
            <span className="text-sm font-medium">
              {isConnected
                ? "Dashboard Connected to API! Live API Data: Frontend successfully connected to backend!"
                : "Connecting to API..."}
            </span>
          </div>

          {health && (
            <div className="ml-auto flex gap-6 text-sm text-slate-400">
              <div>
                CPU Usage:{" "}
                <span className="text-primary font-semibold">
                  {(
                    (health.system?.cpu_percent ?? health.cpu_usage) ||
                    0
                  ).toFixed(1)}
                  %
                </span>
              </div>
              <div>
                Memory Usage:{" "}
                <span className="text-primary font-semibold">
                  {(
                    (health.system?.memory_percent ?? health.memory_usage) ||
                    0
                  ).toFixed(1)}
                  %
                </span>
              </div>
              <div>
                Uptime:{" "}
                <span className="text-primary font-semibold">
                  {health.uptime || "0m"}
                </span>
              </div>
            </div>
          )}
        </div>

        {/* Threat Activity Chart */}
        <ThreatActivityChart />

        {/* Security Posture Score */}
        {securityPosture && (
          <div className="stat-card p-6">
            <div className="flex items-center justify-between mb-6">
              <div>
                <h3 className="text-xl font-bold mb-1">Security Posture</h3>
                <p className="text-sm text-slate-400">
                  Overall system security score
                </p>
              </div>
              <div
                className={`px-3 py-1 rounded-full text-xs font-semibold ${
                  securityPosture.color === "green"
                    ? "bg-green-500/20 text-green-400"
                    : securityPosture.color === "blue"
                    ? "bg-blue-500/20 text-blue-400"
                    : securityPosture.color === "yellow"
                    ? "bg-yellow-500/20 text-yellow-400"
                    : "bg-red-500/20 text-red-400"
                }`}
              >
                {securityPosture.status.toUpperCase()}
              </div>
            </div>

            {/* Score Gauge */}
            <div className="flex items-center justify-center mb-6">
              <div className="relative w-48 h-48">
                <svg className="w-full h-full transform -rotate-90">
                  <circle
                    cx="96"
                    cy="96"
                    r="88"
                    stroke="rgba(148, 163, 184, 0.1)"
                    strokeWidth="12"
                    fill="none"
                  />
                  <circle
                    cx="96"
                    cy="96"
                    r="88"
                    stroke={
                      securityPosture.color === "green"
                        ? "#10b981"
                        : securityPosture.color === "blue"
                        ? "#3b82f6"
                        : securityPosture.color === "yellow"
                        ? "#f59e0b"
                        : "#ef4444"
                    }
                    strokeWidth="12"
                    fill="none"
                    strokeDasharray={`${
                      (securityPosture.score / 100) * 552.92
                    } 552.92`}
                    strokeLinecap="round"
                    className="transition-all duration-1000"
                  />
                </svg>
                <div className="absolute inset-0 flex items-center justify-center flex-col">
                  <div className="text-5xl font-bold">
                    <CountUp end={securityPosture.score} />
                  </div>
                  <div className="text-sm text-slate-400 mt-1">out of 100</div>
                </div>
              </div>
            </div>

            {/* Factors */}
            <div className="grid grid-cols-2 gap-3 text-sm">
              <div className="flex justify-between">
                <span className="text-slate-400">Active Threats:</span>
                <span className="font-semibold">
                  {securityPosture.factors.active_threats}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Protection:</span>
                <span className="font-semibold">
                  {securityPosture.factors.protection_enabled ? "ON" : "OFF"}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Honeypots:</span>
                <span className="font-semibold">
                  {securityPosture.factors.active_honeypots}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Recent Scans:</span>
                <span className="font-semibold">
                  {securityPosture.factors.recent_scans}
                </span>
              </div>
            </div>
          </div>
        )}

        {/* Recent Incidents */}
        {recentIncidents.length > 0 && (
          <div className="stat-card p-6">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-xl font-bold">Recent Security Incidents</h3>
              <span className="text-sm text-slate-400">
                Last 5 threats detected
              </span>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-slate-700">
                    <th className="text-left py-3 px-4 text-sm font-semibold text-slate-400">
                      Time
                    </th>
                    <th className="text-left py-3 px-4 text-sm font-semibold text-slate-400">
                      Source IP
                    </th>
                    <th className="text-left py-3 px-4 text-sm font-semibold text-slate-400">
                      Threat Type
                    </th>
                    <th className="text-left py-3 px-4 text-sm font-semibold text-slate-400">
                      Severity
                    </th>
                    <th className="text-left py-3 px-4 text-sm font-semibold text-slate-400">
                      Status
                    </th>
                    <th className="text-left py-3 px-4 text-sm font-semibold text-slate-400">
                      Description
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {recentIncidents.map((incident) => (
                    <tr
                      key={incident.id}
                      className="group border-b border-slate-700/50 hover:bg-slate-800/50 transition-all duration-300 cursor-pointer relative overflow-hidden"
                    >
                      {/* Hover glow effect */}
                      <td
                        colSpan={6}
                        className="absolute inset-0 pointer-events-none"
                      >
                        <div
                          className={`absolute inset-0 opacity-0 group-hover:opacity-100 transition-opacity duration-300 ${
                            incident.severity === "critical"
                              ? "bg-gradient-to-r from-red-500/10 to-transparent"
                              : incident.severity === "high"
                              ? "bg-gradient-to-r from-orange-500/10 to-transparent"
                              : incident.severity === "medium"
                              ? "bg-gradient-to-r from-yellow-500/10 to-transparent"
                              : "bg-gradient-to-r from-blue-500/10 to-transparent"
                          }`}
                        ></div>
                      </td>

                      {/* Time */}
                      <td className="py-3 px-4 text-sm text-slate-300 relative z-10">
                        {new Date(incident.timestamp).toLocaleTimeString(
                          "en-US",
                          {
                            hour: "2-digit",
                            minute: "2-digit",
                          }
                        )}
                      </td>

                      {/* Source IP */}
                      <td className="py-3 px-4 text-sm font-mono text-slate-300 relative z-10 group-hover:text-cyan-400 transition-colors">
                        {incident.source_ip}
                      </td>

                      {/* Threat Type */}
                      <td className="py-3 px-4 text-sm font-medium relative z-10 group-hover:text-white transition-colors">
                        {incident.threat_type}
                      </td>

                      {/* Severity - Enhanced Badge */}
                      <td className="py-3 px-4 text-sm relative z-10">
                        <span
                          className={`inline-flex items-center gap-1 px-3 py-1 rounded-full text-xs font-bold border transition-all duration-300 group-hover:scale-110 group-hover:shadow-lg ${
                            incident.severity === "critical"
                              ? "bg-red-500/20 text-red-400 border-red-500/50 group-hover:bg-red-500/30 group-hover:border-red-400 group-hover:shadow-red-500/50"
                              : incident.severity === "high"
                              ? "bg-orange-500/20 text-orange-400 border-orange-500/50 group-hover:bg-orange-500/30 group-hover:border-orange-400 group-hover:shadow-orange-500/50"
                              : incident.severity === "medium"
                              ? "bg-yellow-500/20 text-yellow-400 border-yellow-500/50 group-hover:bg-yellow-500/30 group-hover:border-yellow-400 group-hover:shadow-yellow-500/50"
                              : "bg-blue-500/20 text-blue-400 border-blue-500/50 group-hover:bg-blue-500/30 group-hover:border-blue-400 group-hover:shadow-blue-500/50"
                          }`}
                        >
                          {incident.severity === "critical" && (
                            <span className="w-1.5 h-1.5 bg-red-400 rounded-full animate-pulse"></span>
                          )}
                          {incident.severity.toUpperCase()}
                        </span>
                      </td>

                      {/* Status - Enhanced Badge */}
                      <td className="py-3 px-4 text-sm relative z-10">
                        <span
                          className={`inline-flex items-center gap-1 px-3 py-1 rounded-full text-xs font-bold border transition-all duration-300 group-hover:scale-110 ${
                            incident.status === "active"
                              ? "bg-red-500/20 text-red-400 border-red-500/50 group-hover:bg-red-500/30"
                              : incident.status === "blocked"
                              ? "bg-green-500/20 text-green-400 border-green-500/50 group-hover:bg-green-500/30"
                              : "bg-gray-500/20 text-gray-400 border-gray-500/50"
                          }`}
                        >
                          {incident.status === "active" && (
                            <span className="w-1.5 h-1.5 bg-red-400 rounded-full animate-pulse"></span>
                          )}
                          {incident.status.toUpperCase()}
                        </span>
                      </td>

                      {/* Description */}
                      <td className="py-3 px-4 text-sm text-slate-400 relative z-10 group-hover:text-slate-300 transition-colors">
                        {incident.description}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* System Metrics - Enhanced */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Detection Rate */}
          <div className="group stat-card p-6 hover:shadow-2xl hover:shadow-green-500/20 transition-all duration-300">
            <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
              <div className="w-2 h-2 bg-green-400 rounded-full animate-pulse"></div>
              Detection Rate
            </h3>
            <div className="space-y-3">
              <div className="flex justify-between text-sm">
                <span className="text-slate-400 group-hover:text-slate-300 transition-colors">
                  Success Rate
                </span>
                <span className="font-bold text-2xl text-green-400 group-hover:scale-110 transition-transform inline-block">
                  <CountUp end={99.8} duration={1500} suffix="%" />
                </span>
              </div>
              <div className="relative w-full bg-slate-700/50 rounded-full h-3 overflow-hidden">
                {/* Animated background shimmer */}
                <div className="absolute inset-0 bg-gradient-to-r from-transparent via-green-400/20 to-transparent animate-shimmer"></div>

                {/* Animated progress bar */}
                <div
                  className="bg-gradient-to-r from-green-400 to-emerald-500 h-3 rounded-full transition-all duration-1000 ease-out shadow-lg shadow-green-500/50 relative overflow-hidden"
                  style={{
                    width: "0%",
                    animation: "fillBar 2s ease-out forwards",
                  }}
                >
                  {/* Glow effect */}
                  <div className="absolute inset-0 bg-gradient-to-r from-transparent via-white/30 to-transparent animate-shimmer"></div>
                </div>
              </div>
            </div>
          </div>

          {/* Response Time */}
          <div className="group stat-card p-6 hover:shadow-2xl hover:shadow-blue-500/20 transition-all duration-300">
            <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
              <div className="w-2 h-2 bg-blue-400 rounded-full animate-pulse"></div>
              Response Time
            </h3>
            <div className="space-y-3">
              <div className="flex justify-between text-sm">
                <span className="text-slate-400 group-hover:text-slate-300 transition-colors">
                  Average
                </span>
                <span className="font-bold text-2xl text-blue-400 group-hover:scale-110 transition-transform inline-block">
                  &lt; <CountUp end={100} duration={1500} />
                  ms
                </span>
              </div>
              <div className="relative w-full bg-slate-700/50 rounded-full h-3 overflow-hidden">
                <div className="absolute inset-0 bg-gradient-to-r from-transparent via-blue-400/20 to-transparent animate-shimmer"></div>

                <div
                  className="bg-gradient-to-r from-blue-400 to-cyan-500 h-3 rounded-full transition-all duration-1000 ease-out shadow-lg shadow-blue-500/50 relative overflow-hidden"
                  style={{
                    width: "0%",
                    animation: "fillBar 2s ease-out 0.3s forwards",
                  }}
                >
                  <div className="absolute inset-0 bg-gradient-to-r from-transparent via-white/30 to-transparent animate-shimmer"></div>
                </div>
              </div>
            </div>
          </div>

          {/* Protection */}
          <div className="group stat-card p-6 hover:shadow-2xl hover:shadow-purple-500/20 transition-all duration-300">
            <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
              <div className="w-2 h-2 bg-purple-400 rounded-full animate-pulse"></div>
              Protection
            </h3>
            <div className="space-y-3">
              <div className="flex justify-between text-sm">
                <span className="text-slate-400 group-hover:text-slate-300 transition-colors">
                  24/7 Active
                </span>
                <span className="font-bold text-2xl text-purple-400 group-hover:scale-110 transition-transform inline-block">
                  Online
                </span>
              </div>
              <div className="relative w-full bg-slate-700/50 rounded-full h-3 overflow-hidden">
                <div className="absolute inset-0 bg-gradient-to-r from-transparent via-purple-400/20 to-transparent animate-shimmer"></div>

                <div
                  className="bg-gradient-to-r from-purple-400 to-pink-500 h-3 rounded-full transition-all duration-1000 ease-out shadow-lg shadow-purple-500/50 relative overflow-hidden"
                  style={{
                    width: "0%",
                    animation: "fillBar 2s ease-out 0.6s forwards",
                  }}
                >
                  <div className="absolute inset-0 bg-gradient-to-r from-transparent via-white/30 to-transparent animate-shimmer"></div>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Live Threat Notification */}
        <LiveThreatNotification
          threat={currentThreat}
          onClose={() => setCurrentThreat(null)}
        />
      </div>
    </ProtectedRoute>
  );
}
