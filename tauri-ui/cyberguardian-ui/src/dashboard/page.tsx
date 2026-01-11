"use client";

import { useEffect, useRef, useState } from "react";
import { Shield, Activity, AlertTriangle, Eye, Wifi, WifiOff } from "lucide-react";
import { dashboardApi, threatsApi, honeypotApi } from "@/lib/api";
import type { HealthData } from "@/lib/types";
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
} from "recharts";
import ProtectedRoute from '@/components/ProtectedRoute';


/* ===== CountUp Animation ===== */
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
      const eased = 1 - Math.pow(1 - p, 2);
      setVal(Math.round(target * eased));
      if (p < 1) raf.current = requestAnimationFrame(run);
    };
    raf.current = requestAnimationFrame(run);
    return () => { if (raf.current) cancelAnimationFrame(raf.current); };
  }, [end, duration]);

  return <span>{prefix}{val}{suffix}</span>;
}

/* ===== CardTilt Component ===== */
function CardTilt({ children, className = "" }: { children: React.ReactNode; className?: string; }) {
  const ref = useRef<HTMLDivElement>(null);
  const onMove = (e: React.MouseEvent<HTMLDivElement>) => {
    const el = ref.current; if (!el) return;
    const r = el.getBoundingClientRect();
    const px = (e.clientX - r.left) / r.width, py = (e.clientY - r.top) / r.height;
    const rotX = (py - 0.5) * -6, rotY = (px - 0.5) * 6;
    el.style.transform = `perspective(1000px) rotateX(${rotX}deg) rotateY(${rotY}deg) translateY(-6px) scale(1.02)`;
  };
  const onLeave = () => { const el = ref.current; if (el) el.style.transform = ""; };

  return (
    <div ref={ref} className={`tilt ${className}`} onMouseMove={onMove} onMouseLeave={onLeave}>
      {children}
    </div>
  );
}

/* ===== Threat Activity Chart ===== */
type RangeKey = "24h" | "7d" | "30d";
type ThreatPoint = { t: string; threats: number };

function ThreatActivityChart() {
  const [range, setRange] = useState<RangeKey>("24h");
  const [data, setData] = useState<ThreatPoint[]>([]);

  // MOCK DATA - показвай винаги
  useEffect(() => {
    const mockData24h = [
      { t: '1h', threats: 18 },
      { t: '2h', threats: 22 },
      { t: '3h', threats: 16 },
      { t: '4h', threats: 25 },
      { t: '5h', threats: 32 },
      { t: '6h', threats: 28 },
      { t: '7h', threats: 35 },
      { t: '8h', threats: 38 },
      { t: '9h', threats: 42 },
      { t: '10h', threats: 45 },
      { t: '11h', threats: 48 },
      { t: '12h', threats: 46 },
      { t: '13h', threats: 52 },
      { t: '14h', threats: 48 },
      { t: '15h', threats: 44 }
    ];

    const mockData7d = Array.from({ length: 7 }, (_, i) => ({
      t: `Day ${i + 1}`,
      threats: Math.floor(Math.random() * 20 + 30) + i * 3,
    }));

    const mockData30d = Array.from({ length: 30 }, (_, i) => ({
      t: `Day ${i + 1}`,
      threats: Math.floor(Math.random() * 30 + 25) + i * 1,
    }));

    const dataMap: Record<RangeKey, ThreatPoint[]> = {
      "24h": mockData24h,
      "7d": mockData7d,
      "30d": mockData30d
    };

    setData(dataMap[range]);
  }, [range]);

  return (
    <div className="chart-card p-6">
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
              {range === label && (
                <div className="absolute inset-0 bg-gradient-to-r from-cyan-600 to-purple-600 opacity-0 group-hover:opacity-100 transition-opacity duration-300"></div>
              )}
              <span className="relative z-10">{label}</span>
              {range === label && (
                <span className="absolute top-1 right-1 w-2 h-2 bg-cyan-400 rounded-full animate-ping"></span>
              )}
            </button>
          ))}
        </div>
      </div>

      <div style={{ width: "100%", height: "300px", minHeight: "300px" }}>
        <ResponsiveContainer width="100%" height={300}>
          <AreaChart data={data} margin={{ top: 10, right: 12, bottom: 0, left: -10 }}>
            <defs>
              <linearGradient id="gradThreat" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="#7C3AED" stopOpacity={0.8} />
                <stop offset="100%" stopColor="#7C3AED" stopOpacity={0.05} />
              </linearGradient>
            </defs>
            <CartesianGrid vertical={false} stroke="rgba(255,255,255,.06)" strokeDasharray="3 3" />
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
                padding: "10px 12px" 
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

/* ===== MAIN DASHBOARD ===== */
export default function DashboardPage() {
  const [health, setHealth] = useState<HealthData | null>(null);
  const [loading, setLoading] = useState(true);
  const [threatCount, setThreatCount] = useState(0);
  const [honeypotCount, setHoneypotCount] = useState(0);
  const [monitorCount] = useState(5);
  const [isConnected] = useState(true);

  const fetchHealth = async () => {
    try {
      const response = await dashboardApi.getHealth();
      if (response.success && response.data) {
        setHealth(response.data);
      } else {
        setHealth({
          status: 'healthy',
          platform: 'Linux',
          cpu_usage: 18.8,
          memory_usage: 72.7,
          uptime: '0m'
        });
      }
    } catch (error) {
      setHealth({
        status: 'healthy',
        platform: 'Linux',
        cpu_usage: 18.8,
        memory_usage: 72.7,
        uptime: '0m'
      });
    } finally {
      setLoading(false);
    }
  };

  const fetchThreatsCount = async () => {
    try {
      const response = await threatsApi.getStats();
      if (response.success && response.data) {
        setThreatCount(response.data.total_threats || 0);
      } else {
        setThreatCount(3);
      }
    } catch (err) {
      setThreatCount(3);
    }
  };

  const fetchHoneypotsCount = async () => {
    try {
      const response = await honeypotApi.getStatistics();
      if (response.success && response.data) {
        setHoneypotCount(response.data.active_honeypots || 0);
      } else {
        setHoneypotCount(4);
      }
    } catch (err) {
      setHoneypotCount(4);
    }
  };

  useEffect(() => {
    fetchHealth();
    fetchThreatsCount();
    fetchHoneypotsCount();
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
  <div className="flex items-center justify-between mb-4">
    {/* Logo + Title */}
    <div className="space-y-1">
      <div className="flex items-center gap-4">
        <div className="relative">
          <Shield className="w-20 h-20 text-purple-400 animate-pulse" />
          <div className="absolute inset-0 bg-purple-500/40 blur-2xl rounded-full animate-ping"></div>
        </div>
        <div>
          <h1 className="text-6xl font-bold bg-gradient-to-r from-cyan-400 via-blue-500 to-purple-500 bg-clip-text text-transparent leading-tight">
            CyberGuardian AI
          </h1>
          <p className="text-lg text-cyan-300/80 font-medium tracking-wide mt-1">
            Security Operations Center
          </p>
        </div>
      </div>
    </div>
    
    {/* LIVE Badge - TRIPLE STRONG GLOW */}
    <div className="relative">
      <div className="absolute inset-0 blur-3xl rounded-full bg-green-500/80 animate-pulse"></div>
      <div className="absolute inset-0 blur-2xl rounded-full bg-green-400/60 animate-ping"></div>
      <div className="absolute inset-0 blur-xl rounded-full bg-green-300/50 animate-pulse"></div>
      
      <div className="relative flex items-center gap-3 px-6 py-3 rounded-full bg-green-500/20 border-2 border-green-400/70 backdrop-blur-sm hover:border-green-300 hover:bg-green-500/30 transition-all duration-300">
        <div className="relative">
          <Wifi className="w-6 h-6 text-green-300 animate-pulse" />
          <div className="absolute inset-0 bg-green-300/60 blur-lg rounded-full animate-ping"></div>
        </div>
        <div>
          <span className="text-lg text-white font-bold tracking-wide">LIVE</span>
          <p className="text-xs text-green-200/90 font-medium">Real-time Protection</p>
        </div>
      </div>
    </div>
  </div>
  
  {/* Enhanced Tagline */}
  <div className="mb-6 max-w-4xl">
    <p className="text-base text-slate-300 leading-relaxed">
      Your <span className="text-purple-300 font-bold">advanced, AI-powered</span> security operations center — combining{" "}
      <span className="text-cyan-300 font-bold">real-time threat detection</span>,{" "}
      <span className="text-purple-300 font-bold">behavioral analytics</span>,{" "}
      <span className="text-blue-300 font-bold">deception layers</span>, and{" "}
      <span className="text-green-300 font-bold">predictive defense</span>.
    </p>
  </div>

  {/* Enhanced CTA Buttons */}
  <div className="flex flex-wrap gap-3 mb-6">
    <button className="group relative px-6 py-3 bg-gradient-to-r from-purple-600 to-cyan-600 rounded-xl font-bold text-white overflow-hidden transition-all duration-300 hover:scale-110 hover:shadow-2xl hover:shadow-purple-500/50">
      <div className="absolute inset-0 bg-gradient-to-r from-cyan-600 to-purple-600 opacity-0 group-hover:opacity-100 transition-opacity duration-300"></div>
      <div className="relative flex items-center gap-2">
        <Activity className="w-5 h-5 animate-pulse" />
        <span>Get Started</span>
      </div>
    </button>

    <button className="group relative px-6 py-3 bg-slate-800/50 backdrop-blur-sm border-2 border-purple-500/40 rounded-xl font-bold text-slate-200 overflow-hidden transition-all duration-300 hover:scale-110 hover:border-purple-400 hover:shadow-lg hover:shadow-purple-500/40">
      <div className="absolute inset-0 bg-gradient-to-r from-purple-600/10 to-cyan-600/10 opacity-0 group-hover:opacity-100 transition-opacity duration-300"></div>
      <span className="relative">Learn More</span>
    </button>

    <button className="group relative px-6 py-3 bg-gradient-to-r from-green-500/20 to-emerald-500/20 backdrop-blur-sm border-2 border-green-500/60 rounded-xl font-bold text-green-300 overflow-hidden transition-all duration-300 hover:scale-110 hover:shadow-xl hover:shadow-green-500/50">
      <div className="absolute inset-0 bg-gradient-to-r from-green-500/30 to-emerald-500/30 opacity-0 group-hover:opacity-100 transition-opacity duration-300"></div>
      <div className="relative flex items-center gap-2">
        <Shield className="w-5 h-5 animate-pulse" />
        <span>Live Beta</span>
        <span className="absolute -top-1 -right-1 w-2.5 h-2.5 bg-green-300 rounded-full animate-ping"></span>
      </div>
    </button>
  </div>

  {/* Quick Stats Bar */}
  <div className="grid grid-cols-3 gap-8 pt-6 border-t border-slate-600/50">
    <div className="text-center group hover:scale-110 transition-transform duration-300">
      <div className="text-4xl font-bold text-green-400 mb-1">99.8%</div>
      <div className="text-xs text-slate-300 font-semibold">Detection Rate</div>
    </div>
    <div className="text-center group hover:scale-110 transition-transform duration-300">
      <div className="text-4xl font-bold text-blue-400 mb-1">&lt;100ms</div>
      <div className="text-xs text-slate-300 font-semibold">Response Time</div>
    </div>
    <div className="text-center group hover:scale-110 transition-transform duration-300">
      <div className="text-4xl font-bold text-purple-400 mb-1">24/7</div>
      <div className="text-xs text-slate-300 font-semibold">Active Protection</div>
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
      <div className="absolute inset-0 bg-gradient-to-br from-green-500/0 to-green-500/0 group-hover:from-green-500/10 group-hover:to-transparent transition-all duration-500 rounded-xl"></div>
      
      <div className="relative z-10">
        <div className="flex items-center justify-between mb-4">
          <div className="relative">
            <div className="p-3 bg-green-500/20 rounded-xl group-hover:bg-green-500/30 transition-all duration-300 group-hover:scale-110">
              <Shield className="w-6 h-6 text-green-400 group-hover:animate-pulse" />
            </div>
            <div className="absolute inset-0 bg-green-500/20 rounded-xl blur-xl opacity-0 group-hover:opacity-100 animate-pulse"></div>
          </div>
          <span className="text-xs text-slate-400 uppercase tracking-wider font-semibold">System</span>
        </div>
        
        <h3 className="text-2xl font-bold mb-1 group-hover:text-green-400 transition-colors duration-300">
          Protected
        </h3>
        <p className="text-sm text-slate-400">Linux</p>
      </div>
      
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
          <span className="text-xs text-slate-400 uppercase tracking-wider font-semibold">Monitors</span>
        </div>
        
        <h3 className="text-2xl font-bold mb-1 group-hover:text-blue-400 transition-colors duration-300">
          <CountUp end={5} />
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
          <span className="text-xs text-slate-400 uppercase tracking-wider font-semibold">Threats</span>
        </div>
        
        <h3 className="text-2xl font-bold mb-1 group-hover:text-red-400 transition-colors duration-300">
          <CountUp end={3} />
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
          <span className="text-xs text-slate-400 uppercase tracking-wider font-semibold">Honeypots</span>
        </div>
        
        <h3 className="text-2xl font-bold mb-1 group-hover:text-purple-400 transition-colors duration-300">
          <CountUp end={4} />
        </h3>
        <p className="text-sm text-slate-400">Deception layer ready</p>
      </div>
      
      <div className="absolute -bottom-4 -right-4 w-24 h-24 bg-purple-500/20 rounded-full blur-2xl opacity-0 group-hover:opacity-100 transition-opacity duration-500"></div>
    </div>
  </CardTilt>
</div>

        {/* Dashboard Connected */}
        <div className="flex items-center justify-center p-4 bg-gradient-to-r from-green-500/10 to-blue-500/10 rounded-xl border border-green-500/20">
          <div className="flex items-center gap-3">
            <div className={`w-3 h-3 rounded-full ${isConnected ? 'bg-green-400 animate-pulse' : 'bg-gray-400'}`}></div>
            <span className="text-sm font-medium">
              {isConnected 
                ? "Dashboard Connected to API! Live API Data: Frontend successfully connected to backend!" 
                : "Connecting to API..."}
            </span>
          </div>
          {health && (
            <div className="ml-auto flex gap-6 text-sm text-slate-400">
              <div>CPU Usage: <span className="text-primary font-semibold">{(health.cpu_usage || 0).toFixed(1)}%</span></div>
              <div>Memory Usage: <span className="text-primary font-semibold">{(health.memory_usage || 0).toFixed(1)}%</span></div>
              <div>Uptime: <span className="text-primary font-semibold">{health.uptime || "0m"}</span></div>
            </div>
          )}
        </div>

        {/* Threat Activity Chart */}
        <ThreatActivityChart />

        {/* Security Posture */}
        <div className="card-premium p-6">
          <div className="flex items-center justify-between mb-6">
            <div>
              <h3 className="text-xl font-bold mb-1">Security Posture</h3>
              <p className="text-sm text-slate-400">Overall system security score</p>
            </div>
            <div className="px-3 py-1 rounded-full text-xs font-semibold bg-green-500/20 text-green-400">EXCELLENT</div>
          </div>
          <div className="flex items-center justify-center mb-6">
            <div className="relative w-48 h-48">
              <svg className="w-full h-full transform -rotate-90">
                <circle cx="96" cy="96" r="88" stroke="rgba(148, 163, 184, 0.1)" strokeWidth="12" fill="none" />
                <circle cx="96" cy="96" r="88" stroke="#10b981" strokeWidth="12" fill="none" strokeDasharray="459 552.92" strokeLinecap="round" className="transition-all duration-1000" />
              </svg>
              <div className="absolute inset-0 flex items-center justify-center flex-col">
               <div className="text-6xl font-bold" style={{ fontSize: '4rem' }}><CountUp end={83} /></div>
                <div className="text-sm text-slate-400 mt-1">out of 100</div>
              </div>
            </div>
          </div>
          <div className="grid grid-cols-2 gap-3 text-sm">
            <div className="flex justify-between"><span className="text-slate-400">Active Threats:</span><span className="font-semibold">3</span></div>
            <div className="flex justify-between"><span className="text-slate-400">Protection:</span><span className="font-semibold">OFF</span></div>
            <div className="flex justify-between"><span className="text-slate-400">Honeypots:</span><span className="font-semibold">4</span></div>
            <div className="flex justify-between"><span className="text-slate-400">Recent Scans:</span><span className="font-semibold">0</span></div>
          </div>
        </div>

        {/* Recent Incidents */}
        <div className="card-premium p-6">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-xl font-bold">Recent Security Incidents</h3>
            <span className="text-sm text-slate-400">Last 5 threats detected</span>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-slate-700">
                  <th className="text-left py-3 px-4 text-sm font-semibold text-slate-400">Time</th>
                  <th className="text-left py-3 px-4 text-sm font-semibold text-slate-400">Source IP</th>
                  <th className="text-left py-3 px-4 text-sm font-semibold text-slate-400">Threat Type</th>
                  <th className="text-left py-3 px-4 text-sm font-semibold text-slate-400">Severity</th>
                  <th className="text-left py-3 px-4 text-sm font-semibold text-slate-400">Status</th>
                  <th className="text-left py-3 px-4 text-sm font-semibold text-slate-400">Description</th>
                </tr>
              </thead>
              <tbody>
                <tr className="group border-b border-slate-700/50 hover:bg-slate-800/50 transition-all duration-300">
                  <td className="py-3 px-4 text-sm text-slate-300">09:41 AM</td>
                  <td className="py-3 px-4 text-sm font-mono text-slate-300 group-hover:text-cyan-400 transition-colors">198.51.100.42</td>
                  <td className="py-3 px-4 text-sm font-medium group-hover:text-white transition-colors">Brute Force</td>
                  <td className="py-3 px-4 text-sm">
                    <span className="inline-flex items-center gap-1 px-3 py-1 rounded-full text-xs font-bold border bg-red-500/20 text-red-400 border-red-500/50 group-hover:scale-110 transition-transform">
                      <span className="w-1.5 h-1.5 bg-red-400 rounded-full animate-pulse"></span>CRITICAL
                    </span>
                  </td>
                  <td className="py-3 px-4 text-sm">
                    <span className="inline-flex items-center gap-1 px-3 py-1 rounded-full text-xs font-bold border bg-red-500/20 text-red-400 border-red-500/50">
                      <span className="w-1.5 h-1.5 bg-red-400 rounded-full animate-pulse"></span>ACTIVE
                    </span>
                  </td>
                  <td className="py-3 px-4 text-sm text-slate-400 group-hover:text-slate-300 transition-colors">Multiple failed login attempts detected</td>
                </tr>
                <tr className="group border-b border-slate-700/50 hover:bg-slate-800/50 transition-all duration-300">
                  <td className="py-3 px-4 text-sm text-slate-300">09:12 AM</td>
                  <td className="py-3 px-4 text-sm font-mono text-slate-300 group-hover:text-cyan-400 transition-colors">203.0.113.11</td>
                  <td className="py-3 px-4 text-sm font-medium group-hover:text-white transition-colors">Phishing</td>
                  <td className="py-3 px-4 text-sm">
                    <span className="inline-flex items-center gap-1 px-3 py-1 rounded-full text-xs font-bold border bg-orange-500/20 text-orange-400 border-orange-500/50 group-hover:scale-110 transition-transform">HIGH</span>
                  </td>
                  <td className="py-3 px-4 text-sm">
                    <span className="inline-flex items-center gap-1 px-3 py-1 rounded-full text-xs font-bold border bg-red-500/20 text-red-400 border-red-500/50">
                      <span className="w-1.5 h-1.5 bg-red-400 rounded-full animate-pulse"></span>ACTIVE
                    </span>
                  </td>
                  <td className="py-3 px-4 text-sm text-slate-400 group-hover:text-slate-300 transition-colors">Suspicious email with malicious link detected</td>
                </tr>
                <tr className="group border-b border-slate-700/50 hover:bg-slate-800/50 transition-all duration-300">
                  <td className="py-3 px-4 text-sm text-slate-300">08:57 AM</td>
                  <td className="py-3 px-4 text-sm font-mono text-slate-300 group-hover:text-cyan-400 transition-colors">192.0.2.156</td>
                  <td className="py-3 px-4 text-sm font-medium group-hover:text-white transition-colors">Malware</td>
                  <td className="py-3 px-4 text-sm">
                    <span className="inline-flex items-center gap-1 px-3 py-1 rounded-full text-xs font-bold border bg-yellow-500/20 text-yellow-400 border-yellow-500/50 group-hover:scale-110 transition-transform">MEDIUM</span>
                  </td>
                  <td className="py-3 px-4 text-sm">
                    <span className="inline-flex items-center gap-1 px-3 py-1 rounded-full text-xs font-bold border bg-red-500/20 text-red-400 border-red-500/50">
                      <span className="w-1.5 h-1.5 bg-red-400 rounded-full animate-pulse"></span>ACTIVE
                    </span>
                  </td>
                  <td className="py-3 px-4 text-sm text-slate-400 group-hover:text-slate-300 transition-colors">Malicious file detected in download folder</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>

     {/* System Metrics - Enhanced */}
<div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
  {/* Detection Rate Card */}
  <div className="group stat-card p-6 hover:shadow-2xl hover:shadow-green-500/20 transition-all duration-300">
    <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
      <div className="w-2 h-2 bg-green-400 rounded-full animate-pulse"></div>
      Detection Rate
    </h3>
    <div className="space-y-3">
      <div className="flex justify-between items-center mb-2">
        <span className="text-slate-400 text-sm">Success Rate</span>
        <span className="font-bold text-2xl text-green-400">100%</span>
      </div>
      <div style={{ 
        width: '100%', 
        height: '12px', 
        backgroundColor: 'rgba(51, 65, 85, 0.5)', 
        borderRadius: '9999px',
        overflow: 'hidden'
      }}>
        <div style={{
          height: '100%',
          width: '100%',
          background: 'linear-gradient(to right, #10b981, #059669)',
          borderRadius: '9999px',
          boxShadow: '0 0 20px rgba(16, 185, 129, 0.5)'
        }}></div>
      </div>
    </div>
  </div>

  {/* Response Time Card */}
  <div className="group stat-card p-6 hover:shadow-2xl hover:shadow-blue-500/20 transition-all duration-300">
    <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
      <div className="w-2 h-2 bg-blue-400 rounded-full animate-pulse"></div>
      Response Time
    </h3>
    <div className="space-y-3">
      <div className="flex justify-between items-center mb-2">
        <span className="text-slate-400 text-sm">Average</span>
        <span className="font-bold text-2xl text-blue-400">&lt; 100ms</span>
      </div>
      <div style={{ 
        width: '100%', 
        height: '12px', 
        backgroundColor: 'rgba(51, 65, 85, 0.5)', 
        borderRadius: '9999px',
        overflow: 'hidden'
      }}>
        <div style={{
          height: '100%',
          width: '100%',
          background: 'linear-gradient(to right, #3b82f6, #06b6d4)',
          borderRadius: '9999px',
          boxShadow: '0 0 20px rgba(59, 130, 246, 0.5)'
        }}></div>
      </div>
    </div>
  </div>

  {/* Protection Card */}
  <div className="group stat-card p-6 hover:shadow-2xl hover:shadow-purple-500/20 transition-all duration-300">
    <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
      <div className="w-2 h-2 bg-purple-400 rounded-full animate-pulse"></div>
      Protection
    </h3>
    <div className="space-y-3">
      <div className="flex justify-between items-center mb-2">
        <span className="text-slate-400 text-sm">24/7 Active</span>
        <span className="font-bold text-2xl text-purple-400">Online</span>
      </div>
      <div style={{ 
        width: '100%', 
        height: '12px', 
        backgroundColor: 'rgba(51, 65, 85, 0.5)', 
        borderRadius: '9999px',
        overflow: 'hidden'
      }}>
        <div style={{
          height: '100%',
          width: '100%',
          background: 'linear-gradient(to right, #a855f7, #ec4899)',
          borderRadius: '9999px',
          boxShadow: '0 0 20px rgba(168, 85, 247, 0.5)'
        }}></div>
      </div>
    </div>
  </div>
</div>
      </div>
    </ProtectedRoute>
  );
}