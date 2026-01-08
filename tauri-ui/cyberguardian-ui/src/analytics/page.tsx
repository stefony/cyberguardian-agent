"use client";

import { useEffect, useState, useCallback } from "react";
import { BarChart3, TrendingUp, Shield, Activity, RefreshCw, Calendar } from "lucide-react";
import WhatIfPanel from '@/components/WhatIfPanel'
import { LineChart, Line, BarChart, Bar, PieChart, Pie, Cell, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from "recharts";
import { analyticsApi } from "@/lib/api"; 
import ProtectedRoute from '@/components/ProtectedRoute';

// Types
type OverviewStats = {
  total_threats: number;
  active_threats: number;
  blocked_threats: number;
  total_scans: number;
  successful_scans: number;
  total_honeypots: number;
  active_honeypots: number;
  total_interactions: number;
  threats_today: number;
  scans_today: number;
};

type TimelinePoint = {
  date: string;
  count: number;
};

type DetectionBreakdown = {
  method: string;
  count: number;
  percentage: number;
};

type ThreatCategory = {
  category: string;
  count: number;
  severity: string;
};

// Chart colors
const COLORS = {
  primary: "#8b5cf6",
  secondary: "#06b6d4",
  success: "#10b981",
  warning: "#f59e0b",
  danger: "#ef4444",
  purple: "#a855f7",
  blue: "#3b82f6",
  cyan: "#06b6d4",
  pink: "#ec4899",
};

const PIE_COLORS = ["#8b5cf6", "#06b6d4", "#3b82f6", "#ec4899", "#10b981"];

export default function AnalyticsPage() {
  const [overview, setOverview] = useState<OverviewStats | null>(null);
  const [threatsTimeline, setThreatsTimeline] = useState<TimelinePoint[]>([]);
  const [detectionStats, setDetectionStats] = useState<DetectionBreakdown[]>([]);
  const [honeypotActivity, setHoneypotActivity] = useState<TimelinePoint[]>([]);
  const [topThreats, setTopThreats] = useState<ThreatCategory[]>([]);
  
  const [isLoading, setIsLoading] = useState(true);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [timeRange, setTimeRange] = useState<number>(7);

// Fetch all data
  const fetchData = useCallback(async (showRefreshIndicator = false) => {
    try {
      if (showRefreshIndicator) {
        setIsRefreshing(true);
      } else {
        setIsLoading(true);
      }

      const [overviewRes, timelineRes, detectionRes, honeypotRes, threatsRes] = await Promise.all([
        analyticsApi.getOverview(),
        analyticsApi.getThreatsTimeline(timeRange),
        analyticsApi.getDetectionStats(),
        analyticsApi.getHoneypotActivity(timeRange),
        analyticsApi.getTopThreats(5)
      ]);

      if (overviewRes.success) setOverview(overviewRes.data || null);
      if (timelineRes.success) setThreatsTimeline(timelineRes.data || []);
      if (detectionRes.success) setDetectionStats(detectionRes.data || []);
      if (honeypotRes.success) setHoneypotActivity(honeypotRes.data || []);
      if (threatsRes.success) setTopThreats(threatsRes.data || []);

      setError(null);
    } catch (err) {
      console.error("Error fetching analytics:", err);
      setError("Could not load analytics data");
    } finally {
      setIsLoading(false);
      setIsRefreshing(false);
    }
  }, [timeRange]);

  useEffect(() => {
    fetchData();
  }, [timeRange]);

  const handleRefresh = () => {
    fetchData(true);
  };

  const getSeverityColor = (severity: string) => {
    const colors: Record<string, string> = {
      critical: COLORS.danger,
      high: COLORS.warning,
      medium: COLORS.cyan,
      low: COLORS.success,
    };
    return colors[severity.toLowerCase()] || COLORS.primary;
  };

  return (
    <ProtectedRoute>
    <main className="pb-12">
      {/* Hero */}
      <div className="page-container page-hero pt-12 md:pt-16">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="heading-accent gradient-cyber text-3xl md:text-4xl font-bold tracking-tight">
              Analytics Dashboard
            </h1>
            <p className="mt-2 text-muted-foreground">
              Comprehensive security metrics and visualizations
            </p>
          </div>

          <div className="flex items-center gap-3">
            <select
              value={timeRange}
              onChange={(e) => setTimeRange(Number(e.target.value))}
              className="px-4 py-2 rounded-lg bg-card border-2 border-border text-foreground transition-all duration-300 hover:border-purple-400 hover:bg-purple-500/5 focus:outline-none focus:ring-2 focus:ring-purple-500 cursor-pointer"
              style={{ colorScheme: 'dark' }}
            >
              <option value={7} className="bg-[#0a0e27] text-white">Last 7 days</option>
              <option value={14} className="bg-[#0a0e27] text-white">Last 14 days</option>
              <option value={30} className="bg-[#0a0e27] text-white">Last 30 days</option>
              <option value={90} className="bg-[#0a0e27] text-white">Last 90 days</option>
            </select>

            <button
              onClick={handleRefresh}
              disabled={isRefreshing}
              className="px-4 py-2 rounded-lg bg-purple-500/10 text-purple-500 hover:bg-purple-500/20 border-2 border-purple-500/30 transition-all duration-300 hover:scale-105 hover:shadow-lg hover:shadow-purple-500/50 disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2"
            >
              <RefreshCw className={`h-4 w-4 ${isRefreshing ? 'animate-spin' : ''}`} />
              Refresh
            </button>
          </div>
        </div>
      </div>

      {isLoading ? (
        <div className="section text-center py-12">
          <Activity className="h-8 w-8 animate-spin mx-auto text-purple-500" />
          <p className="mt-4 text-muted-foreground">Loading analytics...</p>
        </div>
      ) : error ? (
        <div className="section text-center py-12">
          <Shield className="h-8 w-8 mx-auto text-red-500" />
          <p className="mt-4 text-red-500">{error}</p>
        </div>
      ) : (
        <>
          {/* Stats Cards */}
          {overview && (
            <div className="section">
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4">
                <div className="card-premium p-5 transition-all duration-300 hover:scale-105 hover:shadow-lg hover:shadow-red-500/30">
                  <div className="flex items-center gap-3 mb-2">
                    <Shield className="h-5 w-5 text-red-500" />
                    <div className="text-sm text-muted-foreground">Total Threats</div>
                  </div>
                  <div className="text-2xl font-bold text-red-500">{overview.total_threats}</div>
                </div>

                <div className="card-premium p-5 transition-all duration-300 hover:scale-105 hover:shadow-lg hover:shadow-orange-500/30">
                  <div className="flex items-center gap-3 mb-2">
                    <Activity className="h-5 w-5 text-orange-500" />
                    <div className="text-sm text-muted-foreground">Active Threats</div>
                  </div>
                  <div className="text-2xl font-bold text-orange-500">{overview.active_threats}</div>
                </div>

                <div className="card-premium p-5 transition-all duration-300 hover:scale-105 hover:shadow-lg hover:shadow-green-500/30">
                  <div className="flex items-center gap-3 mb-2">
                    <Shield className="h-5 w-5 text-green-500" />
                    <div className="text-sm text-muted-foreground">Blocked</div>
                  </div>
                  <div className="text-2xl font-bold text-green-500">{overview.blocked_threats}</div>
                </div>

                <div className="card-premium p-5 transition-all duration-300 hover:scale-105 hover:shadow-lg hover:shadow-blue-500/30">
                  <div className="flex items-center gap-3 mb-2">
                    <BarChart3 className="h-5 w-5 text-blue-500" />
                    <div className="text-sm text-muted-foreground">Total Scans</div>
                  </div>
                  <div className="text-2xl font-bold text-blue-500">{overview.total_scans}</div>
                </div>

                <div className="card-premium p-5 transition-all duration-300 hover:scale-105 hover:shadow-lg hover:shadow-purple-500/30">
                  <div className="flex items-center gap-3 mb-2">
                    <TrendingUp className="h-5 w-5 text-purple-500" />
                    <div className="text-sm text-muted-foreground">Honeypots</div>
                  </div>
                  <div className="text-2xl font-bold text-purple-500">{overview.active_honeypots}/{overview.total_honeypots}</div>
                </div>
              </div>
            </div>
          )}

          {/* Charts Row 1 */}
          <div className="section">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* Threats Timeline */}
              <div className="card-premium p-6 transition-all duration-300 hover:shadow-lg hover:shadow-purple-500/20">
                <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
                  <TrendingUp className="h-5 w-5 text-purple-500" />
                  Threats Over Time
                </h3>
                <ResponsiveContainer width="100%" height={300}>
                  <LineChart data={threatsTimeline}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                    <XAxis dataKey="date" stroke="#9ca3af" style={{ fontSize: 12 }} />
                    <YAxis stroke="#9ca3af" style={{ fontSize: 12 }} />
                    <Tooltip contentStyle={{ backgroundColor: '#1f2937', border: '1px solid #374151', borderRadius: 8 }} />
                    <Line type="monotone" dataKey="count" stroke="#8b5cf6" strokeWidth={2} dot={{ fill: '#8b5cf6' }} />
                  </LineChart>
                </ResponsiveContainer>
              </div>

              {/* Detection Breakdown */}
              <div className="card-premium p-6 transition-all duration-300 hover:shadow-lg hover:shadow-cyan-500/20">
                <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
                  <BarChart3 className="h-5 w-5 text-cyan-500" />
                  Detection Methods
                </h3>
                <ResponsiveContainer width="100%" height={300}>
                  <PieChart>
                    <Pie
                      data={detectionStats}
                      cx="50%"
                      cy="50%"
                      labelLine={false}
                      label={(entry) => `${entry.method}: ${entry.percentage}%`}
                      outerRadius={100}
                      fill="#8884d8"
                      dataKey="count"
                    >
                      {detectionStats.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={PIE_COLORS[index % PIE_COLORS.length]} />
                      ))}
                    </Pie>
                    <Tooltip contentStyle={{ backgroundColor: '#1f2937', border: '1px solid #374151', borderRadius: 8 }} />
                  </PieChart>
                </ResponsiveContainer>
              </div>
            </div>
          </div>

          {/* Charts Row 2 */}
          <div className="section">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* Honeypot Activity */}
              <div className="card-premium p-6 transition-all duration-300 hover:shadow-lg hover:shadow-pink-500/20">
                <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
                  <Activity className="h-5 w-5 text-pink-500" />
                  Honeypot Interactions
                </h3>
                <ResponsiveContainer width="100%" height={300}>
                  <LineChart data={honeypotActivity}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                    <XAxis dataKey="date" stroke="#9ca3af" style={{ fontSize: 12 }} />
                    <YAxis stroke="#9ca3af" style={{ fontSize: 12 }} />
                    <Tooltip contentStyle={{ backgroundColor: '#1f2937', border: '1px solid #374151', borderRadius: 8 }} />
                    <Line type="monotone" dataKey="count" stroke="#ec4899" strokeWidth={2} dot={{ fill: '#ec4899' }} />
                  </LineChart>
                </ResponsiveContainer>
              </div>

              {/* Top Threats */}
              <div className="card-premium p-6 transition-all duration-300 hover:shadow-lg hover:shadow-blue-500/20">
                <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
                  <Shield className="h-5 w-5 text-blue-500" />
                  Top Threat Categories
                </h3>
                <ResponsiveContainer width="100%" height={300}>
                  <BarChart data={topThreats} layout="vertical">
                    <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                    <XAxis type="number" stroke="#9ca3af" style={{ fontSize: 12 }} />
                    <YAxis dataKey="category" type="category" stroke="#9ca3af" style={{ fontSize: 12 }} width={100} />
                    <Tooltip contentStyle={{ backgroundColor: '#1f2937', border: '1px solid #374151', borderRadius: 8 }} />
                    <Bar dataKey="count" fill="#3b82f6" />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </div>
          </div>

          {/* What-if Simulator */}
          <div className="section">
            <h2 className="text-2xl font-bold mb-6 flex items-center gap-2 px-6">
              <Activity className="h-6 w-6 text-purple-500" />
              AI What-If Simulator
            </h2>
            <WhatIfPanel />
          </div>
        </>
      )}
    </main>
      </ProtectedRoute>
  );
}