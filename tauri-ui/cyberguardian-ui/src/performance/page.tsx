

import { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import CountUp from 'react-countup';
import { 
  ChartBarIcon,
  CpuChipIcon,
  CircleStackIcon,
  ServerIcon,
  BoltIcon,
  ExclamationTriangleIcon,
  CheckCircleIcon,
  LightBulbIcon,
  ArrowPathIcon,
  ClockIcon,
  SparklesIcon
} from '@heroicons/react/24/outline';
import ProtectedRoute from '@/components/ProtectedRoute';

const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';
// Helper to make authenticated requests
const fetchWithAuth = async (endpoint: string, options?: RequestInit) => {
  const token = typeof window !== 'undefined' ? localStorage.getItem('access_token') : null;
  
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  };
  
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }
  
  const response = await fetch(`${API_URL}${endpoint}`, {
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

interface SystemHealth {
  health_score: number;
  status: string;
  cpu: {
    percent: number;
    count: number;
    frequency_mhz: number;
  };
  memory: {
    total_mb: number;
    available_mb: number;
    used_mb: number;
    percent: number;
  };
  disk: {
    total_gb: number;
    used_gb: number;
    free_gb: number;
    percent: number;
  };
  process: {
    cpu_percent: number;
    memory_mb: number;
    num_threads: number;
  };
  uptime_seconds: number;
}

interface Summary {
  health_score: number;
  status: string;
  cpu_percent: number;
  memory_percent: number;
  disk_percent: number;
  uptime_hours: number;
  total_scans: number;
  total_queries: number;
  active_alerts: number;
  critical_issues: number;
  needs_attention: boolean;
}

interface Bottleneck {
  type: string;
  severity: string;
  message: string;
  recommendation: string;
}

interface Recommendation {
  category: string;
  priority: string;
  recommendation: string;
  expected_improvement: string;
}

export default function PerformancePage() {
  const [health, setHealth] = useState<SystemHealth | null>(null);
  const [summary, setSummary] = useState<Summary | null>(null);
  const [bottlenecks, setBottlenecks] = useState<Bottleneck[]>([]);
  const [recommendations, setRecommendations] = useState<Recommendation[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);

  const fetchData = async (showRefreshing = false) => {
    if (showRefreshing) setRefreshing(true);
    
    try {
      const [healthData, summaryData, bottlenecksData, recsData] = await Promise.all([
  fetchWithAuth('/api/performance/health'),
  fetchWithAuth('/api/performance/report/summary'),
  fetchWithAuth('/api/performance/bottlenecks'),
  fetchWithAuth('/api/performance/recommendations')
    ]);

      if (healthData.success) setHealth(healthData.health);
      if (summaryData.success) setSummary(summaryData.summary);
      if (bottlenecksData.success) setBottlenecks(bottlenecksData.bottlenecks);
      if (recsData.success) setRecommendations(recsData.recommendations);

    } catch (error) {
      console.error('Error fetching performance data:', error);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    fetchData();
    const interval = setInterval(() => fetchData(true), 10000);
    return () => clearInterval(interval);
  }, []);

  const getHealthColor = (score: number) => {
    if (score >= 80) return 'text-green-500';
    if (score >= 60) return 'text-blue-500';
    if (score >= 40) return 'text-yellow-500';
    return 'text-red-500';
  };

  const getUsageColor = (percent: number) => {
    if (percent < 60) return 'bg-green-500';
    if (percent < 80) return 'bg-yellow-500';
    return 'bg-red-500';
  };

  const getSeverityBadge = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical':
        return 'bg-red-500/20 text-red-400 border-red-500/30';
      case 'high':
        return 'bg-orange-500/20 text-orange-400 border-orange-500/30';
      case 'medium':
        return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30';
      default:
        return 'bg-blue-500/20 text-blue-400 border-blue-500/30';
    }
  };

  const getPriorityBadge = (priority: string) => {
    switch (priority.toLowerCase()) {
      case 'high':
        return 'bg-red-500/20 text-red-400 border-red-500/30';
      case 'medium':
        return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30';
      default:
        return 'bg-blue-500/20 text-blue-400 border-blue-500/30';
    }
  };

  const formatUptime = (seconds: number) => {
    const hours = Math.floor(seconds / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    
    if (hours > 0) return `${hours}h ${minutes}m`;
    if (minutes > 0) return `${minutes}m`;
    return `${Math.floor(seconds)}s`;
  };

  // Loading skeleton
  if (loading) {
    return (
        <ProtectedRoute>
      <div className="min-h-screen bg-dark-bg p-8">
        <div className="max-w-7xl mx-auto animate-pulse space-y-8">
          <div className="h-10 w-64 bg-muted/30 rounded"></div>
          <div className="h-64 bg-muted/20 rounded-xl"></div>
          <div className="grid grid-cols-4 gap-6">
            {[...Array(4)].map((_, i) => (
              <div key={i} className="h-32 bg-muted/20 rounded-xl"></div>
            ))}
          </div>
        </div>
      </div>
      </ProtectedRoute>
    );
  }

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5 }}
      className="min-h-screen bg-dark-bg p-6"
    >
      <div className="max-w-7xl mx-auto space-y-6">
        
        {/* Header */}
        <motion.div
          initial={{ opacity: 0, x: -20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ duration: 0.5, delay: 0.1 }}
          className="relative overflow-hidden bg-gradient-to-r from-purple-600 via-blue-600 to-cyan-600 rounded-2xl shadow-2xl p-8 text-white"
        >
          <div className="absolute top-0 right-0 -mt-4 -mr-4 w-64 h-64 bg-white opacity-10 rounded-full blur-3xl"></div>
          <div className="absolute bottom-0 left-0 -mb-4 -ml-4 w-64 h-64 bg-white opacity-10 rounded-full blur-3xl"></div>
          
          <div className="relative z-10">
            <div className="flex items-center justify-between">
              <div>
                <div className="flex items-center space-x-3 mb-4">
                  <motion.div
                    animate={{ rotate: [0, 360] }}
                    transition={{ duration: 3, repeat: Infinity, ease: "linear" }}
                  >
                    <ChartBarIcon className="h-10 w-10" />
                  </motion.div>
                  <h1 className="text-4xl font-bold">Performance Monitor</h1>
                </div>
                <p className="text-blue-100 text-lg">Real-time system health and optimization insights</p>
              </div>
              
              <motion.button
                whileHover={{ scale: 1.05 }}
                whileTap={{ scale: 0.95 }}
                onClick={() => fetchData(true)}
                disabled={refreshing}
                className="px-6 py-3 bg-white/20 hover:bg-white/30 rounded-xl font-semibold transition-all duration-300 disabled:opacity-50 hover:shadow-lg"
              >
                <div className="flex items-center space-x-2">
                  <ArrowPathIcon className={`h-5 w-5 ${refreshing ? 'animate-spin' : ''}`} />
                  <span>{refreshing ? 'Refreshing...' : 'Refresh'}</span>
                </div>
              </motion.button>
            </div>
          </div>
        </motion.div>

        {/* Health Score Hero */}
        {health && summary && (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: 0.2 }}
            className="bg-dark-card rounded-2xl shadow-xl overflow-hidden border border-dark-border"
          >
            <div className="px-8 py-6 border-b border-dark-border">
              <h2 className="text-2xl font-bold text-dark-text">System Health Overview</h2>
              <p className="text-sm text-dark-text/70">Current system status and vital statistics</p>
            </div>

            <div className="p-8">
              <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
                
                {/* Health Gauge */}
                <motion.div
                  initial={{ opacity: 0, scale: 0.9 }}
                  animate={{ opacity: 1, scale: 1 }}
                  transition={{ duration: 0.5, delay: 0.3 }}
                  className="lg:col-span-1 flex flex-col items-center justify-center"
                >
                  <div className="relative">
                    <svg className="transform -rotate-90 w-48 h-48">
                      <circle
                        cx="96"
                        cy="96"
                        r="88"
                        stroke="currentColor"
                        strokeWidth="12"
                        fill="transparent"
                        className="text-dark-border"
                      />
                      <motion.circle
                        cx="96"
                        cy="96"
                        r="88"
                        stroke="currentColor"
                        strokeWidth="12"
                        fill="transparent"
                        strokeDasharray={`${2 * Math.PI * 88}`}
                        className={`${getHealthColor(summary.health_score)} transition-all duration-1000 ease-out`}
                        strokeLinecap="round"
                        initial={{ strokeDashoffset: 2 * Math.PI * 88 }}
                        animate={{ strokeDashoffset: 2 * Math.PI * 88 * (1 - summary.health_score / 100) }}
                        transition={{ duration: 2, ease: "easeOut" }}
                      />
                    </svg>
                    <div className="absolute inset-0 flex flex-col items-center justify-center">
                      <span className={`text-5xl font-black ${getHealthColor(summary.health_score)}`}>
                        <CountUp end={summary.health_score} duration={2} />
                      </span>
                      <span className="text-sm font-semibold text-dark-text/70 uppercase mt-1">Health Score</span>
                    </div>
                  </div>
                  
                  <motion.div
                    initial={{ opacity: 0, scale: 0.8 }}
                    animate={{ opacity: 1, scale: 1 }}
                    transition={{ duration: 0.3, delay: 0.5 }}
                    whileHover={{ scale: 1.05 }}
                    className="mt-6 text-center"
                  >
                    <span className={`inline-flex items-center px-6 py-2 rounded-full text-lg font-bold border-2 ${
                      summary.status === 'excellent' ? 'bg-green-500/20 text-green-400 border-green-500/30' :
                      summary.status === 'good' ? 'bg-blue-500/20 text-blue-400 border-blue-500/30' :
                      summary.status === 'fair' ? 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30' :
                      'bg-red-500/20 text-red-400 border-red-500/30'
                    }`}>
                      {summary.status.toUpperCase()}
                    </span>
                  </motion.div>

                  <div className="mt-4 flex items-center space-x-2 text-sm text-dark-text/70">
                    <ClockIcon className="h-4 w-4" />
                    <span>Uptime: {formatUptime(health.uptime_seconds)}</span>
                  </div>
                </motion.div>

                {/* Metrics Grid */}
                <div className="lg:col-span-2 grid grid-cols-1 md:grid-cols-2 gap-4">
                  
                  {/* CPU */}
                  <motion.div
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ duration: 0.4, delay: 0.4 }}
                    whileHover={{ scale: 1.02, y: -4 }}
                    className="p-6 bg-blue-500/10 rounded-xl border-2 border-blue-500/20 hover:shadow-xl hover:shadow-blue-500/20 transition-all duration-300"
                  >
                    <div className="flex items-center justify-between mb-4">
                      <div className="flex items-center space-x-3">
                        <motion.div
                          whileHover={{ rotate: 360 }}
                          transition={{ duration: 0.5 }}
                          className="p-3 bg-blue-500 rounded-lg shadow-lg"
                        >
                          <CpuChipIcon className="h-6 w-6 text-white" />
                        </motion.div>
                        <div>
                          <p className="text-sm font-semibold text-dark-text/70 uppercase">CPU Usage</p>
                          <p className="text-3xl font-black text-blue-400">
                            <CountUp end={summary.cpu_percent} decimals={1} duration={2} />%
                          </p>
                        </div>
                      </div>
                    </div>
                    <div className="w-full bg-dark-bg rounded-full h-3 overflow-hidden">
                      <motion.div
                        initial={{ width: 0 }}
                        animate={{ width: `${summary.cpu_percent}%` }}
                        transition={{ duration: 1, ease: "easeOut" }}
                        className={`h-full ${getUsageColor(summary.cpu_percent)} transition-all duration-500 rounded-full`}
                      ></motion.div>
                    </div>
                    <p className="mt-2 text-xs text-dark-text/70">{health.cpu.count} cores @ {health.cpu.frequency_mhz.toFixed(0)} MHz</p>
                  </motion.div>

                  {/* Memory */}
                  <motion.div
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ duration: 0.4, delay: 0.5 }}
                    whileHover={{ scale: 1.02, y: -4 }}
                    className="p-6 bg-purple-500/10 rounded-xl border-2 border-purple-500/20 hover:shadow-xl hover:shadow-purple-500/20 transition-all duration-300"
                  >
                    <div className="flex items-center justify-between mb-4">
                      <div className="flex items-center space-x-3">
                        <motion.div
                          whileHover={{ rotate: 360 }}
                          transition={{ duration: 0.5 }}
                          className="p-3 bg-purple-500 rounded-lg shadow-lg"
                        >
                          <CircleStackIcon className="h-6 w-6 text-white" />
                        </motion.div>
                        <div>
                          <p className="text-sm font-semibold text-dark-text/70 uppercase">Memory Usage</p>
                          <p className="text-3xl font-black text-purple-400">
                            <CountUp end={summary.memory_percent} decimals={1} duration={2} />%
                          </p>
                        </div>
                      </div>
                    </div>
                    <div className="w-full bg-dark-bg rounded-full h-3 overflow-hidden">
                      <motion.div
                        initial={{ width: 0 }}
                        animate={{ width: `${summary.memory_percent}%` }}
                        transition={{ duration: 1, ease: "easeOut" }}
                        className={`h-full ${getUsageColor(summary.memory_percent)} transition-all duration-500 rounded-full`}
                      ></motion.div>
                    </div>
                    <p className="mt-2 text-xs text-dark-text/70">
                      {(health.memory.used_mb / 1024).toFixed(1)} GB / {(health.memory.total_mb / 1024).toFixed(1)} GB
                    </p>
                  </motion.div>

                  {/* Disk */}
                  <motion.div
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ duration: 0.4, delay: 0.6 }}
                    whileHover={{ scale: 1.02, y: -4 }}
                    className="p-6 bg-green-500/10 rounded-xl border-2 border-green-500/20 hover:shadow-xl hover:shadow-green-500/20 transition-all duration-300"
                  >
                    <div className="flex items-center justify-between mb-4">
                      <div className="flex items-center space-x-3">
                        <motion.div
                          whileHover={{ rotate: 360 }}
                          transition={{ duration: 0.5 }}
                          className="p-3 bg-green-500 rounded-lg shadow-lg"
                        >
                          <ServerIcon className="h-6 w-6 text-white" />
                        </motion.div>
                        <div>
                          <p className="text-sm font-semibold text-dark-text/70 uppercase">Disk Usage</p>
                          <p className="text-3xl font-black text-green-400">
                            <CountUp end={summary.disk_percent} decimals={1} duration={2} />%
                          </p>
                        </div>
                      </div>
                    </div>
                    <div className="w-full bg-dark-bg rounded-full h-3 overflow-hidden">
                      <motion.div
                        initial={{ width: 0 }}
                        animate={{ width: `${summary.disk_percent}%` }}
                        transition={{ duration: 1, ease: "easeOut" }}
                        className={`h-full ${getUsageColor(summary.disk_percent)} transition-all duration-500 rounded-full`}
                      ></motion.div>
                    </div>
                    <p className="mt-2 text-xs text-dark-text/70">
                      {health.disk.free_gb.toFixed(1)} GB free of {health.disk.total_gb.toFixed(1)} GB
                    </p>
                  </motion.div>

                  {/* Process */}
                  <motion.div
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ duration: 0.4, delay: 0.7 }}
                    whileHover={{ scale: 1.02, y: -4 }}
                    className="p-6 bg-orange-500/10 rounded-xl border-2 border-orange-500/20 hover:shadow-xl hover:shadow-orange-500/20 transition-all duration-300"
                  >
                    <div className="flex items-center justify-between mb-4">
                      <div className="flex items-center space-x-3">
                        <motion.div
                          whileHover={{ scale: 1.2 }}
                          transition={{ type: "spring", stiffness: 400 }}
                          className="p-3 bg-orange-500 rounded-lg shadow-lg"
                        >
                          <BoltIcon className="h-6 w-6 text-white" />
                        </motion.div>
                        <div>
                          <p className="text-sm font-semibold text-dark-text/70 uppercase">Process</p>
                          <p className="text-3xl font-black text-orange-400">
                            <CountUp end={health.process.num_threads} duration={2} />
                          </p>
                        </div>
                      </div>
                    </div>
                    <div className="mt-4 space-y-1 text-xs text-dark-text/70">
                      <p>CPU: {health.process.cpu_percent.toFixed(1)}%</p>
                      <p>Memory: {health.process.memory_mb.toFixed(1)} MB</p>
                      <p>Threads: {health.process.num_threads}</p>
                    </div>
                  </motion.div>

                </div>
              </div>
            </div>
          </motion.div>
        )}

        {/* Statistics Cards */}
        {summary && (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
            
            {[
              { label: 'Total Scans', value: summary.total_scans, icon: ChartBarIcon, color: 'blue' },
              { label: 'Total Queries', value: summary.total_queries, icon: CircleStackIcon, color: 'purple' },
              { label: 'Active Alerts', value: summary.active_alerts, icon: ExclamationTriangleIcon, color: 'yellow' },
              { label: 'Critical Issues', value: summary.critical_issues, icon: ExclamationTriangleIcon, color: 'red' },
            ].map((stat, index) => {
              const Icon = stat.icon;
              return (
                <motion.div
                  key={stat.label}
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ duration: 0.4, delay: 0.8 + index * 0.1 }}
                  whileHover={{ scale: 1.02, y: -4 }}
                  className={`bg-dark-card rounded-xl shadow-lg p-6 border-l-4 border-${stat.color}-500 hover:shadow-2xl hover:shadow-${stat.color}-500/20 transition-all duration-300`}
                >
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm font-semibold text-dark-text/70 uppercase">{stat.label}</p>
                      <p className="text-3xl font-black text-dark-text mt-1">
                        <CountUp end={stat.value} duration={2} />
                      </p>
                    </div>
                    <motion.div
                      whileHover={{ rotate: 360 }}
                      transition={{ duration: 0.5 }}
                      className={`p-3 bg-${stat.color}-500/20 rounded-lg`}
                    >
                      <Icon className={`h-8 w-8 text-${stat.color}-500`} />
                    </motion.div>
                  </div>
                </motion.div>
              );
            })}

          </div>
        )}

        {/* Bottlenecks */}
        <AnimatePresence mode="wait">
          {bottlenecks.length > 0 ? (
            <motion.div
              key="bottlenecks"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -20 }}
              transition={{ duration: 0.5 }}
              className="bg-dark-card rounded-2xl shadow-xl overflow-hidden border border-dark-border"
            >
              <div className="px-8 py-6 border-b border-dark-border">
                <div className="flex items-center space-x-3">
                  <motion.div
                    animate={{ rotate: [0, 10, -10, 0] }}
                    transition={{ duration: 0.5, repeat: Infinity, repeatDelay: 2 }}
                  >
                    <ExclamationTriangleIcon className="h-6 w-6 text-red-500" />
                  </motion.div>
                  <h2 className="text-2xl font-bold text-dark-text">Performance Bottlenecks</h2>
                </div>
                <p className="text-sm text-dark-text/70 mt-1">Issues detected that may impact performance</p>
              </div>

              <div className="p-8 space-y-4">
                {bottlenecks.map((bottleneck, index) => (
                  <motion.div
                    key={index}
                    initial={{ opacity: 0, x: -20 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ duration: 0.3, delay: index * 0.1 }}
                    whileHover={{ scale: 1.01, x: 4 }}
                    className="p-6 bg-red-500/10 rounded-xl border-2 border-red-500/20 hover:shadow-lg hover:shadow-red-500/20 transition-all duration-300"
                  >
                    <div className="flex items-start space-x-4">
                      <div className="flex-shrink-0">
                        <ExclamationTriangleIcon className="h-8 w-8 text-red-500" />
                      </div>
                      <div className="flex-1">
                        <div className="flex items-center space-x-3 mb-2">
                          <h3 className="text-lg font-bold text-dark-text">{bottleneck.type}</h3>
                          <motion.span
                            whileHover={{ scale: 1.05 }}
                            className={`px-3 py-1 rounded-lg text-xs font-bold border-2 ${getSeverityBadge(bottleneck.severity)}`}
                          >
                            {bottleneck.severity.toUpperCase()}
                          </motion.span>
                        </div>
                        <p className="text-dark-text/80 mb-3">{bottleneck.message}</p>
                        <div className="p-4 bg-dark-bg rounded-lg border border-red-500/20">
                          <p className="text-sm font-semibold text-dark-text mb-1">💡 Recommendation:</p>
                          <p className="text-sm text-dark-text/70">{bottleneck.recommendation}</p>
                        </div>
                      </div>
                    </div>
                  </motion.div>
                ))}
              </div>
            </motion.div>
          ) : (
            <motion.div
              key="no-bottlenecks"
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.95 }}
              className="bg-dark-card rounded-2xl shadow-xl p-8 border border-dark-border"
            >
              <div className="text-center py-8">
                <motion.div
                  animate={{ scale: [1, 1.1, 1], rotate: [0, 5, -5, 0] }}
                  transition={{ duration: 2, repeat: Infinity, repeatType: "reverse" }}
                  className="inline-flex items-center justify-center w-20 h-20 bg-green-500/20 rounded-full mb-4"
                >
                  <CheckCircleIcon className="h-10 w-10 text-green-500" />
                </motion.div>
                <h3 className="text-2xl font-bold text-dark-text mb-2">No Bottlenecks Detected! 🎉</h3>
                <p className="text-dark-text/70">Your system is running smoothly with optimal performance.</p>
              </div>
            </motion.div>
          )}
        </AnimatePresence>

        {/* Recommendations */}
        {recommendations.length > 0 && (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: 0.3 }}
            className="bg-dark-card rounded-2xl shadow-xl overflow-hidden border border-dark-border"
          >
            <div className="px-8 py-6 border-b border-dark-border">
              <div className="flex items-center space-x-3">
                <motion.div
                  animate={{ scale: [1, 1.2, 1] }}
                  transition={{ duration: 2, repeat: Infinity }}
                >
                  <LightBulbIcon className="h-6 w-6 text-yellow-500" />
                </motion.div>
                <h2 className="text-2xl font-bold text-dark-text">Optimization Recommendations</h2>
              </div>
              <p className="text-sm text-dark-text/70 mt-1">Smart tips to improve system performance</p>
            </div>

            <div className="p-8 space-y-4">
              {recommendations.map((rec, index) => (
                <motion.div
                  key={index}
                  initial={{ opacity: 0, x: -20 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ duration: 0.3, delay: index * 0.1 }}
                  whileHover={{ scale: 1.01, x: 4 }}
                  className="p-6 bg-blue-500/10 rounded-xl border-2 border-blue-500/20 hover:shadow-lg hover:shadow-blue-500/20 transition-all duration-300"
                >
                  <div className="flex items-start space-x-4">
                    <div className="flex-shrink-0">
                      <SparklesIcon className="h-8 w-8 text-blue-500" />
                    </div>
                    <div className="flex-1">
                      <div className="flex items-center space-x-3 mb-2">
                        <h3 className="text-lg font-bold text-dark-text">{rec.category}</h3>
                        <motion.span
                          whileHover={{ scale: 1.05 }}
                          className={`px-3 py-1 rounded-lg text-xs font-bold border-2 ${getPriorityBadge(rec.priority)}`}
                        >
                          {rec.priority.toUpperCase()} PRIORITY
                        </motion.span>
                      </div>
                      <p className="text-dark-text/80 mb-3">{rec.recommendation}</p>
                      <div className="p-4 bg-dark-bg rounded-lg border border-blue-500/20">
                        <p className="text-sm font-semibold text-dark-text mb-1">📈 Expected Improvement:</p>
                        <p className="text-sm text-dark-text/70">{rec.expected_improvement}</p>
                      </div>
                    </div>
                  </div>
                </motion.div>
              ))}
            </div>
          </motion.div>
        )}

      </div>
    </motion.div>
  );
}