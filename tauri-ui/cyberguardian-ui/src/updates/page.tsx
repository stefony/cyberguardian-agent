import { httpFetch } from '@/lib/api';
import { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import CountUp from 'react-countup';
import { 
  ArrowDownTrayIcon, 
  CheckCircleIcon,
  ClockIcon,
  ExclamationTriangleIcon,
  ArrowPathIcon,
  ShieldCheckIcon,
  RocketLaunchIcon,
  SparklesIcon,
  BoltIcon,
  ChartBarIcon
} from '@heroicons/react/24/outline';
import { 
  CheckCircleIcon as CheckCircleSolid,
  XCircleIcon,
  ClockIcon as ClockSolid
} from '@heroicons/react/24/solid';
import ProtectedRoute from '@/components/ProtectedRoute';
import { check } from '@tauri-apps/plugin-updater';
import { getVersion } from '@tauri-apps/api/app';
// import { relaunch } from '@tauri-apps/api/process'; // Will add later

const API_URL = (import.meta as any).env.VITE_API_URL || 'https://cyberguardian-backend-production.up.railway.app';

// Helper to make authenticated requests
const fetchWithAuth = async (endpoint: string, options?: RequestInit) => {
  const token = typeof window !== 'undefined' ? localStorage.getItem('access_token') : null;
  
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  };
  
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }
  
  const response = await httpFetch(`${API_URL}${endpoint}`, {
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

interface VersionInfo {
  version: string;
  major: number;
  minor: number;
  patch: number;
  codename: string;
  build_date: string;
  release_notes: string;
}

interface UpdateInfo {
  available: boolean;
  current_version: string;
  latest_version?: string;
  update_type?: string;
  release_date?: string;
  release_notes?: string;
  download_url?: string;
  size_bytes?: number;
  message?: string;
}

interface UpdateHistory {
  id: number;
  from_version: string;
  to_version: string;
  update_type: string;
  status: string;
  started_at: string;
  completed_at?: string;
  duration_seconds?: number;
  error_message?: string;
}

export default function UpdatesPage() {
  const [versionInfo, setVersionInfo] = useState<VersionInfo | null>(null);
  const [updateInfo, setUpdateInfo] = useState<UpdateInfo | null>(null);
  const [updateHistory, setUpdateHistory] = useState<UpdateHistory[]>([]);
  const [loading, setLoading] = useState(true);
  const [checking, setChecking] = useState(false);
  const [downloading, setDownloading] = useState(false);

// Fail gracefully, NO fake data
// Read version directly from Tauri config
const fetchVersion = async () => {
  try {
    const version = await getVersion();
    
    // Parse version string (e.g., "1.5.0")
    const [major, minor, patch] = version.split('.').map(Number);
    
    setVersionInfo({
      version: version,
      major: major,
      minor: minor,
      patch: patch,
      codename: "Sentinel", // You can customize this
      build_date: new Date().toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' }),
      release_notes: "Enhanced threat detection and auto-update capabilities"
    });
  } catch (error) {
    console.error('Error fetching version:', error);
    // No mock fallback
  }
};

const checkForUpdates = async (force: boolean = false) => {
  setChecking(true);
  try {
    // Use Tauri updater plugin
    const update = await check();
    
    if (update) {
      setUpdateInfo({
        available: true,
        current_version: update.currentVersion,
        latest_version: update.version,
        update_type: getUpdateType(update.currentVersion, update.version),
        release_date: update.date,
        release_notes: update.body || '',
        download_url: '', // Handled by Tauri
        size_bytes: 0, // Unknown
      });
    } else {
      setUpdateInfo({
        available: false,
        current_version: versionInfo?.version || 'Unknown',
        message: 'You are already on the latest version'
      });
    }
  } catch (error) {
    console.error('Error checking updates:', error);
    setUpdateInfo({
      available: false,
      current_version: versionInfo?.version || 'Unknown',
      message: 'Failed to check for updates'
    });
  } finally {
    setChecking(false);
  }
};

// Helper function to determine update type
const getUpdateType = (current: string, latest: string): string => {
  const [cMaj, cMin, cPat] = current.split('.').map(Number);
  const [lMaj, lMin, lPat] = latest.split('.').map(Number);
  
  if (lMaj > cMaj) return 'major';
  if (lMin > cMin) return 'minor';
  if (lPat > cPat) return 'patch';
  return 'none';
};

const fetchHistory = async () => {
  try {
    const data = await fetchWithAuth('/api/updates/history?limit=10');

    if (data.success && data.history) {
      setUpdateHistory(data.history);
    } else {
      // No mock data - empty history is OK
      setUpdateHistory([]);
    }
  } catch (error) {
    console.error('Error fetching history:', error);
    // No mock data fallback - professional empty state will show
    setUpdateHistory([]);
  }
};

 const downloadUpdate = async () => {
  setDownloading(true);
  try {
    // Use Tauri updater to download and install
    const update = await check();
    
    if (!update) {
      alert('No updates available');
      return;
    }
    
    // Show confirmation dialog
    const confirmed = window.confirm(
      `Update to v${update.version}?\n\n${update.body}\n\nThe app will restart after installation.`
    );
    
    if (!confirmed) {
      setDownloading(false);
      return;
    }
    
    // Download and install
    await update.downloadAndInstall();
    
    // Update history will be refreshed on restart
    alert('Update installed! Please restart the application.');
    
    // Note: We can't auto-restart without relaunch()
    // User will need to manually restart
    
  } catch (error) {
    console.error('Error downloading update:', error);
    alert('Failed to download update: ' + error);
  } finally {
    setDownloading(false);
  }
};

  useEffect(() => {
    const loadData = async () => {
      setLoading(true);
      await Promise.all([
        fetchVersion(),
        checkForUpdates(),
        fetchHistory()
      ]);
      setLoading(false);
    };
    loadData();
  }, []);

  const formatBytes = (bytes?: number) => {
    if (!bytes) return 'Unknown';
    const mb = bytes / (1024 * 1024);
    return `${mb.toFixed(2)} MB`;
  };

  const formatDate = (dateString?: string) => {
    if (!dateString) return 'Unknown';
    const date = new Date(dateString);
    return date.toLocaleDateString('en-US', { 
      month: 'short', 
      day: 'numeric', 
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'completed':
        return <CheckCircleSolid className="h-6 w-6 text-green-500" />;
      case 'failed':
        return <XCircleIcon className="h-6 w-6 text-red-500" />;
      case 'in_progress':
        return <ClockSolid className="h-6 w-6 text-blue-500 animate-pulse" />;
      case 'downloaded':
        return <ArrowDownTrayIcon className="h-6 w-6 text-yellow-500" />;
      default:
        return <ClockSolid className="h-6 w-6 text-gray-400" />;
    }
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'completed':
        return 'bg-green-500/20 text-green-400 border-green-500/30';
      case 'failed':
        return 'bg-red-500/20 text-red-400 border-red-500/30';
      case 'in_progress':
        return 'bg-blue-500/20 text-blue-400 border-blue-500/30';
      case 'downloaded':
        return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30';
      default:
        return 'bg-gray-500/20 text-gray-400 border-gray-500/30';
    }
  };

  const getUpdateTypeBadge = (type: string) => {
    switch (type.toLowerCase()) {
      case 'major':
        return 'bg-purple-500/20 text-purple-400 border-purple-500/30';
      case 'minor':
        return 'bg-blue-500/20 text-blue-400 border-blue-500/30';
      case 'patch':
        return 'bg-green-500/20 text-green-400 border-green-500/30';
      default:
        return 'bg-gray-500/20 text-gray-400 border-gray-500/30';
    }
  };

  // Loading skeleton
  if (loading) {
    return (
      <ProtectedRoute>
      <div className="min-h-screen bg-dark-bg p-8">
        <div className="max-w-7xl mx-auto animate-pulse space-y-8">
          <div className="h-10 w-64 bg-muted/30 rounded"></div>
          <div className="h-64 bg-muted/20 rounded-xl"></div>
          <div className="h-48 bg-muted/20 rounded-xl"></div>
        </div>
      </div>
      </ProtectedRoute>
    );
  }

  const completedPhases = 6;
  const totalPhases = 11;
  const progressPercentage = (completedPhases / totalPhases) * 100;

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
          className="relative overflow-hidden bg-gradient-to-r from-blue-600 via-purple-600 to-pink-600 rounded-2xl shadow-2xl p-8 text-white"
        >
          <div className="absolute top-0 right-0 -mt-4 -mr-4 w-64 h-64 bg-white opacity-10 rounded-full blur-3xl"></div>
          <div className="absolute bottom-0 left-0 -mb-4 -ml-4 w-64 h-64 bg-white opacity-10 rounded-full blur-3xl"></div>
          
          <div className="relative z-10">
            <div className="flex items-center space-x-3 mb-4">
              <motion.div
                animate={{ y: [0, -10, 0] }}
                transition={{ duration: 2, repeat: Infinity, ease: "easeInOut" }}
              >
                <RocketLaunchIcon className="h-10 w-10" />
              </motion.div>
              <h1 className="text-4xl font-bold">Software Updates</h1>
            </div>
            <p className="text-blue-100 text-lg">Keep your CyberGuardian AI secure and up-to-date</p>
          </div>
        </motion.div>

        {/* Current Version Card */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5, delay: 0.2 }}
          className="relative overflow-hidden bg-dark-card rounded-2xl shadow-xl border border-dark-border"
        >
          <div className="absolute top-0 right-0 w-1/2 h-full bg-gradient-to-l from-blue-500/10 to-transparent"></div>
          
          <div className="relative z-10 p-8">
            <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-6">
              
              {/* Left Side */}
              <div className="flex-1">
                <motion.div
                  initial={{ opacity: 0, x: -20 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ duration: 0.4, delay: 0.3 }}
                  className="flex items-center space-x-3 mb-6"
                >
                  <motion.div
                    whileHover={{ scale: 1.1, rotate: 5 }}
                    className="p-3 bg-gradient-to-br from-blue-500 to-purple-600 rounded-xl shadow-lg"
                  >
                    <ShieldCheckIcon className="h-8 w-8 text-white" />
                  </motion.div>
                  <div>
                    <h2 className="text-2xl font-bold text-dark-text">Current Version</h2>
                    <p className="text-sm text-dark-text/70">Actively protecting your system</p>
                  </div>
                </motion.div>

                {/* Version Display */}
                <motion.div
                  initial={{ opacity: 0, scale: 0.9 }}
                  animate={{ opacity: 1, scale: 1 }}
                  transition={{ duration: 0.5, delay: 0.4 }}
                  className="mb-6"
                >
                  <div className="inline-flex items-baseline space-x-3">
                    <span className="text-6xl font-black bg-gradient-to-r from-blue-400 to-purple-400 bg-clip-text text-transparent">
                      {versionInfo?.version}
                    </span>
                    <div className="flex flex-col">
                      <motion.span
                        whileHover={{ scale: 1.05 }}
                        className="px-4 py-1.5 bg-gradient-to-r from-blue-500 to-purple-600 text-white rounded-full text-sm font-bold shadow-lg flex items-center space-x-2"
                      >
                        <SparklesIcon className="h-4 w-4" />
                        <span>{versionInfo?.codename}</span>
                      </motion.span>
                      <span className="text-sm text-dark-text/70 mt-2">Built on {versionInfo?.build_date}</span>
                    </div>
                  </div>
                </motion.div>

                {/* Stats Grid */}
                <div className="grid grid-cols-3 gap-4">
                  {[
                    { label: 'Major', value: versionInfo?.major, icon: CheckCircleIcon, color: 'green' },
                    { label: 'Minor', value: versionInfo?.minor, icon: BoltIcon, color: 'blue' },
                    { label: 'Patch', value: versionInfo?.patch, icon: SparklesIcon, color: 'purple' },
                  ].map((stat, index) => {
                    const Icon = stat.icon;
                    return (
                      <motion.div
                        key={stat.label}
                        initial={{ opacity: 0, y: 20 }}
                        animate={{ opacity: 1, y: 0 }}
                        transition={{ duration: 0.4, delay: 0.5 + index * 0.1 }}
                        whileHover={{ scale: 1.05, y: -4 }}
                        className={`p-4 bg-${stat.color}-500/10 rounded-xl border border-${stat.color}-500/20 hover:shadow-xl hover:shadow-${stat.color}-500/20 transition-all duration-300`}
                      >
                        <div className="flex items-center space-x-2 mb-1">
                          <motion.div whileHover={{ rotate: 360 }} transition={{ duration: 0.5 }}>
                            <Icon className={`h-5 w-5 text-${stat.color}-400`} />
                          </motion.div>
                          <span className={`text-xs font-semibold text-${stat.color}-400 uppercase`}>{stat.label}</span>
                        </div>
                        <p className={`text-2xl font-bold text-${stat.color}-400`}>
                          <CountUp end={stat.value || 0} duration={2} />
                        </p>
                      </motion.div>
                    );
                  })}
                </div>
              </div>

              {/* Right Side - Progress Circle */}
              <motion.div
                initial={{ opacity: 0, scale: 0.8 }}
                animate={{ opacity: 1, scale: 1 }}
                transition={{ duration: 0.5, delay: 0.6 }}
                className="flex flex-col items-center lg:items-end space-y-4"
              >
                <div className="relative">
                  <svg className="transform -rotate-90 w-40 h-40">
                    <circle
                      cx="80"
                      cy="80"
                      r="70"
                      stroke="currentColor"
                      strokeWidth="12"
                      fill="transparent"
                      className="text-dark-border"
                    />
                    <motion.circle
                      cx="80"
                      cy="80"
                      r="70"
                      stroke="currentColor"
                      strokeWidth="12"
                      fill="transparent"
                      strokeDasharray={`${2 * Math.PI * 70}`}
                      className="text-blue-500 transition-all duration-1000 ease-out"
                      strokeLinecap="round"
                      initial={{ strokeDashoffset: 2 * Math.PI * 70 }}
                      animate={{ strokeDashoffset: 2 * Math.PI * 70 * (1 - progressPercentage / 100) }}
                      transition={{ duration: 2, ease: "easeOut" }}
                    />
                  </svg>
                  <div className="absolute inset-0 flex flex-col items-center justify-center">
                    <span className="text-3xl font-black text-dark-text">
                      <CountUp end={completedPhases} duration={2} />/<CountUp end={totalPhases} duration={2} />
                    </span>
                    <span className="text-xs font-semibold text-dark-text/70 uppercase">Phases</span>
                  </div>
                </div>
                
                <div className="text-center lg:text-right">
                  <p className="text-sm font-semibold text-dark-text">Development Progress</p>
                  <p className="text-xs text-dark-text/70">
                    <CountUp end={progressPercentage} decimals={0} duration={2} />% Complete
                  </p>
                </div>
              </motion.div>
            </div>

            {/* Release Notes */}
            {versionInfo?.release_notes && (
              <motion.div
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.4, delay: 0.7 }}
                whileHover={{ scale: 1.01 }}
                className="mt-6 p-5 bg-blue-500/10 rounded-xl border border-blue-500/20 hover:shadow-lg hover:shadow-blue-500/10 transition-all duration-300"
              >
                <div className="flex items-start space-x-3">
                  <ChartBarIcon className="h-5 w-5 text-blue-400 mt-0.5 flex-shrink-0" />
                  <div>
                    <h3 className="text-sm font-bold text-dark-text mb-1">Release Highlights</h3>
                    <p className="text-sm text-dark-text/80 leading-relaxed">{versionInfo.release_notes}</p>
                  </div>
                </div>
              </motion.div>
            )}
          </div>
        </motion.div>

        {/* Update Status Card */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5, delay: 0.8 }}
          className="bg-dark-card rounded-2xl shadow-xl overflow-hidden border border-dark-border"
        >
          <div className="px-8 py-6 border-b border-dark-border">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-3">
                <motion.div
                  animate={{ rotate: [0, 360] }}
                  transition={{ duration: 3, repeat: Infinity, ease: "linear" }}
                  className="p-2 bg-blue-500/20 rounded-lg"
                >
                  <ArrowPathIcon className="h-6 w-6 text-blue-400" />
                </motion.div>
                <div>
                  <h2 className="text-2xl font-bold text-dark-text">Update Status</h2>
                  <p className="text-sm text-dark-text/70">Check for the latest security updates</p>
                </div>
              </div>
              
              <motion.button
                whileHover={{ scale: 1.05 }}
                whileTap={{ scale: 0.95 }}
                onClick={() => checkForUpdates(true)}
                disabled={checking}
                className="px-6 py-3 bg-gradient-to-r from-blue-600 to-purple-600 text-white rounded-xl font-semibold shadow-lg hover:shadow-xl transition-all duration-300 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                <div className="flex items-center space-x-2">
                  <ArrowPathIcon className={`h-5 w-5 ${checking ? 'animate-spin' : ''}`} />
                  <span>{checking ? 'Checking...' : 'Check for Updates'}</span>
                </div>
              </motion.button>
            </div>
          </div>

          <div className="p-8">
            <AnimatePresence mode="wait">
              {updateInfo?.available ? (
                <motion.div
                  key="update-available"
                  initial={{ opacity: 0, scale: 0.95 }}
                  animate={{ opacity: 1, scale: 1 }}
                  exit={{ opacity: 0, scale: 0.95 }}
                  className="relative overflow-hidden bg-green-500/10 rounded-2xl border-2 border-green-500/20 p-8 hover:shadow-xl hover:shadow-green-500/20 transition-all duration-300"
                >
                  <div className="absolute top-0 right-0 w-64 h-64 bg-green-500/10 rounded-full blur-3xl animate-pulse"></div>
                  
                  <div className="relative z-10">
                    <div className="flex items-start space-x-6">
                      <motion.div
                        animate={{ scale: [1, 1.1, 1], rotate: [0, 5, -5, 0] }}
                        transition={{ duration: 2, repeat: Infinity }}
                        className="flex-shrink-0"
                      >
                        <div className="p-4 bg-gradient-to-br from-green-400 to-emerald-500 rounded-2xl shadow-xl">
                          <ArrowDownTrayIcon className="h-12 w-12 text-white" />
                        </div>
                      </motion.div>
                      
                      <div className="flex-1">
                        <div className="flex items-center space-x-3 mb-3">
                          <h3 className="text-2xl font-bold text-green-400">
                            New Update Available!
                          </h3>
                          <motion.span
                            animate={{ y: [0, -10, 0] }}
                            transition={{ duration: 1, repeat: Infinity }}
                            className="px-4 py-1.5 bg-green-500 text-white rounded-full text-sm font-bold shadow-lg"
                          >
                            v{updateInfo.latest_version}
                          </motion.span>
                        </div>
                        
                        <div className="flex flex-wrap items-center gap-4 mb-6">
                          <motion.div whileHover={{ scale: 1.05 }}>
                            <div className={`px-3 py-1.5 rounded-lg text-sm font-semibold border-2 ${getUpdateTypeBadge(updateInfo.update_type || '')}`}>
                              {updateInfo.update_type?.toUpperCase()} UPDATE
                            </div>
                          </motion.div>
                          
                          {updateInfo.size_bytes && (
                            <div className="flex items-center space-x-2 text-sm text-green-400">
                              <ArrowDownTrayIcon className="h-4 w-4" />
                              <span className="font-semibold">{formatBytes(updateInfo.size_bytes)}</span>
                            </div>
                          )}
                          
                          {updateInfo.release_date && (
                            <div className="flex items-center space-x-2 text-sm text-green-400">
                              <ClockIcon className="h-4 w-4" />
                              <span className="font-semibold">{formatDate(updateInfo.release_date)}</span>
                            </div>
                          )}
                        </div>

                        {updateInfo.release_notes && (
                          <div className="mb-6 p-6 bg-dark-bg rounded-xl border border-green-500/20 shadow-sm">
                            <h4 className="font-bold text-dark-text mb-3 flex items-center space-x-2">
                              <SparklesIcon className="h-5 w-5 text-green-400" />
                              <span>What's New:</span>
                            </h4>
                            <div className="text-dark-text/80">
                              <pre className="whitespace-pre-wrap font-sans text-sm leading-relaxed">
                                {updateInfo.release_notes}
                              </pre>
                            </div>
                          </div>
                        )}

                        <motion.button
                          whileHover={{ scale: 1.02, y: -2 }}
                          whileTap={{ scale: 0.98 }}
                          onClick={downloadUpdate}
                          disabled={downloading}
                          className="px-8 py-4 bg-gradient-to-r from-green-600 to-emerald-600 text-white rounded-xl font-bold shadow-xl hover:shadow-2xl transition-all duration-300 disabled:opacity-50 disabled:cursor-not-allowed"
                        >
                          <div className="flex items-center space-x-3">
                            <ArrowDownTrayIcon className={`h-6 w-6 ${downloading ? 'animate-bounce' : ''}`} />
                            <span className="text-lg">
                              {downloading ? 'Downloading Update...' : 'Download & Install Update'}
                            </span>
                          </div>
                        </motion.button>
                      </div>
                    </div>
                  </div>
                </motion.div>
              ) : (
                <motion.div
                  key="up-to-date"
                  initial={{ opacity: 0, scale: 0.95 }}
                  animate={{ opacity: 1, scale: 1 }}
                  exit={{ opacity: 0, scale: 0.95 }}
                  className="relative overflow-hidden bg-dark-bg rounded-2xl border-2 border-dark-border p-8 hover:shadow-lg transition-shadow duration-300"
                >
                  <div className="flex items-center space-x-6">
                    <div className="flex-shrink-0">
                      <div className="relative">
                        <motion.div
                          animate={{ scale: [1, 1.1, 1] }}
                          transition={{ duration: 2, repeat: Infinity }}
                          className="p-4 bg-gradient-to-br from-green-400 to-emerald-500 rounded-2xl shadow-lg"
                        >
                          <CheckCircleIcon className="h-12 w-12 text-white" />
                        </motion.div>
                        <motion.div
                          animate={{ rotate: [0, 360] }}
                          transition={{ duration: 3, repeat: Infinity, ease: "linear" }}
                          className="absolute -top-1 -right-1"
                        >
                          <SparklesIcon className="h-6 w-6 text-yellow-400" />
                        </motion.div>
                      </div>
                    </div>
                    
                    <div>
                      <h3 className="text-2xl font-bold text-dark-text mb-2">
                        You're Up to Date! 🎉
                      </h3>
                      <p className="text-dark-text/70 text-lg">
                        {updateInfo?.message || 'Your CyberGuardian is running the latest version with all security patches.'}
                      </p>
                    </div>
                  </div>
                </motion.div>
              )}
            </AnimatePresence>
          </div>
        </motion.div>

        {/* Update History */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5, delay: 0.9 }}
          className="bg-dark-card rounded-2xl shadow-xl overflow-hidden border border-dark-border"
        >
          <div className="px-8 py-6 border-b border-dark-border">
            <div className="flex items-center space-x-3">
              <motion.div
                animate={{ rotate: [0, 360] }}
                transition={{ duration: 20, repeat: Infinity, ease: "linear" }}
                className="p-2 bg-purple-500/20 rounded-lg"
              >
                <ClockIcon className="h-6 w-6 text-purple-400" />
              </motion.div>
              <div>
                <h2 className="text-2xl font-bold text-dark-text">Update History</h2>
                <p className="text-sm text-dark-text/70">Track all system updates and changes</p>
              </div>
            </div>
          </div>

          <div className="p-8">
            <AnimatePresence mode="wait">
              {updateHistory.length === 0 ? (
                <motion.div
                  key="no-history"
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  exit={{ opacity: 0 }}
                  className="text-center py-16"
                >
                  <motion.div
                    animate={{ scale: [1, 1.1, 1], rotate: [0, 5, -5, 0] }}
                    transition={{ duration: 2, repeat: Infinity, repeatType: "reverse" }}
                    className="inline-flex items-center justify-center w-20 h-20 bg-dark-bg rounded-full mb-4"
                  >
                    <ClockIcon className="h-10 w-10 text-dark-text/50" />
                  </motion.div>
                  <h3 className="text-lg font-semibold text-dark-text mb-2">No Update History Yet</h3>
                  <p className="text-dark-text/70">Update history will appear here once you perform system updates</p>
                </motion.div>
              ) : (
                <motion.div
                  key="history"
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  className="relative"
                >
                  {/* Timeline Line */}
                  <div className="absolute left-8 top-0 bottom-0 w-0.5 bg-gradient-to-b from-blue-500/50 via-purple-500/50 to-pink-500/50"></div>

                  <div className="space-y-8">
                    {updateHistory.map((update, index) => (
                      <motion.div
                        key={update.id}
                        initial={{ opacity: 0, x: -20 }}
                        animate={{ opacity: 1, x: 0 }}
                        transition={{ duration: 0.3, delay: index * 0.1 }}
                        whileHover={{ scale: 1.01, x: 4 }}
                        className="relative pl-20 group"
                      >
                        {/* Timeline Dot */}
                        <div className="absolute left-5 top-1 flex items-center justify-center">
                          <motion.div
                            whileHover={{ scale: 1.2 }}
                            className="w-8 h-8 bg-dark-card rounded-full border-4 border-dark-border shadow-lg flex items-center justify-center group-hover:border-blue-500/50 transition-all"
                          >
                            {getStatusIcon(update.status)}
                          </motion.div>
                        </div>

                        {/* Content Card */}
                        <div className="bg-dark-bg rounded-xl border-2 border-dark-border p-6 hover:border-blue-500/30 hover:shadow-lg hover:shadow-blue-500/10 transition-all duration-300">
                          <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4 mb-4">
                            <div className="flex items-center space-x-4">
                              <div>
                                <div className="flex items-center space-x-2 mb-2">
                                  <span className="text-lg font-bold text-dark-text">
                                    {update.from_version}
                                  </span>
                                  <ArrowPathIcon className="h-4 w-4 text-dark-text/50" />
                                  <span className="text-lg font-bold text-blue-400">
                                    {update.to_version}
                                  </span>
                                </div>
                                
                                <div className="flex items-center space-x-2">
                                  <motion.span whileHover={{ scale: 1.05 }} className={`px-3 py-1 rounded-lg text-xs font-bold border-2 ${getStatusBadge(update.status)}`}>
                                    {update.status.toUpperCase()}
                                  </motion.span>
                                  <motion.span whileHover={{ scale: 1.05 }} className={`px-3 py-1 rounded-lg text-xs font-bold border-2 ${getUpdateTypeBadge(update.update_type)}`}>
                                    {update.update_type.toUpperCase()}
                                  </motion.span>
                                </div>
                              </div>
                            </div>

                            {update.duration_seconds && (
                              <motion.div
                                whileHover={{ scale: 1.05 }}
                                className="flex items-center space-x-2 px-4 py-2 bg-blue-500/10 rounded-lg border border-blue-500/20"
                              >
                                <BoltIcon className="h-5 w-5 text-blue-400" />
                                <span className="text-sm font-semibold text-blue-400">
                                  <CountUp end={update.duration_seconds} duration={1} />s
                                </span>
                              </motion.div>
                            )}
                          </div>

                          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 text-sm">
                            <div className="flex items-center space-x-2 text-dark-text/70">
                              <ClockIcon className="h-4 w-4 text-dark-text/50" />
                              <span className="font-medium">Started:</span>
                              <span>{formatDate(update.started_at)}</span>
                            </div>
                            
                            {update.completed_at && (
                              <div className="flex items-center space-x-2 text-dark-text/70">
                                <CheckCircleIcon className="h-4 w-4 text-dark-text/50" />
                                <span className="font-medium">Completed:</span>
                                <span>{formatDate(update.completed_at)}</span>
                              </div>
                            )}
                          </div>

                          {update.error_message && (
                            <motion.div
                              initial={{ opacity: 0, height: 0 }}
                              animate={{ opacity: 1, height: 'auto' }}
                              className="mt-4 p-4 bg-red-500/10 border border-red-500/20 rounded-lg"
                            >
                              <div className="flex items-start space-x-3">
                                <ExclamationTriangleIcon className="h-5 w-5 text-red-400 mt-0.5 flex-shrink-0" />
                                <div>
                                  <p className="text-sm font-semibold text-red-400 mb-1">Error Details:</p>
                                  <p className="text-sm text-red-400/80">{update.error_message}</p>
                                </div>
                              </div>
                            </motion.div>
                          )}
                        </div>
                      </motion.div>
                    ))}
                  </div>
                </motion.div>
              )}
            </AnimatePresence>
          </div>
        </motion.div>

      </div>
    </motion.div>
  );
}
