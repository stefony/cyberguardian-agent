

import { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import CountUp from 'react-countup';
import { 
  ShieldCheckIcon,
  ServerIcon,
  LockClosedIcon,
  ExclamationTriangleIcon,
  CheckCircleIcon,
  LightBulbIcon,
  ArrowPathIcon,
  SparklesIcon,
  BoltIcon,
  ComputerDesktopIcon,
  CpuChipIcon,
  PlayIcon,
  StopIcon,
  MagnifyingGlassIcon
} from '@heroicons/react/24/outline';
import { processProtectionApi, processMonitorApi } from '@/lib/api';
import ProtectedRoute from '@/components/ProtectedRoute';

const API_URL = (import.meta as any).env.VITE_API_URL || 'http://localhost:8000';

interface ProtectionStatus {
  platform: string;
  is_protected: boolean;
  service_installed: boolean;
  can_protect: boolean;
  is_admin: boolean;
  is_root: boolean;
  username: string;
  recommendations: string[];
}

interface Statistics {
  platform: string;
  is_protected: boolean;
  service_installed: boolean;
  has_admin_rights: boolean;
  has_root_rights: boolean;
  can_enable_protection: boolean;
  recommendations_count: number;
}

interface MonitorStats {
  total_processes: number;
  suspicious_processes: number;
  total_threats: number;
  threats_by_type: Record<string, number>;
  threats_by_severity: Record<string, number>;
  monitoring_active: boolean;
  platform: string;
  last_scan: string;
}

interface Process {
  pid: number;
  name: string;
  username: string;
  cpu_percent: number;
  memory_mb: number;
  exe_path: string;
  cmdline: string;
  created_at: string;
  suspicious: boolean;
}

interface Threat {
  type: string;
  pid: number;
  process_name: string;
  severity: string;
  description: string;
  details: any;
  detected_at: string;
}

export default function ProcessProtectionPage() {
  const [status, setStatus] = useState<ProtectionStatus | null>(null);
  const [statistics, setStatistics] = useState<Statistics | null>(null);
  const [monitorStats, setMonitorStats] = useState<MonitorStats | null>(null);
  const [processes, setProcesses] = useState<Process[]>([]);
  const [threats, setThreats] = useState<Threat[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [actionLoading, setActionLoading] = useState<string | null>(null);
  const [scanningProcess, setScanningProcess] = useState<number | null>(null);
  const [detectionMode, setDetectionMode] = useState<'production' | 'demo' | 'testing'>('demo');
  // ← ДОБАВИ ТАЗИ ФУНКЦИЯ ТУК:
const handleModeChange = async (newMode: 'production' | 'demo' | 'testing') => {
  try {
    const response = await processMonitorApi.setDetectionMode(newMode);
    if (response.success) {
      setDetectionMode(newMode);
      console.log(`✅ Detection mode changed to: ${newMode}`);
    }
  } catch (error) {
    console.error('❌ Error changing detection mode:', error);
  }
};

const fetchData = async (showRefreshing = false) => {
  if (showRefreshing) setRefreshing(true);
  
  try {
    const [statusRes, statsRes, monitorStatsRes, monitorStatusRes, processesRes, threatsRes] = await Promise.all([
      processProtectionApi.getStatus(),
      processProtectionApi.getStatistics(),
      processMonitorApi.getStatistics(),
      processMonitorApi.getMonitoringStatus(),
      processMonitorApi.getProcesses(50),
      processMonitorApi.getThreats({ limit: 20 })
    ]);

    if (statusRes.success && statusRes.data) {
      setStatus(statusRes.data);
      if (statsRes.success && statsRes.data) setStatistics(statsRes.data);
      if (monitorStatsRes.success && monitorStatsRes.data) setMonitorStats(monitorStatsRes.data);
      
      if (monitorStatusRes.success && monitorStatusRes.data?.monitoring) {
        setMonitorStats(prev => ({
          ...prev!,
          monitoring_active: monitorStatusRes.data!.monitoring.active
        }));
      }
      
      if (processesRes.success && processesRes.data) setProcesses(processesRes.data.processes);
      if (threatsRes.success && threatsRes.data) setThreats(threatsRes.data.threats);
      
      const modeRes = await processMonitorApi.getDetectionMode();
      if (modeRes.success && modeRes.data?.mode) {
        setDetectionMode(modeRes.data.mode as any);
      }
    } else {
      console.log('🟡 Using mock process protection data');
      
      const mockStatus: ProtectionStatus = {
        platform: 'Windows',
        is_protected: true,
        service_installed: true,
        can_protect: true,
        is_admin: true,
        is_root: false,
        username: 'Administrator',
        recommendations: []
      };
      
      const mockStatistics: Statistics = {
        platform: 'Windows',
        is_protected: true,
        service_installed: true,
        has_admin_rights: true,
        has_root_rights: false,
        can_enable_protection: true,
        recommendations_count: 0
      };
      
      const mockMonitorStats: MonitorStats = {
        total_processes: 247,
        suspicious_processes: 3,
        total_threats: 5,
        threats_by_type: {
          'process_injection': 2,
          'dll_hijacking': 2,
          'process_hollowing': 1
        },
        threats_by_severity: {
          'critical': 1,
          'high': 2,
          'medium': 2
        },
        monitoring_active: true,
        platform: 'Windows',
        last_scan: new Date(Date.now() - 300000).toISOString()
      };
      
      const mockProcesses: Process[] = [
        { pid: 1234, name: 'cyberguardian.exe', username: 'SYSTEM', cpu_percent: 2.5, memory_mb: 256, exe_path: 'C:\\Program Files\\CyberGuardian\\cyberguardian.exe', cmdline: 'cyberguardian.exe --service', created_at: new Date(Date.now() - 86400000).toISOString(), suspicious: false },
        { pid: 5678, name: 'chrome.exe', username: 'Administrator', cpu_percent: 15.3, memory_mb: 512, exe_path: 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe', cmdline: 'chrome.exe', created_at: new Date(Date.now() - 7200000).toISOString(), suspicious: false },
        { pid: 9012, name: 'suspicious.exe', username: 'Administrator', cpu_percent: 45.7, memory_mb: 1024, exe_path: 'C:\\Temp\\suspicious.exe', cmdline: 'suspicious.exe --inject', created_at: new Date(Date.now() - 600000).toISOString(), suspicious: true },
        { pid: 3456, name: 'explorer.exe', username: 'Administrator', cpu_percent: 3.2, memory_mb: 128, exe_path: 'C:\\Windows\\explorer.exe', cmdline: 'C:\\Windows\\explorer.exe', created_at: new Date(Date.now() - 172800000).toISOString(), suspicious: false },
        { pid: 7890, name: 'notepad.exe', username: 'Administrator', cpu_percent: 0.1, memory_mb: 32, exe_path: 'C:\\Windows\\System32\\notepad.exe', cmdline: 'notepad.exe document.txt', created_at: new Date(Date.now() - 3600000).toISOString(), suspicious: false },
        { pid: 2345, name: 'malware.dll', username: 'Administrator', cpu_percent: 23.4, memory_mb: 64, exe_path: 'C:\\Windows\\Temp\\malware.dll', cmdline: 'rundll32.exe malware.dll', created_at: new Date(Date.now() - 1800000).toISOString(), suspicious: true },
        { pid: 6789, name: 'svchost.exe', username: 'SYSTEM', cpu_percent: 1.2, memory_mb: 48, exe_path: 'C:\\Windows\\System32\\svchost.exe', cmdline: 'svchost.exe -k netsvcs', created_at: new Date(Date.now() - 259200000).toISOString(), suspicious: false },
        { pid: 1111, name: 'powershell.exe', username: 'Administrator', cpu_percent: 5.6, memory_mb: 96, exe_path: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', cmdline: 'powershell.exe', created_at: new Date(Date.now() - 900000).toISOString(), suspicious: false },
        { pid: 2222, name: 'hollowed.exe', username: 'Administrator', cpu_percent: 67.8, memory_mb: 2048, exe_path: 'C:\\Users\\Public\\hollowed.exe', cmdline: 'hollowed.exe', created_at: new Date(Date.now() - 1200000).toISOString(), suspicious: true },
        { pid: 3333, name: 'taskmgr.exe', username: 'Administrator', cpu_percent: 2.1, memory_mb: 64, exe_path: 'C:\\Windows\\System32\\taskmgr.exe', cmdline: 'taskmgr.exe', created_at: new Date(Date.now() - 10800000).toISOString(), suspicious: false }
      ];
      
      const mockThreats: Threat[] = [
        { type: 'process_injection', pid: 9012, process_name: 'suspicious.exe', severity: 'critical', description: 'Process injection detected', details: { target_pid: 1234, injection_type: 'CreateRemoteThread' }, detected_at: new Date(Date.now() - 300000).toISOString() },
        { type: 'dll_hijacking', pid: 2345, process_name: 'malware.dll', severity: 'high', description: 'DLL hijacking attempt detected', details: { dll_path: 'C:\\Windows\\Temp\\malware.dll', legitimate_dll: 'kernel32.dll' }, detected_at: new Date(Date.now() - 600000).toISOString() },
        { type: 'process_hollowing', pid: 2222, process_name: 'hollowed.exe', severity: 'critical', description: 'Process hollowing detected', details: { original_process: 'svchost.exe', hollowed_process: 'hollowed.exe' }, detected_at: new Date(Date.now() - 900000).toISOString() },
        { type: 'dll_hijacking', pid: 2345, process_name: 'malware.dll', severity: 'high', description: 'Suspicious DLL loaded', details: { dll_name: 'evil.dll', loaded_by: 'explorer.exe' }, detected_at: new Date(Date.now() - 1200000).toISOString() },
        { type: 'process_injection', pid: 9012, process_name: 'suspicious.exe', severity: 'medium', description: 'Memory allocation in protected process', details: { allocation_type: 'VirtualAllocEx', size: '4096 bytes' }, detected_at: new Date(Date.now() - 1500000).toISOString() }
      ];
      
      setStatus(mockStatus);
      setStatistics(mockStatistics);
      setMonitorStats(mockMonitorStats);
      setProcesses(mockProcesses);
      setThreats(mockThreats);
      setDetectionMode('production');
    }

  } catch (error) {
    console.error('Error fetching process data:', error);
    console.log('🟡 Using mock process protection data (error fallback)');
    
    const mockStatus: ProtectionStatus = {
      platform: 'Windows',
      is_protected: true,
      service_installed: true,
      can_protect: true,
      is_admin: true,
      is_root: false,
      username: 'Administrator',
      recommendations: []
    };
    
    const mockStatistics: Statistics = {
      platform: 'Windows',
      is_protected: true,
      service_installed: true,
      has_admin_rights: true,
      has_root_rights: false,
      can_enable_protection: true,
      recommendations_count: 0
    };
    
    const mockMonitorStats: MonitorStats = {
      total_processes: 247,
      suspicious_processes: 3,
      total_threats: 5,
      threats_by_type: {
        'process_injection': 2,
        'dll_hijacking': 2,
        'process_hollowing': 1
      },
      threats_by_severity: {
        'critical': 1,
        'high': 2,
        'medium': 2
      },
      monitoring_active: true,
      platform: 'Windows',
      last_scan: new Date(Date.now() - 300000).toISOString()
    };
    
    const mockProcesses: Process[] = [
      { pid: 1234, name: 'cyberguardian.exe', username: 'SYSTEM', cpu_percent: 2.5, memory_mb: 256, exe_path: 'C:\\Program Files\\CyberGuardian\\cyberguardian.exe', cmdline: 'cyberguardian.exe --service', created_at: new Date(Date.now() - 86400000).toISOString(), suspicious: false },
      { pid: 5678, name: 'chrome.exe', username: 'Administrator', cpu_percent: 15.3, memory_mb: 512, exe_path: 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe', cmdline: 'chrome.exe', created_at: new Date(Date.now() - 7200000).toISOString(), suspicious: false },
      { pid: 9012, name: 'suspicious.exe', username: 'Administrator', cpu_percent: 45.7, memory_mb: 1024, exe_path: 'C:\\Temp\\suspicious.exe', cmdline: 'suspicious.exe --inject', created_at: new Date(Date.now() - 600000).toISOString(), suspicious: true },
      { pid: 3456, name: 'explorer.exe', username: 'Administrator', cpu_percent: 3.2, memory_mb: 128, exe_path: 'C:\\Windows\\explorer.exe', cmdline: 'C:\\Windows\\explorer.exe', created_at: new Date(Date.now() - 172800000).toISOString(), suspicious: false },
      { pid: 7890, name: 'notepad.exe', username: 'Administrator', cpu_percent: 0.1, memory_mb: 32, exe_path: 'C:\\Windows\\System32\\notepad.exe', cmdline: 'notepad.exe document.txt', created_at: new Date(Date.now() - 3600000).toISOString(), suspicious: false },
      { pid: 2345, name: 'malware.dll', username: 'Administrator', cpu_percent: 23.4, memory_mb: 64, exe_path: 'C:\\Windows\\Temp\\malware.dll', cmdline: 'rundll32.exe malware.dll', created_at: new Date(Date.now() - 1800000).toISOString(), suspicious: true },
      { pid: 6789, name: 'svchost.exe', username: 'SYSTEM', cpu_percent: 1.2, memory_mb: 48, exe_path: 'C:\\Windows\\System32\\svchost.exe', cmdline: 'svchost.exe -k netsvcs', created_at: new Date(Date.now() - 259200000).toISOString(), suspicious: false },
      { pid: 1111, name: 'powershell.exe', username: 'Administrator', cpu_percent: 5.6, memory_mb: 96, exe_path: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', cmdline: 'powershell.exe', created_at: new Date(Date.now() - 900000).toISOString(), suspicious: false },
      { pid: 2222, name: 'hollowed.exe', username: 'Administrator', cpu_percent: 67.8, memory_mb: 2048, exe_path: 'C:\\Users\\Public\\hollowed.exe', cmdline: 'hollowed.exe', created_at: new Date(Date.now() - 1200000).toISOString(), suspicious: true },
      { pid: 3333, name: 'taskmgr.exe', username: 'Administrator', cpu_percent: 2.1, memory_mb: 64, exe_path: 'C:\\Windows\\System32\\taskmgr.exe', cmdline: 'taskmgr.exe', created_at: new Date(Date.now() - 10800000).toISOString(), suspicious: false }
    ];
    
    const mockThreats: Threat[] = [
      { type: 'process_injection', pid: 9012, process_name: 'suspicious.exe', severity: 'critical', description: 'Process injection detected', details: { target_pid: 1234, injection_type: 'CreateRemoteThread' }, detected_at: new Date(Date.now() - 300000).toISOString() },
      { type: 'dll_hijacking', pid: 2345, process_name: 'malware.dll', severity: 'high', description: 'DLL hijacking attempt detected', details: { dll_path: 'C:\\Windows\\Temp\\malware.dll', legitimate_dll: 'kernel32.dll' }, detected_at: new Date(Date.now() - 600000).toISOString() },
      { type: 'process_hollowing', pid: 2222, process_name: 'hollowed.exe', severity: 'critical', description: 'Process hollowing detected', details: { original_process: 'svchost.exe', hollowed_process: 'hollowed.exe' }, detected_at: new Date(Date.now() - 900000).toISOString() },
      { type: 'dll_hijacking', pid: 2345, process_name: 'malware.dll', severity: 'high', description: 'Suspicious DLL loaded', details: { dll_name: 'evil.dll', loaded_by: 'explorer.exe' }, detected_at: new Date(Date.now() - 1200000).toISOString() },
      { type: 'process_injection', pid: 9012, process_name: 'suspicious.exe', severity: 'medium', description: 'Memory allocation in protected process', details: { allocation_type: 'VirtualAllocEx', size: '4096 bytes' }, detected_at: new Date(Date.now() - 1500000).toISOString() }
    ];
    
    setStatus(mockStatus);
    setStatistics(mockStatistics);
    setMonitorStats(mockMonitorStats);
    setProcesses(mockProcesses);
    setThreats(mockThreats);
    setDetectionMode('production');
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

  const handleEnableAntiTermination = async () => {
    setActionLoading('anti-termination');
    try {
      const response = await processProtectionApi.enableAntiTermination();
      if (response.success) await fetchData();
    } catch (error) {
      console.error('Error enabling anti-termination:', error);
    } finally {
      setActionLoading(null);
    }
  };

  const handleEnableSelfHealing = async () => {
    setActionLoading('self-healing');
    try {
      const response = await processProtectionApi.enableSelfHealing();
      if (response.success) await fetchData();
    } catch (error) {
      console.error('Error enabling self-healing:', error);
    } finally {
      setActionLoading(null);
    }
  };

  const handleEnableMaxProtection = async () => {
    setActionLoading('max-protection');
    try {
      const response = await processProtectionApi.enableMaximumProtection();
      if (response.success) await fetchData();
    } catch (error) {
      console.error('Error enabling maximum protection:', error);
    } finally {
      setActionLoading(null);
    }
  };

  const handleInstallService = async () => {
    setActionLoading('install-service');
    try {
      const response = await processProtectionApi.installService();
      if (response.success) await fetchData();
    } catch (error) {
      console.error('Error installing service:', error);
    } finally {
      setActionLoading(null);
    }
  };

  const handleStartMonitoring = async () => {
    setActionLoading('start-monitoring');
    try {
      const response = await processMonitorApi.startMonitoring();
      if (response.success) await fetchData();
    } catch (error) {
      console.error('Error starting monitoring:', error);
    } finally {
      setActionLoading(null);
    }
  };

  const handleStopMonitoring = async () => {
    setActionLoading('stop-monitoring');
    try {
      const response = await processMonitorApi.stopMonitoring();
      if (response.success) await fetchData();
    } catch (error) {
      console.error('Error stopping monitoring:', error);
    } finally {
      setActionLoading(null);
    }
  };

  const handleTriggerScan = async () => {
    setActionLoading('trigger-scan');
    try {
      const response = await processMonitorApi.triggerScan();
      if (response.success) await fetchData();
    } catch (error) {
      console.error('Error triggering scan:', error);
    } finally {
      setActionLoading(null);
    }
  };

  const handleScanProcessMemory = async (pid: number) => {
    setScanningProcess(pid);
    try {
      const response = await processMonitorApi.scanProcessMemory(pid);
      if (response.success) await fetchData();
    } catch (error) {
      console.error(`Error scanning process ${pid}:`, error);
    } finally {
      setScanningProcess(null);
    }
  };

  const getPlatformIcon = (platform: string) => {
    if (platform === 'Windows') return '🪟';
    if (platform === 'Linux') return '🐧';
    if (platform === 'Darwin') return '🍎';
    return '💻';
  };

  const getStatusColor = (isProtected: boolean) => {
    return isProtected ? 'text-green-500' : 'text-red-500';
  };

  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical': return 'bg-red-500/20 text-red-400 border-red-500/30';
      case 'high': return 'bg-orange-500/20 text-orange-400 border-orange-500/30';
      case 'medium': return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30';
      default: return 'bg-blue-500/20 text-blue-400 border-blue-500/30';
    }
  };

  const getThreatTypeIcon = (type: string) => {
    switch (type) {
      case 'process_injection': return '💉';
      case 'dll_hijacking': return '📚';
      case 'process_hollowing': return '👻';
      default: return '⚠️';
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

  if (!status || !statistics) {
    return null;
  }

  return (
    <ProtectedRoute>
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
            <div className="flex items-center justify-between">
              <div>
                <div className="flex items-center space-x-3 mb-4">
                  <motion.div
                    animate={{ scale: [1, 1.1, 1] }}
                    transition={{ duration: 2, repeat: Infinity }}
                  >
                    <ShieldCheckIcon className="h-10 w-10" />
                  </motion.div>
                  <h1 className="text-4xl font-bold">Process Protection & Monitoring</h1>
                </div>
                <p className="text-blue-100 text-lg">Anti-termination, self-healing & advanced threat detection</p>
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

        {/* Status Cards */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
          
          {/* Platform */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.4, delay: 0.2 }}
            whileHover={{ scale: 1.02, y: -4 }}
            className="p-6 bg-blue-500/10 rounded-xl border-2 border-blue-500/20 hover:shadow-xl hover:shadow-blue-500/20 transition-all duration-300"
          >
            <div className="flex items-center space-x-3 mb-2">
              <ComputerDesktopIcon className="h-6 w-6 text-blue-400" />
              <p className="text-sm font-semibold text-dark-text/70 uppercase">Platform</p>
            </div>
            <p className="text-2xl font-black text-blue-400 flex items-center space-x-2">
              <span>{getPlatformIcon(status.platform)}</span>
              <span>{status.platform}</span>
            </p>
          </motion.div>

          {/* Total Processes */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.4, delay: 0.3 }}
            whileHover={{ scale: 1.02, y: -4 }}
            className="p-6 bg-purple-500/10 rounded-xl border-2 border-purple-500/20 hover:shadow-xl hover:shadow-purple-500/20 transition-all duration-300"
          >
            <div className="flex items-center space-x-3 mb-2">
              <CpuChipIcon className="h-6 w-6 text-purple-400" />
              <p className="text-sm font-semibold text-dark-text/70 uppercase">Total Processes</p>
            </div>
            <p className="text-3xl font-black text-purple-400">
              <CountUp end={monitorStats?.total_processes || 0} duration={2} />
            </p>
          </motion.div>

          {/* Suspicious Processes */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.4, delay: 0.4 }}
            whileHover={{ scale: 1.02, y: -4 }}
            className="p-6 bg-yellow-500/10 rounded-xl border-2 border-yellow-500/20 hover:shadow-xl hover:shadow-yellow-500/20 transition-all duration-300"
          >
            <div className="flex items-center space-x-3 mb-2">
              <ExclamationTriangleIcon className="h-6 w-6 text-yellow-400" />
              <p className="text-sm font-semibold text-dark-text/70 uppercase">Suspicious</p>
            </div>
            <p className="text-3xl font-black text-yellow-400">
              <CountUp end={monitorStats?.suspicious_processes || 0} duration={2} />
            </p>
          </motion.div>

          {/* Threats Detected */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.4, delay: 0.5 }}
            whileHover={{ scale: 1.02, y: -4 }}
            className="p-6 bg-red-500/10 rounded-xl border-2 border-red-500/20 hover:shadow-xl hover:shadow-red-500/20 transition-all duration-300"
          >
            <div className="flex items-center space-x-3 mb-2">
              <ShieldCheckIcon className="h-6 w-6 text-red-400" />
              <p className="text-sm font-semibold text-dark-text/70 uppercase">Threats</p>
            </div>
            <p className="text-3xl font-black text-red-400">
              <CountUp end={monitorStats?.total_threats || 0} duration={2} />
            </p>
          </motion.div>

        </div>

        {/* Monitoring Controls */}
        {monitorStats && (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: 0.6 }}
            className="bg-dark-card rounded-2xl shadow-xl overflow-hidden border border-dark-border"
          >
            <div className="px-8 py-6 border-b border-dark-border">
  <div className="flex items-center justify-between">
    <div className="flex items-center space-x-3">
      <BoltIcon className="h-6 w-6 text-cyan-500" />
      <h2 className="text-2xl font-bold text-dark-text">Advanced Monitoring</h2>
    </div>
    <div className="flex items-center space-x-3">
      {/* Detection Mode Dropdown */}
      <select
        value={detectionMode}
        onChange={(e) => handleModeChange(e.target.value as any)}
        className="px-4 py-2 rounded-lg bg-dark-bg border-2 border-dark-border text-dark-text font-semibold cursor-pointer hover:border-cyan-500 transition-colors"
      >
        <option value="production">Production Mode</option>
        <option value="demo">Demo Mode</option>
        <option value="testing">Testing Mode</option>
      </select>
      
      <span className={`px-3 py-1 rounded-full text-sm font-bold ${
        monitorStats.monitoring_active 
          ? 'bg-green-500/20 text-green-400' 
          : 'bg-gray-500/20 text-gray-400'
      }`}>
        {monitorStats.monitoring_active ? '🟢 Active' : '🔴 Inactive'}
      </span>
    </div>
  </div>
</div>

            <div className="p-8">
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                
                {/* Start/Stop Monitoring */}
                <motion.button
                  whileHover={{ scale: 1.02, y: -2 }}
                  whileTap={{ scale: 0.98 }}
                  onClick={monitorStats.monitoring_active ? handleStopMonitoring : handleStartMonitoring}
                  disabled={actionLoading === 'start-monitoring' || actionLoading === 'stop-monitoring'}
                  className={`p-6 rounded-xl border-2 font-semibold transition-all duration-300 ${
                    monitorStats.monitoring_active
                      ? 'bg-red-600 hover:bg-red-700 border-red-500/20 text-white hover:shadow-lg hover:shadow-red-500/30'
                      : 'bg-green-600 hover:bg-green-700 border-green-500/20 text-white hover:shadow-lg hover:shadow-green-500/30'
                  } disabled:opacity-50 disabled:cursor-not-allowed`}
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-3">
                      {monitorStats.monitoring_active ? (
                        <StopIcon className="h-6 w-6" />
                      ) : (
                        <PlayIcon className="h-6 w-6" />
                      )}
                      <span>{monitorStats.monitoring_active ? 'Stop Monitoring' : 'Start Monitoring'}</span>
                    </div>
                    {(actionLoading === 'start-monitoring' || actionLoading === 'stop-monitoring') && (
                      <ArrowPathIcon className="h-5 w-5 animate-spin" />
                    )}
                  </div>
                </motion.button>

                {/* Trigger Scan */}
                <motion.button
                  whileHover={{ scale: 1.02, y: -2 }}
                  whileTap={{ scale: 0.98 }}
                  onClick={handleTriggerScan}
                  disabled={actionLoading === 'trigger-scan'}
                  className="p-6 bg-purple-600 hover:bg-purple-700 rounded-xl border-2 border-purple-500/20 font-semibold transition-all duration-300 hover:shadow-lg hover:shadow-purple-500/30 text-white disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-3">
                      <MagnifyingGlassIcon className="h-6 w-6" />
                      <span>Trigger Scan</span>
                    </div>
                    {actionLoading === 'trigger-scan' && (
                      <ArrowPathIcon className="h-5 w-5 animate-spin" />
                    )}
                  </div>
                </motion.button>

                {/* Clear Threats */}
                <motion.button
                  whileHover={{ scale: 1.02, y: -2 }}
                  whileTap={{ scale: 0.98 }}
                  onClick={async () => {
                    try {
                      await processMonitorApi.clearThreats();
                      await fetchData();
                    } catch (error) {
                      console.error('Error clearing threats:', error);
                    }
                  }}
                  className="p-6 bg-orange-600 hover:bg-orange-700 rounded-xl border-2 border-orange-500/20 font-semibold transition-all duration-300 hover:shadow-lg hover:shadow-orange-500/30 text-white"
                >
                  <div className="flex items-center space-x-3">
                    <ArrowPathIcon className="h-6 w-6" />
                    <span>Clear Threats</span>
                  </div>
                </motion.button>

              </div>
            </div>
          </motion.div>
        )}

        {/* Protection Controls */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5, delay: 0.7 }}
          className="bg-dark-card rounded-2xl shadow-xl overflow-hidden border border-dark-border"
        >
          <div className="px-8 py-6 border-b border-dark-border">
            <div className="flex items-center space-x-3">
              <BoltIcon className="h-6 w-6 text-purple-500" />
              <h2 className="text-2xl font-bold text-dark-text">Protection Controls</h2>
            </div>
            <p className="text-sm text-dark-text/70 mt-1">Enable and manage protection mechanisms</p>
          </div>

          <div className="p-8">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              
              {/* Enable Anti-Termination */}
              <motion.button
                whileHover={{ scale: 1.02, y: -2 }}
                whileTap={{ scale: 0.98 }}
                onClick={handleEnableAntiTermination}
                disabled={actionLoading === 'anti-termination' || !status.can_protect}
                className={`p-6 rounded-xl border-2 font-semibold transition-all duration-300 ${
                  status.is_protected
                    ? 'bg-green-500/10 border-green-500/20 text-green-400'
                    : 'bg-purple-600 hover:bg-purple-700 border-purple-500/20 text-white hover:shadow-lg hover:shadow-purple-500/30'
                } disabled:opacity-50 disabled:cursor-not-allowed`}
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-3">
                    <ShieldCheckIcon className="h-6 w-6" />
                    <span>Enable Anti-Termination</span>
                  </div>
                  {actionLoading === 'anti-termination' && (
                    <ArrowPathIcon className="h-5 w-5 animate-spin" />
                  )}
                </div>
                {!status.can_protect && (
                  <p className="text-xs text-left mt-2 opacity-70">Requires elevated privileges</p>
                )}
              </motion.button>

              {/* Enable Self-Healing */}
              <motion.button
                whileHover={{ scale: 1.02, y: -2 }}
                whileTap={{ scale: 0.98 }}
                onClick={handleEnableSelfHealing}
                disabled={actionLoading === 'self-healing'}
                className="p-6 bg-blue-600 hover:bg-blue-700 rounded-xl border-2 border-blue-500/20 font-semibold transition-all duration-300 hover:shadow-lg hover:shadow-blue-500/30 text-white disabled:opacity-50 disabled:cursor-not-allowed"
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-3">
                    <SparklesIcon className="h-6 w-6" />
                    <span>Enable Self-Healing</span>
                  </div>
                  {actionLoading === 'self-healing' && (
                    <ArrowPathIcon className="h-5 w-5 animate-spin" />
                  )}
                </div>
              </motion.button>

              {/* Maximum Protection */}
              <motion.button
                whileHover={{ scale: 1.02, y: -2 }}
                whileTap={{ scale: 0.98 }}
                onClick={handleEnableMaxProtection}
                disabled={actionLoading === 'max-protection' || !status.can_protect}
                className="p-6 bg-gradient-to-r from-purple-600 to-pink-600 hover:from-purple-700 hover:to-pink-700 rounded-xl border-2 border-purple-500/20 font-semibold transition-all duration-300 hover:shadow-lg hover:shadow-purple-500/30 text-white disabled:opacity-50 disabled:cursor-not-allowed"
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-3">
                    <BoltIcon className="h-6 w-6" />
                    <span>🚀 Maximum Protection</span>
                  </div>
                  {actionLoading === 'max-protection' && (
                    <ArrowPathIcon className="h-5 w-5 animate-spin" />
                  )}
                </div>
                {!status.can_protect && (
                  <p className="text-xs text-left mt-2 opacity-70">Requires elevated privileges</p>
                )}
              </motion.button>

              {/* Install Service */}
              <motion.button
                whileHover={{ scale: 1.02, y: -2 }}
                whileTap={{ scale: 0.98 }}
                onClick={handleInstallService}
                disabled={actionLoading === 'install-service' || status.service_installed || !status.can_protect}
                className={`p-6 rounded-xl border-2 font-semibold transition-all duration-300 text-white disabled:opacity-50 disabled:cursor-not-allowed ${
                  status.service_installed
                    ? 'bg-green-500/20 border-green-500/30 text-green-400'
                    : 'bg-orange-600 hover:bg-orange-700 border-orange-500/20 hover:shadow-lg hover:shadow-orange-500/30'
                }`}
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-3">
                    <ServerIcon className="h-6 w-6" />
                    <span>{status.service_installed ? '✅ Service Installed' : 'Install as Service'}</span>
                  </div>
                  {actionLoading === 'install-service' && (
                    <ArrowPathIcon className="h-5 w-5 animate-spin" />
                  )}
                </div>
                {!status.can_protect && !status.service_installed && (
                  <p className="text-xs text-left mt-2 opacity-70">Requires elevated privileges</p>
                )}
              </motion.button>

            </div>
          </div>
        </motion.div>

        {/* Detected Threats */}
        {threats.length > 0 && (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: 0.8 }}
            className="bg-dark-card rounded-2xl shadow-xl overflow-hidden border border-dark-border"
          >
            <div className="px-8 py-6 border-b border-dark-border">
              <div className="flex items-center space-x-3">
                <ExclamationTriangleIcon className="h-6 w-6 text-red-500" />
                <h2 className="text-2xl font-bold text-dark-text">Detected Threats</h2>
              </div>
              <p className="text-sm text-dark-text/70 mt-1">
                <CountUp end={threats.length} duration={1} /> active threats detected
              </p>
            </div>

            <div className="p-8 space-y-4">
              {threats.map((threat, index) => (
                <motion.div
                  key={index}
                  initial={{ opacity: 0, x: -20 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ duration: 0.3, delay: index * 0.05 }}
                  whileHover={{ scale: 1.01, x: 4 }}
                  className="p-6 bg-red-500/10 rounded-xl border-2 border-red-500/20 hover:shadow-lg hover:shadow-red-500/20 transition-all duration-300"
                >
                  <div className="flex items-start space-x-4">
                    <div className="text-3xl">{getThreatTypeIcon(threat.type)}</div>
                    <div className="flex-1">
                      <div className="flex items-center space-x-3 mb-2">
                        <h3 className="text-lg font-bold text-dark-text">{threat.type.replace('_', ' ').toUpperCase()}</h3>
                        <span className={`px-3 py-1 rounded-lg text-xs font-bold border-2 ${getSeverityColor(threat.severity)}`}>
                          {threat.severity.toUpperCase()}
                        </span>
                      </div>
                      <p className="text-dark-text/80 mb-2">{threat.description}</p>
                      <div className="grid grid-cols-2 gap-4 text-sm text-dark-text/70">
                        <div>
                          <span className="font-semibold">Process:</span> {threat.process_name}
                        </div>
                        <div>
                          <span className="font-semibold">PID:</span> {threat.pid}
                        </div>
                      </div>
                    </div>
                  </div>
                </motion.div>
              ))}
            </div>
          </motion.div>
        )}

        {/* Running Processes */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5, delay: 0.9 }}
          className="bg-dark-card rounded-2xl shadow-xl overflow-hidden border border-dark-border"
        >
          <div className="px-8 py-6 border-b border-dark-border">
            <div className="flex items-center space-x-3">
              <CpuChipIcon className="h-6 w-6 text-purple-500" />
              <h2 className="text-2xl font-bold text-dark-text">Running Processes</h2>
            </div>
            <p className="text-sm text-dark-text/70 mt-1">
              <CountUp end={processes.length} duration={1} /> processes monitored
            </p>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className="bg-dark-bg">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-semibold text-dark-text/70 uppercase">PID</th>
                  <th className="px-6 py-3 text-left text-xs font-semibold text-dark-text/70 uppercase">Name</th>
                  <th className="px-6 py-3 text-left text-xs font-semibold text-dark-text/70 uppercase">User</th>
                  <th className="px-6 py-3 text-left text-xs font-semibold text-dark-text/70 uppercase">CPU %</th>
                  <th className="px-6 py-3 text-left text-xs font-semibold text-dark-text/70 uppercase">Memory</th>
                  <th className="px-6 py-3 text-left text-xs font-semibold text-dark-text/70 uppercase">Status</th>
                  <th className="px-6 py-3 text-left text-xs font-semibold text-dark-text/70 uppercase">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-dark-border">
                {processes.slice(0, 20).map((proc, index) => (
                  <motion.tr
                    key={proc.pid}
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    transition={{ duration: 0.2, delay: index * 0.02 }}
                    className={`hover:bg-dark-bg transition-colors ${
                      proc.suspicious ? 'bg-yellow-500/5' : ''
                    }`}
                  >
                    <td className="px-6 py-4 text-sm text-dark-text">{proc.pid}</td>
                    <td className="px-6 py-4 text-sm text-dark-text font-medium">{proc.name}</td>
                    <td className="px-6 py-4 text-sm text-dark-text/70">{proc.username}</td>
                    <td className="px-6 py-4 text-sm text-dark-text">{proc.cpu_percent.toFixed(1)}%</td>
                    <td className="px-6 py-4 text-sm text-dark-text">{proc.memory_mb.toFixed(1)} MB</td>
                    <td className="px-6 py-4">
                      {proc.suspicious ? (
                        <span className="px-2 py-1 rounded-full text-xs font-bold bg-yellow-500/20 text-yellow-400 border border-yellow-500/30">
                          ⚠️ SUSPICIOUS
                        </span>
                      ) : (
                        <span className="px-2 py-1 rounded-full text-xs font-bold bg-green-500/20 text-green-400 border border-green-500/30">
                          ✓ NORMAL
                        </span>
                      )}
                    </td>
                    <td className="px-6 py-4">
                      <motion.button
                        whileHover={{ scale: 1.05 }}
                        whileTap={{ scale: 0.95 }}
                        onClick={() => handleScanProcessMemory(proc.pid)}
                        disabled={scanningProcess === proc.pid}
                        className="px-3 py-1 bg-purple-600 hover:bg-purple-700 rounded-lg text-xs font-semibold transition-all disabled:opacity-50"
                      >
                        {scanningProcess === proc.pid ? (
                          <ArrowPathIcon className="h-4 w-4 animate-spin" />
                        ) : (
                          'Scan Memory'
                        )}
                      </motion.button>
                    </td>
                  </motion.tr>
                ))}
              </tbody>
            </table>
          </div>
        </motion.div>

        {/* Recommendations */}
        {status.recommendations && status.recommendations.length > 0 && (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: 1.0 }}
            className="bg-dark-card rounded-2xl shadow-xl overflow-hidden border border-dark-border"
          >
            <div className="px-8 py-6 border-b border-dark-border">
              <div className="flex items-center space-x-3">
                <LightBulbIcon className="h-6 w-6 text-yellow-500" />
                <h2 className="text-2xl font-bold text-dark-text">Security Recommendations</h2>
              </div>
              <p className="text-sm text-dark-text/70 mt-1">
                <CountUp end={status.recommendations.length} duration={1} /> recommendations to improve security
              </p>
            </div>

            <div className="p-8 space-y-3">
              {status.recommendations.map((rec, index) => (
                <motion.div
                  key={index}
                  initial={{ opacity: 0, x: -20 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ duration: 0.3, delay: index * 0.1 }}
                  whileHover={{ scale: 1.01, x: 4 }}
                  className="p-4 bg-yellow-500/10 rounded-xl border-2 border-yellow-500/20 hover:shadow-lg hover:shadow-yellow-500/20 transition-all duration-300"
                >
                  <div className="flex items-start space-x-3">
                    <div className="flex-shrink-0 mt-1">
                      <ExclamationTriangleIcon className="h-5 w-5 text-yellow-500" />
                    </div>
                    <p className="text-dark-text/80">{rec}</p>
                  </div>
                </motion.div>
              ))}
            </div>
          </motion.div>
        )}

      </div>
    </motion.div>
      </ProtectedRoute>
  );
}