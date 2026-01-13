

import { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import CountUp from 'react-countup';
import { 
  ArrowDownTrayIcon,
  ArrowUpTrayIcon,
  ClockIcon,
  DocumentArrowDownIcon,
  CheckCircleIcon,
  ExclamationCircleIcon,
  Cog6ToothIcon,
  CloudArrowDownIcon,
  CloudArrowUpIcon,
  ShieldCheckIcon
} from '@heroicons/react/24/outline';
import ProtectedRoute from '@/components/ProtectedRoute';

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
  
  return response;
};

interface ConfigBackup {
  filename: string;
  path: string;
  size_bytes: number;
  created_at: string;
}

interface ExportConfig {
  config_version: string;
  exported_at: string;
  cyberguardian_version: string;
  sections: {
    protection?: any;
    exclusions?: any[];
    scan_schedules?: any[];
    update_settings?: any;
  };
}

export default function ConfigurationPage() {
  const [backups, setBackups] = useState<ConfigBackup[]>([]);
  const [loading, setLoading] = useState(true);
  const [exporting, setExporting] = useState(false);
  const [importing, setImporting] = useState(false);
  const [lastExport, setLastExport] = useState<ExportConfig | null>(null);

const fetchBackups = async () => {
  try {
    const response = await fetchWithAuth('/api/configuration/backups');
    const data = await response.json();
    
    if (data.success && data.backups) {
      setBackups(data.backups);
    }
  } catch (error) {
    console.error('Error fetching backups:', error);
    // No mock data fallback
  }
};
const exportConfiguration = async () => {
  setExporting(true);
  try {
    const response = await fetchWithAuth('/api/configuration/export');
    const data = await response.json();
    
    if (data.success && data.config) {
      setLastExport(data.config);
      
      const blob = new Blob([JSON.stringify(data.config, null, 2)], { type: 'application/json' });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `cyberguardian_config_${new Date().toISOString().split('T')[0]}.json`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
      
      alert('Configuration exported successfully!');
    } else {
      alert('Failed to export configuration');
    }
  } catch (error) {
    console.error('Error exporting configuration:', error);
    alert('Error exporting configuration');
  } finally {
    setExporting(false);
  }
};

  const importConfiguration = async (file: File) => {
    setImporting(true);
    try {
      const text = await file.text();
      const config = JSON.parse(text);
      
      const validateResponse = await fetchWithAuth('/api/configuration/validate', {
  method: 'POST',
  body: JSON.stringify(config)
});
      
      const validateData = await validateResponse.json();
      
      if (!validateData.valid) {
        alert('Invalid configuration file');
        return;
      }
      
      const importResponse = await fetchWithAuth('/api/configuration/import', {
  method: 'POST',
  body: JSON.stringify(config)
});
      
      const importData = await importResponse.json();
      
      if (importData.success) {
        alert('Configuration imported successfully!');
        await fetchBackups();
      } else {
        alert('Configuration import failed: ' + (importData.message || 'Unknown error'));
      }
    } catch (error) {
      console.error('Error importing configuration:', error);
      alert('Error importing configuration');
    } finally {
      setImporting(false);
    }
  };

  const downloadBackup = async (filename: string) => {
  try {
    const response = await fetchWithAuth(`/api/configuration/backups/${filename}/download`);
    const blob = await response.blob();
      
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
    } catch (error) {
      console.error('Error downloading backup:', error);
      alert('Error downloading backup');
    }
  };

  const restoreBackup = async (filename: string) => {
    if (!confirm(`Are you sure you want to restore from ${filename}? Current configuration will be backed up.`)) {
      return;
    }
    
    try {
      const response = await fetchWithAuth(`/api/configuration/backups/${filename}/restore`, {
  method: 'POST'
});
      
      const data = await response.json();
      
      if (data.success) {
        alert('Configuration restored successfully!');
        await fetchBackups();
      } else {
        alert('Restore failed: ' + (data.message || 'Unknown error'));
      }
    } catch (error) {
      console.error('Error restoring backup:', error);
      alert('Error restoring backup');
    }
  };

  useEffect(() => {
    const loadData = async () => {
      setLoading(true);
      await fetchBackups();
      setLoading(false);
    };
    loadData();
  }, []);

  const formatBytes = (bytes: number) => {
    const kb = bytes / 1024;
    return `${kb.toFixed(2)} KB`;
  };

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleString();
  };

  // Loading skeleton
  if (loading) {
    return (
        <ProtectedRoute>
      <div className="min-h-screen bg-dark-bg p-8">
        <div className="max-w-7xl mx-auto animate-pulse space-y-8">
          <div className="h-10 w-64 bg-muted/30 rounded"></div>
          <div className="grid grid-cols-2 gap-6">
            {[...Array(2)].map((_, i) => (
              <div key={i} className="h-64 bg-muted/20 rounded-xl"></div>
            ))}
          </div>
          <div className="h-96 bg-muted/20 rounded-xl"></div>
        </div>
      </div>
      </ProtectedRoute>
    );
  }

  return (
    <ProtectedRoute>
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5 }}
      className="min-h-screen bg-dark-bg p-6"
    >
      <div className="max-w-7xl mx-auto">
        
        {/* Header */}
        <motion.div
          initial={{ opacity: 0, x: -20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ duration: 0.5, delay: 0.1 }}
          className="mb-8"
        >
          <div className="flex items-center gap-3 mb-2">
            <motion.div
              animate={{ rotate: [0, 360] }}
              transition={{ duration: 3, repeat: Infinity, ease: "linear" }}
            >
              <Cog6ToothIcon className="w-10 h-10 text-purple-400" />
            </motion.div>
            <h1 className="text-4xl font-bold">
              <span className="gradient-cyber">Configuration Management</span>
            </h1>
          </div>
          <p className="text-dark-text/70">Export, import, and manage system configuration backups</p>
        </motion.div>

        {/* Last Export Success Message */}
        <AnimatePresence>
          {lastExport && (
            <motion.div
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: 'auto' }}
              exit={{ opacity: 0, height: 0 }}
              className="mb-6"
            >
              <div className="bg-green-500/10 border border-green-500/20 rounded-xl p-4">
                <div className="flex items-start space-x-3">
                  <motion.div
                    animate={{ scale: [1, 1.2, 1] }}
                    transition={{ duration: 0.5 }}
                  >
                    <CheckCircleIcon className="h-6 w-6 text-green-400 flex-shrink-0 mt-0.5" />
                  </motion.div>
                  <div className="flex-1">
                    <h3 className="text-sm font-semibold text-green-400 mb-1">
                      Configuration Exported Successfully! 🎉
                    </h3>
                    <div className="text-xs text-green-400/80 space-y-1">
                      <p>Version: {lastExport.cyberguardian_version}</p>
                      <p>Exported: {formatDate(lastExport.exported_at)}</p>
                      <p>Config Version: {lastExport.config_version}</p>
                    </div>
                  </div>
                </div>
              </div>
            </motion.div>
          )}
        </AnimatePresence>

        {/* Export/Import Cards */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8">
          
          {/* Export Card */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.4, delay: 0.2 }}
            whileHover={{ scale: 1.02, y: -4 }}
            className="relative overflow-hidden bg-dark-card border-2 border-blue-500/20 rounded-2xl p-8 hover:shadow-2xl hover:shadow-blue-500/20 transition-all duration-300"
          >
            {/* Background Gradient */}
            <div className="absolute top-0 right-0 w-64 h-64 bg-blue-500/10 rounded-full blur-3xl"></div>
            
            <div className="relative z-10 text-center">
              <motion.div
                animate={{ y: [0, -10, 0] }}
                transition={{ duration: 2, repeat: Infinity, ease: "easeInOut" }}
                className="inline-block"
              >
                <div className="p-4 bg-gradient-to-br from-blue-500 to-cyan-500 rounded-2xl shadow-xl mb-4">
                  <CloudArrowDownIcon className="h-12 w-12 text-white" />
                </div>
              </motion.div>
              
              <h3 className="text-2xl font-bold text-blue-400 mb-2">Export Configuration</h3>
              <p className="text-sm text-dark-text/70 mb-6">
                Download current system configuration as JSON file
              </p>
              
              <motion.button
                whileHover={{ scale: 1.05 }}
                whileTap={{ scale: 0.95 }}
                onClick={exportConfiguration}
                disabled={exporting}
                className="w-full px-6 py-3 bg-gradient-to-r from-blue-600 to-cyan-600 text-white rounded-xl font-semibold hover:from-blue-700 hover:to-cyan-700 disabled:opacity-50 disabled:cursor-not-allowed transition-all duration-300 shadow-lg hover:shadow-xl hover:shadow-blue-500/30 flex items-center justify-center gap-2"
              >
                {exporting ? (
                  <>
                    <motion.div
                      animate={{ rotate: 360 }}
                      transition={{ duration: 1, repeat: Infinity, ease: "linear" }}
                    >
                      <ArrowDownTrayIcon className="h-5 w-5" />
                    </motion.div>
                    Exporting...
                  </>
                ) : (
                  <>
                    <ArrowDownTrayIcon className="h-5 w-5" />
                    Export Configuration
                  </>
                )}
              </motion.button>
            </div>
          </motion.div>

          {/* Import Card */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.4, delay: 0.3 }}
            whileHover={{ scale: 1.02, y: -4 }}
            className="relative overflow-hidden bg-dark-card border-2 border-green-500/20 rounded-2xl p-8 hover:shadow-2xl hover:shadow-green-500/20 transition-all duration-300"
          >
            {/* Background Gradient */}
            <div className="absolute top-0 right-0 w-64 h-64 bg-green-500/10 rounded-full blur-3xl"></div>
            
            <div className="relative z-10 text-center">
              <motion.div
                animate={{ y: [0, -10, 0] }}
                transition={{ duration: 2, repeat: Infinity, ease: "easeInOut", delay: 0.5 }}
                className="inline-block"
              >
                <div className="p-4 bg-gradient-to-br from-green-500 to-emerald-500 rounded-2xl shadow-xl mb-4">
                  <CloudArrowUpIcon className="h-12 w-12 text-white" />
                </div>
              </motion.div>
              
              <h3 className="text-2xl font-bold text-green-400 mb-2">Import Configuration</h3>
              <p className="text-sm text-dark-text/70 mb-6">
                Restore system configuration from JSON file
              </p>
              
              <label className="block">
                <input
                  type="file"
                  accept=".json"
                  onChange={(e) => {
                    const file = e.target.files?.[0];
                    if (file) importConfiguration(file);
                  }}
                  disabled={importing}
                  className="hidden"
                />
                <motion.span
                  whileHover={{ scale: 1.05 }}
                  whileTap={{ scale: 0.95 }}
                  className="w-full inline-flex items-center justify-center gap-2 px-6 py-3 bg-gradient-to-r from-green-600 to-emerald-600 text-white rounded-xl font-semibold hover:from-green-700 hover:to-emerald-700 disabled:opacity-50 transition-all duration-300 shadow-lg hover:shadow-xl hover:shadow-green-500/30 cursor-pointer"
                >
                  {importing ? (
                    <>
                      <motion.div
                        animate={{ rotate: 360 }}
                        transition={{ duration: 1, repeat: Infinity, ease: "linear" }}
                      >
                        <ArrowUpTrayIcon className="h-5 w-5" />
                      </motion.div>
                      Importing...
                    </>
                  ) : (
                    <>
                      <ArrowUpTrayIcon className="h-5 w-5" />
                      Import Configuration
                    </>
                  )}
                </motion.span>
              </label>
            </div>
          </motion.div>
        </div>

        {/* Backups Section */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.4, delay: 0.4 }}
          className="bg-dark-card border border-dark-border rounded-2xl shadow-xl overflow-hidden"
        >
          <div className="px-8 py-6 border-b border-dark-border">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <motion.div
                  animate={{ rotate: [0, 360] }}
                  transition={{ duration: 20, repeat: Infinity, ease: "linear" }}
                >
                  <ShieldCheckIcon className="h-6 w-6 text-purple-400" />
                </motion.div>
                <div>
                  <h2 className="text-2xl font-bold text-dark-text">Configuration Backups</h2>
                  <p className="text-sm text-dark-text/70">
                    <CountUp end={backups.length} duration={1} /> backup{backups.length !== 1 ? 's' : ''} available
                  </p>
                </div>
              </div>
              
              <motion.button
                whileHover={{ scale: 1.05 }}
                whileTap={{ scale: 0.95 }}
                onClick={fetchBackups}
                className="text-sm text-purple-400 hover:text-purple-300 font-semibold px-4 py-2 rounded-lg hover:bg-purple-500/10 transition-all duration-300"
              >
                Refresh
              </motion.button>
            </div>
          </div>

          <div className="p-8">
            <AnimatePresence mode="wait">
              {backups.length === 0 ? (
                <motion.div
                  key="no-backups"
                  initial={{ opacity: 0, scale: 0.95 }}
                  animate={{ opacity: 1, scale: 1 }}
                  exit={{ opacity: 0, scale: 0.95 }}
                  className="text-center py-16"
                >
                  <motion.div
                    animate={{ scale: [1, 1.1, 1], rotate: [0, 5, -5, 0] }}
                    transition={{ duration: 2, repeat: Infinity, repeatType: "reverse" }}
                    className="inline-block mb-4"
                  >
                    <DocumentArrowDownIcon className="h-16 w-16 text-dark-text/30" />
                  </motion.div>
                  <p className="text-lg text-dark-text/50 mb-1">No backups available</p>
                  <p className="text-sm text-dark-text/30">Backups are created automatically when importing configurations</p>
                </motion.div>
              ) : (
                <motion.div
                  key="backups"
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  className="space-y-3"
                >
                  {backups.map((backup, index) => (
                    <motion.div
                      key={backup.filename}
                      initial={{ opacity: 0, x: -20 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{ duration: 0.3, delay: index * 0.05 }}
                      whileHover={{ scale: 1.01, x: 4 }}
                      className="border border-dark-border rounded-xl p-5 hover:border-purple-500/50 transition-all duration-300 hover:shadow-lg hover:shadow-purple-500/10 bg-dark-bg"
                    >
                      <div className="flex items-center justify-between">
                        <div className="flex-1">
                          <div className="flex items-center space-x-3 mb-3">
                            <motion.div
                              whileHover={{ rotate: 360 }}
                              transition={{ duration: 0.5 }}
                            >
                              <ClockIcon className="h-5 w-5 text-purple-400" />
                            </motion.div>
                            <h3 className="font-bold text-dark-text">{backup.filename}</h3>
                          </div>
                          <div className="flex items-center gap-4 text-sm text-dark-text/70">
                            <span className="flex items-center gap-1">
                              Size: <span className="font-semibold text-cyan-400">{formatBytes(backup.size_bytes)}</span>
                            </span>
                            <span className="flex items-center gap-1">
                              Created: <span className="font-semibold text-blue-400">{formatDate(backup.created_at)}</span>
                            </span>
                          </div>
                        </div>
                        
                        <div className="flex items-center space-x-2">
                          <motion.button
                            whileHover={{ scale: 1.05 }}
                            whileTap={{ scale: 0.95 }}
                            onClick={() => downloadBackup(backup.filename)}
                            className="px-4 py-2 text-sm bg-dark-card border border-dark-border text-dark-text rounded-lg hover:border-cyan-500/50 hover:bg-cyan-500/10 transition-all duration-300"
                          >
                            Download
                          </motion.button>
                          <motion.button
                            whileHover={{ scale: 1.05 }}
                            whileTap={{ scale: 0.95 }}
                            onClick={() => restoreBackup(backup.filename)}
                            className="px-4 py-2 text-sm bg-gradient-to-r from-blue-600 to-purple-600 text-white rounded-lg hover:from-blue-700 hover:to-purple-700 transition-all duration-300 shadow-lg hover:shadow-xl hover:shadow-blue-500/30"
                          >
                            Restore
                          </motion.button>
                        </div>
                      </div>
                    </motion.div>
                  ))}
                </motion.div>
              )}
            </AnimatePresence>
          </div>
        </motion.div>

        {/* Info Section */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.4, delay: 0.5 }}
          whileHover={{ scale: 1.005 }}
          className="mt-6 bg-yellow-500/10 border border-yellow-500/20 rounded-xl p-5 hover:shadow-lg hover:shadow-yellow-500/10 transition-all duration-300"
        >
          <div className="flex items-start space-x-3">
            <motion.div
              animate={{ scale: [1, 1.1, 1] }}
              transition={{ duration: 2, repeat: Infinity }}
            >
              <ExclamationCircleIcon className="h-6 w-6 text-yellow-400 flex-shrink-0 mt-0.5" />
            </motion.div>
            <div className="flex-1">
              <h3 className="text-sm font-bold text-yellow-400 mb-2">Important Notes</h3>
              <ul className="text-xs text-yellow-400/80 space-y-1.5">
                <li className="flex items-start gap-2">
                  <span className="text-yellow-400 mt-0.5">•</span>
                  <span>Backups are created automatically before importing configurations</span>
                </li>
                <li className="flex items-start gap-2">
                  <span className="text-yellow-400 mt-0.5">•</span>
                  <span>Exported configurations include: protection settings, exclusions, scan schedules, and update settings</span>
                </li>
                <li className="flex items-start gap-2">
                  <span className="text-yellow-400 mt-0.5">•</span>
                  <span>Restoring a backup will override current configuration</span>
                </li>
                <li className="flex items-start gap-2">
                  <span className="text-yellow-400 mt-0.5">•</span>
                  <span>Keep exported configuration files secure as they contain system settings</span>
                </li>
              </ul>
            </div>
          </div>
        </motion.div>

      </div>
    </motion.div>
    </ProtectedRoute>
  );
}
