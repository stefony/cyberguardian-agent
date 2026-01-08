"use client";

import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import CountUp from "react-countup";
import {
  Shield,
  Trash2,
  RotateCcw,
  AlertTriangle,
  FileWarning,
  HardDrive,
  Clock,
  RefreshCw,
  Search,
} from "lucide-react";
import { quarantineApi } from "@/lib/api";
import AutoPurgeSettings from "@/components/AutoPurgeSettings";
import ProtectedRoute from '@/components/ProtectedRoute';

export default function QuarantinePage() {
  const [files, setFiles] = useState<any[]>([]);
  const [stats, setStats] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [searchTerm, setSearchTerm] = useState("");

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    setLoading(true);
    await Promise.all([loadFiles(), loadStats()]);
    setLoading(false);
  };

  const loadFiles = async () => {
    try {
      const res = await quarantineApi.getFiles();
      if (res.success && res.data) {
        setFiles(Array.isArray(res.data) ? res.data : []);
      } else {
        setFiles([]);
      }
    } catch (err) {
      console.error("Error loading files:", err);
      setFiles([]);
    }
  };

  const loadStats = async () => {
    try {
      const res = await quarantineApi.getStats();
      if (res.success && res.data) {
        setStats(res.data);
      }
    } catch (err) {
      console.error("Error loading stats:", err);
    }
  };

  const refresh = async () => {
    setRefreshing(true);
    await loadData();
    setRefreshing(false);
  };

  const handleRestore = async (id: string, name: string) => {
    if (!confirm(`Restore "${name}" to original location?`)) return;

    try {
      const res = await quarantineApi.restoreFile(id);
      if (res.success) {
        alert("File restored successfully!");
        await loadData();
      } else {
        alert(`Failed to restore file: ${res.error || "Unknown error"}`);
      }
    } catch (err) {
      console.error("Error restoring file:", err);
      alert("Error restoring file");
    }
  };

  const handleDelete = async (id: string, name: string) => {
    if (!confirm(`Permanently delete "${name}"? This cannot be undone!`)) return;

    try {
      const res = await quarantineApi.deleteFile(id);
      if (res.success) {
        alert("File permanently deleted");
        await loadData();
      } else {
        alert(`Failed to delete file: ${res.error || "Unknown error"}`);
      }
    } catch (err) {
      console.error("Error deleting file:", err);
      alert("Error deleting file");
    }
  };

  const getThreatColor = (level: string) => {
    switch (level?.toLowerCase()) {
      case "critical": return "text-red-500";
      case "high": return "text-orange-500";
      case "medium": return "text-yellow-500";
      case "low": return "text-green-500";
      default: return "text-gray-500";
    }
  };

  const getThreatBg = (level: string) => {
    switch (level?.toLowerCase()) {
      case "critical": return "bg-red-500/10 border-red-500/30";
      case "high": return "bg-orange-500/10 border-orange-500/30";
      case "medium": return "bg-yellow-500/10 border-yellow-500/30";
      case "low": return "bg-green-500/10 border-green-500/30";
      default: return "bg-gray-500/10 border-gray-500/30";
    }
  };

  const formatBytes = (bytes: number) => {
    if (bytes === 0) return "0 B";
    const k = 1024;
    const sizes = ["B", "KB", "MB", "GB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + " " + sizes[i];
  };

  const filteredFiles = files.filter((file) =>
    file.original_name?.toLowerCase().includes(searchTerm.toLowerCase()) ||
    file.original_path?.toLowerCase().includes(searchTerm.toLowerCase())
  );

  // Loading Skeletons
  if (loading) {
    return (
      <ProtectedRoute>
      <main className="pb-12">
        <div className="page-container page-hero pt-12 md:pt-16">
          <div className="animate-pulse space-y-8">
            {/* Hero Skeleton */}
            <div className="flex items-center justify-between">
              <div className="space-y-3">
                <div className="h-10 w-64 bg-muted/30 rounded-lg"></div>
                <div className="h-4 w-48 bg-muted/20 rounded"></div>
              </div>
              <div className="h-10 w-32 bg-muted/30 rounded-lg"></div>
            </div>

            {/* Stats Skeleton */}
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
              {[...Array(4)].map((_, i) => (
                <div key={i} className="card-premium p-6">
                  <div className="h-4 w-24 bg-muted/20 rounded mb-4"></div>
                  <div className="h-8 w-16 bg-muted/30 rounded"></div>
                </div>
              ))}
            </div>

            {/* Content Skeleton */}
            <div className="card-premium p-6">
              <div className="h-6 w-48 bg-muted/30 rounded mb-4"></div>
              <div className="space-y-3">
                {[...Array(3)].map((_, i) => (
                  <div key={i} className="h-16 bg-muted/10 rounded"></div>
                ))}
              </div>
            </div>
          </div>
        </div>
      </main>
      </ProtectedRoute>
    );
  }

  return (
    <ProtectedRoute>
    <motion.main
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5 }}
      className="pb-12"
    >
      {/* Hero */}
      <div className="page-container page-hero pt-12 md:pt-16">
        <div className="flex items-center justify-between">
          <motion.div
            initial={{ opacity: 0, x: -20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ duration: 0.5, delay: 0.1 }}
          >
            <h1 className="heading-accent gradient-cyber text-3xl md:text-4xl font-bold tracking-tight">
              Quarantine Vault
            </h1>
            <p className="mt-2 text-muted-foreground">
              Isolated threats and suspicious files
            </p>
          </motion.div>

          <motion.button
            initial={{ opacity: 0, scale: 0.9 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ duration: 0.3, delay: 0.2 }}
            whileHover={{ scale: 1.05 }}
            whileTap={{ scale: 0.95 }}
            onClick={refresh}
            disabled={refreshing}
            className="btn btn-primary hover:shadow-lg hover:shadow-primary/20 transition-all duration-300"
          >
            <RefreshCw className={`h-4 w-4 ${refreshing ? "animate-spin" : ""}`} />
            Refresh
          </motion.button>
        </div>
      </div>

      {/* Statistics Cards */}
      {stats && (
        <div className="section">
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            {/* Total Files */}
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.4, delay: 0.1 }}
              whileHover={{ scale: 1.02, y: -4 }}
              className="card-premium p-6 hover:shadow-2xl hover:shadow-purple-500/20 transition-all duration-300"
            >
              <div className="flex items-center gap-3 mb-2">
                <FileWarning className="h-5 w-5 text-purple-400" />
                <span className="text-sm text-muted-foreground">Total Files</span>
              </div>
              <div className="text-3xl font-bold text-purple-400">
                <CountUp end={stats.total_files || 0} duration={2} separator="," />
              </div>
            </motion.div>

            {/* Total Size */}
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.4, delay: 0.2 }}
              whileHover={{ scale: 1.02, y: -4 }}
              className="card-premium p-6 hover:shadow-2xl hover:shadow-blue-500/20 transition-all duration-300"
            >
              <div className="flex items-center gap-3 mb-2">
                <HardDrive className="h-5 w-5 text-blue-400" />
                <span className="text-sm text-muted-foreground">Total Size</span>
              </div>
              <div className="text-3xl font-bold text-blue-400">
                {formatBytes(stats.total_size_bytes || 0)}
              </div>
            </motion.div>

            {/* Critical Threats */}
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.4, delay: 0.3 }}
              whileHover={{ scale: 1.02, y: -4 }}
              className="card-premium p-6 hover:shadow-2xl hover:shadow-red-500/20 transition-all duration-300"
            >
              <div className="flex items-center gap-3 mb-2">
                <AlertTriangle className="h-5 w-5 text-red-400" />
                <span className="text-sm text-muted-foreground">Critical</span>
              </div>
              <div className="text-3xl font-bold text-red-400">
                <CountUp end={stats.threat_counts?.critical || 0} duration={2} />
              </div>
            </motion.div>

            {/* High Threats */}
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.4, delay: 0.4 }}
              whileHover={{ scale: 1.02, y: -4 }}
              className="card-premium p-6 hover:shadow-2xl hover:shadow-orange-500/20 transition-all duration-300"
            >
              <div className="flex items-center gap-3 mb-2">
                <Shield className="h-5 w-5 text-orange-400" />
                <span className="text-sm text-muted-foreground">High Risk</span>
              </div>
              <div className="text-3xl font-bold text-orange-400">
                <CountUp end={stats.threat_counts?.high || 0} duration={2} />
              </div>
            </motion.div>
          </div>
        </div>
      )}

      {/* Auto-Purge Settings */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5, delay: 0.5 }}
        className="section"
      >
        <AutoPurgeSettings onSettingsChanged={loadData} />
      </motion.div>

      {/* Search */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5, delay: 0.6 }}
        className="section"
      >
        <div className="card-premium p-4 hover:shadow-lg transition-all duration-300">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-5 w-5 text-muted-foreground pointer-events-none" />
            <input
              type="text"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Search by filename or path..."
              className="w-full pl-10 pr-4 py-3 rounded-lg bg-card border-2 border-border text-foreground focus:border-purple-500 focus:outline-none transition-all duration-300 focus:shadow-lg focus:shadow-purple-500/10"
              autoComplete="off"
            />
          </div>
        </div>
      </motion.div>

      {/* Files Table */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5, delay: 0.7 }}
        className="section"
      >
        <div className="card-premium p-6">
          <h2 className="text-xl font-bold mb-4 flex items-center gap-2">
            <Shield className="h-5 w-5 text-purple-500" />
            Quarantined Files ({filteredFiles.length})
          </h2>

          {filteredFiles.length === 0 ? (
            <motion.div
              initial={{ opacity: 0, scale: 0.9 }}
              animate={{ opacity: 1, scale: 1 }}
              transition={{ duration: 0.5 }}
              className="text-center py-12"
            >
              <motion.div
                animate={{
                  scale: [1, 1.1, 1],
                  rotate: [0, 5, -5, 0],
                }}
                transition={{
                  duration: 2,
                  repeat: Infinity,
                  repeatType: "reverse",
                }}
              >
                <Shield className="h-16 w-16 text-green-500/50 mx-auto mb-4" />
              </motion.div>
              <p className="text-lg font-medium text-muted-foreground">
                {searchTerm
                  ? "No files match your search"
                  : "No quarantined files. Your system is clean!"}
              </p>
            </motion.div>
          ) : (
            <div className="overflow-x-auto">
              <table className="table w-full">
                <thead>
                  <tr>
                    <th>File Name</th>
                    <th>Original Path</th>
                    <th>Size</th>
                    <th>Threat Score</th>
                    <th>Threat Level</th>
                    <th>Quarantined</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredFiles.map((file, index) => (
                    <motion.tr
                      key={file.id}
                      initial={{ opacity: 0, x: -20 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{ duration: 0.3, delay: index * 0.05 }}
                      className="hover:bg-accent/5 transition-colors duration-200"
                    >
                      <td className="font-medium">
                        <div className="flex items-center gap-2">
                          <FileWarning className="h-4 w-4 text-red-400" />
                          {file.original_name}
                        </div>
                      </td>
                      <td className="font-mono text-xs truncate max-w-xs" title={file.original_path}>
                        {file.original_path}
                      </td>
                      <td className="text-sm">{formatBytes(file.file_size || 0)}</td>
                      <td className={`font-bold ${getThreatColor(file.threat_level)}`}>
                        <CountUp end={Math.round(file.threat_score || 0)} duration={1.5} />
                      </td>
                      <td>
                        <motion.span
                          whileHover={{ scale: 1.05 }}
                          className={`badge border-2 ${getThreatBg(file.threat_level)} transition-all duration-300`}
                        >
                          <span className={getThreatColor(file.threat_level)}>
                            {file.threat_level?.toUpperCase() || "UNKNOWN"}
                          </span>
                        </motion.span>
                      </td>
                      <td className="text-sm">
                        <div className="flex items-center gap-1 text-muted-foreground">
                          <Clock className="h-3 w-3" />
                          {new Date(file.quarantined_at).toLocaleDateString()}
                        </div>
                      </td>
                      <td>
                        <div className="flex gap-2">
                          <motion.button
                            whileHover={{ scale: 1.15 }}
                            whileTap={{ scale: 0.95 }}
                            onClick={() => handleRestore(file.id, file.original_name)}
                            className="p-2 rounded-lg hover:bg-green-500/10 transition-all duration-300 group"
                            title="Restore file"
                          >
                            <RotateCcw className="h-4 w-4 text-green-500 group-hover:text-green-400 transition-colors" />
                          </motion.button>
                          <motion.button
                            whileHover={{ scale: 1.15 }}
                            whileTap={{ scale: 0.95 }}
                            onClick={() => handleDelete(file.id, file.original_name)}
                            className="p-2 rounded-lg hover:bg-red-500/10 transition-all duration-300 group"
                            title="Delete permanently"
                          >
                            <Trash2 className="h-4 w-4 text-red-500 group-hover:text-red-400 transition-colors" />
                          </motion.button>
                        </div>
                      </td>
                    </motion.tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </motion.div>
    </motion.main>
    </ProtectedRoute>
  );
}