"use client";

import { useState, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import CountUp from "react-countup";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Alert, AlertDescription } from "@/components/ui/alert";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Input } from "@/components/ui/input";
import {
  AlertTriangle,
  Database,
  Search,
  Trash2,
  RotateCcw,
  Shield,
  RefreshCw,
  Info,
  History,
  ChevronDown,
  ChevronRight,
} from "lucide-react";
import { remediationApi } from "@/lib/api";
import { toast } from "sonner";
import ProtectedRoute from '@/components/ProtectedRoute';

interface RegistryEntry {
  id: string;
  hive: string;
  key_path: string;
  value_name: string;
  value_data: string;
  value_type: string;
  risk_score: number;
  indicators: string[];
  scanned_at: string;
}

interface RegistryStats {
  total_suspicious: number;
  critical_risk: number;
  high_risk: number;
  medium_risk: number;
  low_risk: number;
  by_hive: Record<string, number>;
}

interface BackupFile {
  filename: string;
  filepath: string;
  hive: string;
  key_path: string;
  value_name: string;
  backed_up_at: string;
}

export default function RegistryCleanupPage() {
  const [scanning, setScanning] = useState(false);
  const [entries, setEntries] = useState<RegistryEntry[]>([]);
  const [stats, setStats] = useState<RegistryStats | null>(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedSeverity, setSelectedSeverity] = useState<string>("all");
  const [expandedEntry, setExpandedEntry] = useState<string | null>(null);
  const [backups, setBackups] = useState<BackupFile[]>([]);
  const [showBackups, setShowBackups] = useState(false);
  const [removing, setRemoving] = useState<string | null>(null);

  useEffect(() => {
    handleScan();
    loadBackups();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const handleScan = async () => {
    setScanning(true);
    try {
      const response = await remediationApi.scanRegistry();

      if (response.success && response.data) {
        setEntries(response.data.entries);
        setStats(response.data.statistics);

        toast("Scan Complete", {
          description: `Found ${response.data.entries.length} suspicious registry entries`,
        });
      } else {
        toast.error("Scan Failed", {
          description: response.error || "Failed to scan registry",
        });
      }
    } catch (error) {
      toast.error("Error", {
        description: "An error occurred while scanning",
      });
    } finally {
      setScanning(false);
    }
  };

  const loadBackups = async () => {
    try {
      const response = await remediationApi.listRegistryBackups();
      if (response.success && response.data) {
        setBackups(response.data.backups);
      }
    } catch (error) {
      console.error("Failed to load backups:", error);
    }
  };

  const handleRemove = async (entry: RegistryEntry) => {
    if (
      !confirm(
        `Are you sure you want to remove this registry entry?\n\n${entry.hive}\\${entry.key_path}\\${entry.value_name}\n\nA backup will be created automatically.`
      )
    ) {
      return;
    }

    setRemoving(entry.id);
    try {
      const response = await remediationApi.removeRegistryEntry({
        hive: entry.hive,
        key_path: entry.key_path,
        value_name: entry.value_name,
      });

      if (response.success && response.data?.success) {
        toast("Entry Removed", {
          description: `Registry entry removed successfully. Backup: ${response.data.backup_file}`,
        });
        await handleScan();
        await loadBackups();
      } else {
        toast.error("Removal Failed", {
          description:
            response.data?.message || response.error || "Failed to remove entry",
        });
      }
    } catch (error) {
      toast.error("Error", {
        description: "An error occurred during removal",
      });
    } finally {
      setRemoving(null);
    }
  };

  const handleRestore = async (backup: BackupFile) => {
    if (
      !confirm(
        `Restore this registry entry?\n\n${backup.hive}\\${backup.key_path}\\${backup.value_name}`
      )
    ) {
      return;
    }

    try {
      const response = await remediationApi.restoreRegistryEntry({
        backup_file: backup.filepath,
      });

      if (response.success && response.data?.success) {
        toast("Entry Restored", {
          description: response.data.message,
        });
        await handleScan();
        await loadBackups();
      } else {
        toast.error("Restore Failed", {
          description:
            response.data?.message || response.error || "Failed to restore entry",
        });
      }
    } catch (error) {
      toast.error("Error", {
        description: "An error occurred during restore",
      });
    }
  };

  const getRiskBadge = (score: number) => {
    if (score >= 80) {
      return (
        <motion.div whileHover={{ scale: 1.05 }} transition={{ type: "spring", stiffness: 400 }}>
          <Badge className="bg-red-500/20 text-red-400 border border-red-500/30 transition-all duration-300">
            Critical ({score})
          </Badge>
        </motion.div>
      );
    } else if (score >= 60) {
      return (
        <motion.div whileHover={{ scale: 1.05 }} transition={{ type: "spring", stiffness: 400 }}>
          <Badge className="bg-orange-500/20 text-orange-400 border border-orange-500/30 transition-all duration-300">
            High ({score})
          </Badge>
        </motion.div>
      );
    } else if (score >= 40) {
      return (
        <motion.div whileHover={{ scale: 1.05 }} transition={{ type: "spring", stiffness: 400 }}>
          <Badge className="bg-yellow-500/20 text-yellow-400 border border-yellow-500/30 transition-all duration-300">
            Medium ({score})
          </Badge>
        </motion.div>
      );
    } else {
      return (
        <motion.div whileHover={{ scale: 1.05 }} transition={{ type: "spring", stiffness: 400 }}>
          <Badge className="bg-blue-500/20 text-blue-400 border border-blue-500/30 transition-all duration-300">
            Low ({score})
          </Badge>
        </motion.div>
      );
    }
  };

  const filteredEntries = entries.filter((entry) => {
    const q = searchQuery.toLowerCase();

    const matchesSearch =
      entry.value_name.toLowerCase().includes(q) ||
      entry.value_data.toLowerCase().includes(q) ||
      entry.key_path.toLowerCase().includes(q);

    const matchesSeverity =
      selectedSeverity === "all" ||
      (selectedSeverity === "critical" && entry.risk_score >= 80) ||
      (selectedSeverity === "high" &&
        entry.risk_score >= 60 &&
        entry.risk_score < 80) ||
      (selectedSeverity === "medium" &&
        entry.risk_score >= 40 &&
        entry.risk_score < 60) ||
      (selectedSeverity === "low" && entry.risk_score < 40);

    return matchesSearch && matchesSeverity;
  });

  return (
    <ProtectedRoute>
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5 }}
      className="container mx-auto p-6 space-y-6"
    >
      {/* Header */}
      <motion.div
        initial={{ opacity: 0, x: -20 }}
        animate={{ opacity: 1, x: 0 }}
        transition={{ duration: 0.5, delay: 0.1 }}
        className="flex items-center justify-between"
      >
        <div>
          <h1 className="text-3xl font-bold flex items-center gap-3">
            <motion.div
              animate={{ rotate: [0, 360] }}
              transition={{ duration: 2, repeat: Infinity, ease: "linear", repeatDelay: 3 }}
            >
              <Database className="h-8 w-8 text-blue-500" />
            </motion.div>
            Registry Cleanup
          </h1>
          <p className="text-muted-foreground mt-2">
            Scan and remove malicious Windows registry entries
          </p>
        </div>
        <motion.div
          initial={{ opacity: 0, scale: 0.9 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ duration: 0.3, delay: 0.2 }}
          className="flex gap-2"
        >
          <motion.div whileHover={{ scale: 1.02 }} whileTap={{ scale: 0.98 }}>
            <Button variant="outline" onClick={() => setShowBackups(!showBackups)}>
              <History className="mr-2 h-4 w-4" />
              Backups ({backups.length})
            </Button>
          </motion.div>
          <motion.div whileHover={{ scale: 1.02 }} whileTap={{ scale: 0.98 }}>
            <Button onClick={handleScan} disabled={scanning}>
              {scanning ? (
                <>
                  <RefreshCw className="mr-2 h-4 w-4 animate-spin" />
                  Scanning...
                </>
              ) : (
                <>
                  <Search className="mr-2 h-4 w-4" />
                  Scan Registry
                </>
              )}
            </Button>
          </motion.div>
        </motion.div>
      </motion.div>

      {/* Statistics */}
      {stats && (
        <div className="grid gap-4 md:grid-cols-5">
          {[
            { label: "Total", value: stats.total_suspicious, icon: Database, color: "gray", severity: "all" },
            { label: "Critical", value: stats.critical_risk, icon: AlertTriangle, color: "red", severity: "critical" },
            { label: "High", value: stats.high_risk, icon: AlertTriangle, color: "orange", severity: "high" },
            { label: "Medium", value: stats.medium_risk, icon: AlertTriangle, color: "yellow", severity: "medium" },
            { label: "Low", value: stats.low_risk, icon: Info, color: "blue", severity: "low" },
          ].map((stat, index) => {
            const Icon = stat.icon;
            return (
              <motion.div
                key={stat.label}
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.4, delay: 0.1 + index * 0.1 }}
                whileHover={{ scale: 1.02, y: -4 }}
              >
                <Card
                  className={`cursor-pointer hover:border-${stat.color}-500/50 transition-all duration-300 hover:shadow-xl hover:shadow-${stat.color}-500/20 ${
                    selectedSeverity === stat.severity ? `border-${stat.color}-500/50 shadow-lg shadow-${stat.color}-500/20` : ""
                  }`}
                  onClick={() => setSelectedSeverity(stat.severity)}
                >
                  <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                    <CardTitle className="text-sm font-medium">{stat.label}</CardTitle>
                    <motion.div
                      whileHover={{ rotate: 360 }}
                      transition={{ duration: 0.5 }}
                    >
                      <Icon className={`h-4 w-4 text-${stat.color}-500`} />
                    </motion.div>
                  </CardHeader>
                  <CardContent>
                    <div className={`text-2xl font-bold text-${stat.color}-500`}>
                      <CountUp end={stat.value} duration={2} />
                    </div>
                  </CardContent>
                </Card>
              </motion.div>
            );
          })}
        </div>
      )}

      {/* Backups Panel */}
      <AnimatePresence>
        {showBackups && (
          <motion.div
            initial={{ opacity: 0, height: 0, y: -20 }}
            animate={{ opacity: 1, height: "auto", y: 0 }}
            exit={{ opacity: 0, height: 0, y: -20 }}
            transition={{ duration: 0.4 }}
          >
            <Card className="hover:shadow-lg transition-shadow duration-300">
              <CardHeader>
                <CardTitle>Registry Backups</CardTitle>
                <CardDescription>
                  Restore previously removed registry entries
                </CardDescription>
              </CardHeader>
              <CardContent>
                {backups.length === 0 ? (
                  <p className="text-sm text-muted-foreground">No backups available</p>
                ) : (
                  <div className="space-y-2">
                    {backups.map((backup, index) => (
                      <motion.div
                        key={backup.filename}
                        initial={{ opacity: 0, x: -20 }}
                        animate={{ opacity: 1, x: 0 }}
                        transition={{ duration: 0.3, delay: index * 0.05 }}
                        whileHover={{ scale: 1.01, x: 4 }}
                        className="flex items-center justify-between p-3 border rounded-lg hover:bg-accent/50 transition-all duration-300"
                      >
                        <div className="flex-1">
                          <p className="text-sm font-medium">{backup.value_name}</p>
                          <p className="text-xs text-muted-foreground">
                            {backup.hive}\{backup.key_path}
                          </p>
                          <p className="text-xs text-muted-foreground">
                            {new Date(backup.backed_up_at).toLocaleString()}
                          </p>
                        </div>
                        <motion.div whileHover={{ scale: 1.05 }} whileTap={{ scale: 0.95 }}>
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() => handleRestore(backup)}
                          >
                            <RotateCcw className="mr-2 h-4 w-4" />
                            Restore
                          </Button>
                        </motion.div>
                      </motion.div>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Search and Filters */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4, delay: 0.6 }}
        className="flex gap-4"
      >
        <div className="flex-1">
          <Input
            placeholder="Search by name, value, or path..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full transition-all duration-300 focus:shadow-lg focus:shadow-primary/10"
          />
        </div>
        <motion.div whileHover={{ scale: 1.05 }} whileTap={{ scale: 0.95 }}>
          <Badge
            variant={selectedSeverity === "all" ? "default" : "outline"}
            className="cursor-pointer px-4 transition-all duration-300"
            onClick={() => setSelectedSeverity("all")}
          >
            All
          </Badge>
        </motion.div>
      </motion.div>

      {/* Entries Table */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4, delay: 0.7 }}
      >
        <Card className="hover:shadow-xl transition-shadow duration-300">
          <CardHeader>
            <CardTitle>Suspicious Registry Entries</CardTitle>
            <CardDescription>
              Found <CountUp end={filteredEntries.length} duration={1} /> entries matching your criteria
            </CardDescription>
          </CardHeader>
          <CardContent>
            {filteredEntries.length === 0 ? (
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
                  <Shield className="mx-auto h-16 w-16 text-green-500/50 mb-4" />
                </motion.div>
                <p className="text-lg font-medium">No suspicious entries found</p>
                <p className="text-sm text-muted-foreground">
                  {entries.length === 0
                    ? "Click 'Scan Registry' to start scanning"
                    : "Try adjusting your filters"}
                </p>
              </motion.div>
            ) : (
              <div className="space-y-2">
                {filteredEntries.map((entry, index) => (
                  <motion.div
                    key={entry.id}
                    initial={{ opacity: 0, x: -20 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ duration: 0.3, delay: index * 0.05 }}
                    whileHover={{ scale: 1.01, x: 4 }}
                    className="border rounded-lg p-4 space-y-2 hover:bg-accent/5 transition-all duration-300 hover:shadow-md"
                  >
                    <div className="flex items-start justify-between">
                      <div className="flex-1">
                        <div className="flex items-center gap-2 mb-2">
                          <motion.button
                            whileHover={{ scale: 1.2 }}
                            whileTap={{ scale: 0.9 }}
                            onClick={() =>
                              setExpandedEntry(
                                expandedEntry === entry.id ? null : entry.id
                              )
                            }
                          >
                            <motion.div
                              animate={{ rotate: expandedEntry === entry.id ? 0 : -90 }}
                              transition={{ duration: 0.2 }}
                            >
                              <ChevronDown className="h-4 w-4" />
                            </motion.div>
                          </motion.button>
                          <p className="font-medium">{entry.value_name}</p>
                          {getRiskBadge(entry.risk_score)}
                        </div>
                        <p className="text-xs text-muted-foreground ml-6">
                          {entry.hive}\{entry.key_path}
                        </p>
                        <AnimatePresence>
                          {expandedEntry === entry.id && (
                            <motion.div
                              initial={{ opacity: 0, height: 0 }}
                              animate={{ opacity: 1, height: "auto" }}
                              exit={{ opacity: 0, height: 0 }}
                              transition={{ duration: 0.3 }}
                              className="mt-4 ml-6 space-y-2 border-l-2 border-primary/20 pl-4"
                            >
                              <div>
                                <p className="text-xs font-medium">Value Data:</p>
                                <p className="text-xs text-muted-foreground break-all">
                                  {entry.value_data}
                                </p>
                              </div>
                              <div>
                                <p className="text-xs font-medium">Type:</p>
                                <p className="text-xs text-muted-foreground">
                                  {entry.value_type}
                                </p>
                              </div>
                              <div>
                                <p className="text-xs font-medium">Indicators:</p>
                                <div className="flex flex-wrap gap-1 mt-1">
                                  {entry.indicators.map((indicator, idx) => (
                                    <motion.div
                                      key={idx}
                                      initial={{ opacity: 0, scale: 0.8 }}
                                      animate={{ opacity: 1, scale: 1 }}
                                      transition={{ duration: 0.2, delay: idx * 0.05 }}
                                      whileHover={{ scale: 1.05 }}
                                    >
                                      <Badge
                                        variant="outline"
                                        className="text-xs transition-all duration-300"
                                      >
                                        {indicator}
                                      </Badge>
                                    </motion.div>
                                  ))}
                                </div>
                              </div>
                            </motion.div>
                          )}
                        </AnimatePresence>
                      </div>
                      <motion.div whileHover={{ scale: 1.05 }} whileTap={{ scale: 0.95 }}>
                        <Button
                          size="sm"
                          variant="destructive"
                          onClick={() => handleRemove(entry)}
                          disabled={removing === entry.id}
                          className="transition-all duration-300"
                        >
                          {removing === entry.id ? (
                            <RefreshCw className="h-4 w-4 animate-spin" />
                          ) : (
                            <>
                              <Trash2 className="mr-2 h-4 w-4" />
                              Remove
                            </>
                          )}
                        </Button>
                      </motion.div>
                    </div>
                  </motion.div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      </motion.div>

      {/* Warning */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4, delay: 0.8 }}
        whileHover={{ scale: 1.01 }}
      >
        <Alert className="border-yellow-500/50 bg-yellow-500/10 hover:shadow-lg hover:shadow-yellow-500/20 transition-all duration-300">
          <motion.div
            animate={{ rotate: [0, 10, -10, 0] }}
            transition={{ duration: 0.5, repeat: Infinity, repeatDelay: 2 }}
          >
            <AlertTriangle className="h-4 w-4 text-yellow-500" />
          </motion.div>
          <AlertDescription>
            <strong>Warning:</strong> Removing registry entries can affect system
            stability. All entries are automatically backed up before removal and can
            be restored if needed.
          </AlertDescription>
        </Alert>
      </motion.div>
    </motion.div>
      </ProtectedRoute>
  );
}