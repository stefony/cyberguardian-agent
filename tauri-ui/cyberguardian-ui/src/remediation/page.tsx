"use client";

import { motion } from "framer-motion";
import CountUp from "react-countup";
import { useState, useEffect } from "react";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { useNavigate } from "react-router-dom";
import {
  Shield,
  FileSearch,
  Wrench,
  Settings,
  Clock,
  Database,
  AlertTriangle,
  CheckCircle2,
  Activity,
  Loader2,
} from "lucide-react";
import ProtectedRoute from "@/components/ProtectedRoute";
import { toast } from "sonner";

export default function RemediationPage() {
  const navigate = useNavigate();
  const [loading, setLoading] = useState(true);
  const [statsData, setStatsData] = useState({
    registry: 0,
    services: 0,
    tasks: 0,
    total: 0,
  });

  useEffect(() => {
    loadStatistics();
  }, []);

  const loadStatistics = async () => {
    setLoading(true);
    try {
      // Check if running in Tauri Desktop Agent environment
      if (!(window as any).__TAURI__) {
        toast.error("Desktop Agent Required", {
          description: "This feature requires the CyberGuardian Desktop Agent. Run with: npm run tauri dev",
        });
        setLoading(false);
        return;
      }

      const invoke = (window as any).__TAURI__.core.invoke;

      // Fetch statistics from all Desktop Agent modules in parallel
      const [registryResult, servicesResult, tasksResult] = await Promise.all([
        invoke('scan_windows_registry'),
        invoke('scan_windows_services'),
        invoke('scan_windows_tasks'),
      ]);

      // Extract statistics from Desktop Agent responses
      const registryCount = registryResult?.statistics?.total_suspicious || 0;
      const servicesCount = servicesResult?.statistics?.total_suspicious || 0;
      const tasksCount = tasksResult?.statistics?.total_suspicious || 0;

      setStatsData({
        registry: registryCount,
        services: servicesCount,
        tasks: tasksCount,
        total: registryCount + servicesCount + tasksCount,
      });

      // Show success notification
      toast.success("Statistics Updated", {
        description: `Found ${registryCount + servicesCount + tasksCount} suspicious items across all modules`,
      });
    } catch (error) {
      console.error("Failed to load statistics:", error);
      toast.error("Scan Failed", {
        description: error instanceof Error ? error.message : "Could not scan system for suspicious items",
      });
    } finally {
      setLoading(false);
    }
  };

  const remediationModules = [
    {
      id: "registry",
      title: "Registry Cleanup",
      description: "Scan and remove malicious Windows registry entries",
      icon: Database,
      status: "available",
      color: "text-blue-500",
      bgColor: "bg-blue-500/10",
      borderColor: "border-blue-500/30",
      shadowColor: "shadow-blue-500/20",
      path: "/remediation/registry",
      features: [
        "Scan autorun registry keys",
        "Detect suspicious entries",
        "Automatic backup before removal",
        "One-click restore",
      ],
    },
    {
      id: "services",
      title: "Services Cleanup",
      description: "Identify and remove malicious Windows services",
      icon: Settings,
      status: "available",
      color: "text-purple-500",
      bgColor: "bg-purple-500/10",
      borderColor: "border-purple-500/30",
      shadowColor: "shadow-purple-500/20",
      path: "/remediation/services",
      features: [
        "Enumerate all services",
        "Detect suspicious services",
        "Stop and delete services",
        "Service backup",
      ],
    },
    {
      id: "tasks",
      title: "Tasks Cleanup",
      description: "Scan and clean malicious scheduled tasks",
      icon: Clock,
      status: "available",
      color: "text-green-500",
      bgColor: "bg-green-500/10",
      borderColor: "border-green-500/30",
      shadowColor: "shadow-green-500/20",
      path: "/remediation/tasks",
      features: [
        "Scan Task Scheduler",
        "Identify malicious tasks",
        "Remove suspicious tasks",
        "Task backup",
      ],
    },
    {
      id: "deep-quarantine",
      title: "Deep Quarantine",
      description: "Complete malware removal with deep scanning",
      icon: Shield,
      status: "available",
      color: "text-red-500",
      bgColor: "bg-red-500/10",
      borderColor: "border-red-500/30",
      shadowColor: "shadow-red-500/20",
      path: "/remediation/quarantine",
      features: [
        "Deep file analysis",
        "Registry reference scan",
        "Service dependency check",
        "Complete removal",
      ],
    },
  ];

  const stats = [
    {
      label: "Registry Entries",
      value: statsData.registry,
      desc: "Suspicious entries found",
      icon: Database,
      color: "blue",
    },
    {
      label: "Services",
      value: statsData.services,
      desc: "Malicious services",
      icon: Settings,
      color: "purple",
    },
    {
      label: "Scheduled Tasks",
      value: statsData.tasks,
      desc: "Suspicious tasks",
      icon: Clock,
      color: "green",
    },
    {
      label: "Total Threats",
      value: statsData.total,
      desc: "Persistence mechanisms",
      icon: AlertTriangle,
      color: "red",
    },
  ];

  const getStatusBadge = (status: string) => {
    switch (status) {
      case "available":
        return (
          <motion.div
            whileHover={{ scale: 1.05 }}
            transition={{ type: "spring", stiffness: 400 }}
          >
            <Badge className="bg-green-500/20 text-green-400 hover:bg-green-500/30 border border-green-500/30 transition-all duration-300">
              Available
            </Badge>
          </motion.div>
        );
      case "planned":
        return (
          <motion.div
            whileHover={{ scale: 1.05 }}
            transition={{ type: "spring", stiffness: 400 }}
          >
            <Badge className="bg-yellow-500/20 text-yellow-400 hover:bg-yellow-500/30 border border-yellow-500/30 transition-all duration-300">
              Coming Soon
            </Badge>
          </motion.div>
        );
      default:
        return null;
    }
  };

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
                animate={{ rotate: [0, 10, -10, 0] }}
                transition={{ duration: 2, repeat: Infinity, repeatDelay: 3 }}
              >
                <Wrench className="h-8 w-8 text-primary" />
              </motion.div>
              Malware Remediation
            </h1>
            <p className="text-muted-foreground mt-2">
              Advanced tools for complete malware removal and system cleanup
            </p>
          </div>
          <motion.div whileHover={{ scale: 1.05 }} whileTap={{ scale: 0.95 }}>
            <Button onClick={loadStatistics} disabled={loading}>
              {loading ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  Scanning...
                </>
              ) : (
                <>
                  <Activity className="mr-2 h-4 w-4" />
                  Refresh Stats
                </>
              )}
            </Button>
          </motion.div>
        </motion.div>

        {/* Statistics Overview */}
        <div className="grid gap-4 md:grid-cols-4">
          {stats.map((stat, index) => {
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
                  className={`border-${stat.color}-500/20 bg-gradient-to-br from-${stat.color}-500/10 to-transparent hover:shadow-xl hover:shadow-${stat.color}-500/20 transition-all duration-300`}
                >
                  <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                    <CardTitle className="text-sm font-medium">
                      {stat.label}
                    </CardTitle>
                    <motion.div
                      whileHover={{ rotate: 360 }}
                      transition={{ duration: 0.5 }}
                    >
                      <Icon className={`h-4 w-4 text-${stat.color}-500`} />
                    </motion.div>
                  </CardHeader>
                  <CardContent>
                    <div
                      className={`text-2xl font-bold text-${stat.color}-500`}
                    >
                      {loading ? (
                        <Loader2 className="h-6 w-6 animate-spin" />
                      ) : (
                        <CountUp end={stat.value} duration={2} />
                      )}
                    </div>
                    <p className="text-xs text-muted-foreground">{stat.desc}</p>
                  </CardContent>
                </Card>
              </motion.div>
            );
          })}
        </div>

        {/* Remediation Modules */}
        <div className="grid gap-6 md:grid-cols-2">
          {remediationModules.map((module, index) => {
            const Icon = module.icon;
            return (
              <motion.div
                key={module.id}
                initial={{ opacity: 0, y: 30 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.5, delay: 0.2 + index * 0.1 }}
                whileHover={{ scale: 1.02, y: -4 }}
              >
                <Card
                  className={`hover:border-primary/50 transition-all duration-300 hover:shadow-2xl ${module.shadowColor} border-2 ${module.borderColor}`}
                >
                  <CardHeader>
                    <div className="flex items-start justify-between">
                      <div className="flex items-center gap-3">
                        <motion.div
                          whileHover={{ scale: 1.1, rotate: 5 }}
                          transition={{ type: "spring", stiffness: 400 }}
                          className={`p-3 rounded-lg ${module.bgColor} border ${module.borderColor}`}
                        >
                          <Icon className={`h-6 w-6 ${module.color}`} />
                        </motion.div>
                        <div>
                          <CardTitle className="text-xl">
                            {module.title}
                          </CardTitle>
                          <CardDescription className="mt-1">
                            {module.description}
                          </CardDescription>
                        </div>
                      </div>
                      {getStatusBadge(module.status)}
                    </div>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    {/* Features List */}
                    <div className="space-y-2">
                      {module.features.map((feature, featureIndex) => (
                        <motion.div
                          key={featureIndex}
                          initial={{ opacity: 0, x: -20 }}
                          animate={{ opacity: 1, x: 0 }}
                          transition={{
                            duration: 0.3,
                            delay: 0.3 + index * 0.1 + featureIndex * 0.05,
                          }}
                          whileHover={{ x: 4 }}
                          className="flex items-center gap-2 text-sm text-muted-foreground group"
                        >
                          <motion.div
                            whileHover={{ scale: 1.2, rotate: 360 }}
                            transition={{ duration: 0.3 }}
                          >
                            <CheckCircle2 className="h-4 w-4 text-green-500 group-hover:text-green-400 transition-colors" />
                          </motion.div>
                          <span className="group-hover:text-foreground transition-colors">
                            {feature}
                          </span>
                        </motion.div>
                      ))}
                    </div>

                    {/* Action Button */}
                    <motion.div
                      whileHover={{ scale: 1.02 }}
                      whileTap={{ scale: 0.98 }}
                    >
                      <Button
                        className="w-full hover:shadow-lg transition-all duration-300"
                        disabled={module.status !== "available"}
                        onClick={() => navigate(module.path)}
                      >
                        {module.status === "available" ? (
                          <>
                            <FileSearch className="mr-2 h-4 w-4" />
                            Open Module
                          </>
                        ) : (
                          <>
                            <Activity className="mr-2 h-4 w-4" />
                            Coming Soon
                          </>
                        )}
                      </Button>
                    </motion.div>
                  </CardContent>
                </Card>
              </motion.div>
            );
          })}
        </div>

        {/* Info Card */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5, delay: 0.8 }}
          whileHover={{ scale: 1.01 }}
        >
          <Card className="border-yellow-500/20 bg-gradient-to-br from-yellow-500/10 to-transparent hover:shadow-xl hover:shadow-yellow-500/20 transition-all duration-300">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <motion.div
                  animate={{ rotate: [0, 10, -10, 0] }}
                  transition={{
                    duration: 0.5,
                    repeat: Infinity,
                    repeatDelay: 2,
                  }}
                >
                  <AlertTriangle className="h-5 w-5 text-yellow-500" />
                </motion.div>
                Important Information
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              {[
                {
                  icon: "⚠️",
                  title: "Administrator Rights Required:",
                  text: "Most remediation operations require administrator privileges to modify system registry, services, and scheduled tasks.",
                },
                {
                  icon: "💾",
                  title: "Automatic Backups:",
                  text: "All modifications are automatically backed up before removal. You can restore any changes if needed.",
                },
                {
                  icon: "🔍",
                  title: "Deep Scanning:",
                  text: "Our remediation tools perform comprehensive scans to identify all persistence mechanisms used by malware.",
                },
                {
                  icon: "🛡️",
                  title: "Safe Removal:",
                  text: "Files and registry entries are analyzed before removal to prevent false positives and system damage.",
                },
              ].map((item, index) => (
                <motion.p
                  key={index}
                  initial={{ opacity: 0, x: -20 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ duration: 0.3, delay: 0.9 + index * 0.1 }}
                  whileHover={{ x: 4 }}
                  className="text-sm text-muted-foreground hover:text-foreground transition-all duration-300"
                >
                  <strong className="text-foreground">
                    {item.icon} {item.title}
                  </strong>{" "}
                  {item.text}
                </motion.p>
              ))}
            </CardContent>
          </Card>
        </motion.div>
      </motion.div>
    </ProtectedRoute>
  );
}