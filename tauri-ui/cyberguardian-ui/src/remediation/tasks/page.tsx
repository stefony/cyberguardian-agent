"use client"

import { useState, useEffect } from "react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Input } from "@/components/ui/input"
import {
  AlertTriangle,
  Clock,
  Search,
  Trash2,
  Shield,
  RefreshCw,
  Info,
  History,
  Calendar,
  Zap,
  Loader2,
  Play,
  XCircle,
  CheckCircle2,
  User,
  MapPin
} from "lucide-react"
import { remediationApi } from "@/lib/api"
import { useToast } from "@/hooks/use-toast"
import ProtectedRoute from '@/components/ProtectedRoute';

interface Task {
  id: string
  task_name: string
  path: string
  status: string
  enabled: boolean
  actions: Array<{
    type: string
    path: string
    arguments: string
    working_directory: string
  }>
  triggers: Array<{
    type: string
    enabled: boolean
  }>
  last_run: string
  next_run: string
  author: string
  risk_score: number
  indicators: string[]
  scanned_at: string
}

interface TaskStats {
  total_suspicious: number
  critical_risk: number
  high_risk: number
  medium_risk: number
  low_risk: number
  by_status: Record<string, number>
  enabled_count: number
  disabled_count: number
}

interface BackupFile {
  filename: string
  filepath: string
  task_path: string
  task_name: string
  author: string
  backed_up_at: string
}

export default function TasksCleanupPage() {
  const { toast } = useToast()
  const [scanning, setScanning] = useState(false)
  const [tasks, setTasks] = useState<Task[]>([])
  const [stats, setStats] = useState<TaskStats | null>(null)
  const [searchQuery, setSearchQuery] = useState("")
  const [selectedSeverity, setSelectedSeverity] = useState<string>("all")
  const [backups, setBackups] = useState<BackupFile[]>([])
  const [showBackups, setShowBackups] = useState(false)
  const [removing, setRemoving] = useState<string | null>(null)

  useEffect(() => {
    handleScan()
    loadBackups()
  }, [])

  const handleScan = async () => {
    setScanning(true)
    try {
      const response = await remediationApi.scanTasks()
      if (response.success && response.data) {
        setTasks(response.data.tasks)
        setStats(response.data.statistics)
        toast({
          title: "Scan Complete",
          description: `Found ${response.data.tasks.length} suspicious tasks`,
        })
      } else {
        toast({
          title: "Scan Failed",
          description: response.error || "Failed to scan tasks",
          variant: "destructive",
        })
      }
    } catch (error) {
      toast({
        title: "Error",
        description: "An error occurred while scanning",
        variant: "destructive",
      })
    } finally {
      setScanning(false)
    }
  }

  const loadBackups = async () => {
    try {
      const response = await remediationApi.listTaskBackups()
      if (response.success && response.data) {
        setBackups(response.data.backups)
      }
    } catch (error) {
      console.error("Failed to load backups:", error)
    }
  }

  const handleRemove = async (task: Task) => {
    if (!confirm(`⚠️ PERMANENTLY DELETE this scheduled task?\n\n${task.task_name}\n\nPath: ${task.path}\n\nA backup will be created automatically.\n\n⚠️ This action requires administrator privileges!`)) {
      return
    }

    setRemoving(task.id)
    try {
      const response = await remediationApi.removeTask({ task_path: task.path })

      if (response.success && response.data?.success) {
        toast({
          title: "Task Removed",
          description: `Task deleted. Backup: ${response.data.backup_file}`,
        })
        handleScan()
        loadBackups()
      } else {
        toast({
          title: "Removal Failed",
          description: response.data?.message || response.error,
          variant: "destructive",
        })
      }
    } catch (error) {
      toast({
        title: "Error",
        description: "An error occurred during removal",
        variant: "destructive",
      })
    } finally {
      setRemoving(null)
    }
  }

  const getRiskColor = (score: number) => {
    if (score >= 80) return "from-red-500 to-orange-500"
    if (score >= 60) return "from-orange-500 to-yellow-500"
    if (score >= 40) return "from-yellow-500 to-green-500"
    return "from-green-500 to-emerald-500"
  }

  const getRiskBadge = (score: number) => {
    if (score >= 80) {
      return <Badge className="bg-red-500/20 text-red-400 border-red-500/30">Critical</Badge>
    } else if (score >= 60) {
      return <Badge className="bg-orange-500/20 text-orange-400 border-orange-500/30">High</Badge>
    } else if (score >= 40) {
      return <Badge className="bg-yellow-500/20 text-yellow-400 border-yellow-500/30">Medium</Badge>
    } else {
      return <Badge className="bg-green-500/20 text-green-400 border-green-500/30">Low</Badge>
    }
  }

  const getTriggerIcon = (triggerType: string) => {
    if (triggerType.includes("BOOT")) return <Zap className="h-3 w-3" />
    if (triggerType.includes("LOGON")) return <User className="h-3 w-3" />
    if (triggerType.includes("DAILY")) return <Calendar className="h-3 w-3" />
    return <Clock className="h-3 w-3" />
  }

  const filteredTasks = tasks.filter((task) => {
    const matchesSearch =
      task.task_name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      task.path.toLowerCase().includes(searchQuery.toLowerCase())

    const matchesSeverity =
      selectedSeverity === "all" ||
      (selectedSeverity === "critical" && task.risk_score >= 80) ||
      (selectedSeverity === "high" && task.risk_score >= 60 && task.risk_score < 80) ||
      (selectedSeverity === "medium" && task.risk_score >= 40 && task.risk_score < 60) ||
      (selectedSeverity === "low" && task.risk_score < 40)

    return matchesSearch && matchesSeverity
  })

  return (
    <ProtectedRoute>
    <div className="container mx-auto p-6 space-y-6">
      {/* Header with Gradient */}
      <div className="relative overflow-hidden rounded-2xl bg-gradient-to-br from-orange-600 via-yellow-600 to-green-600 p-8">
        <div className="absolute inset-0 bg-grid-white/10" />
        <div className="relative flex items-center justify-between">
          <div>
            <h1 className="text-4xl font-bold text-white flex items-center gap-3">
              <div className="p-3 bg-white/20 backdrop-blur-sm rounded-xl">
                <Clock className="h-8 w-8" />
              </div>
              Scheduled Tasks Cleanup
            </h1>
            <p className="text-white/90 mt-2 text-lg">
              Scan and clean malicious scheduled tasks
            </p>
          </div>
          <div className="flex gap-3">
            <Button
              variant="secondary"
              className="bg-white/20 backdrop-blur-sm border-white/30 text-white hover:bg-white/30"
              onClick={() => setShowBackups(!showBackups)}
            >
              <History className="mr-2 h-4 w-4" />
              Backups ({backups.length})
            </Button>
            <Button
              onClick={handleScan}
              disabled={scanning}
              className="bg-white text-orange-600 hover:bg-white/90"
            >
              {scanning ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  Scanning...
                </>
              ) : (
                <>
                  <Search className="mr-2 h-4 w-4" />
                  Scan Tasks
                </>
              )}
            </Button>
          </div>
        </div>
      </div>

      {/* Statistics Cards */}
      {stats && (
        <div className="grid gap-4 md:grid-cols-5">
          {[
            { label: "Total", value: stats.total_suspicious, icon: Clock, gradient: "from-orange-500 to-yellow-500" },
            { label: "Critical", value: stats.critical_risk, icon: AlertTriangle, gradient: "from-red-500 to-orange-500" },
            { label: "High", value: stats.high_risk, icon: AlertTriangle, gradient: "from-orange-500 to-yellow-500" },
            { label: "Medium", value: stats.medium_risk, icon: AlertTriangle, gradient: "from-yellow-500 to-green-500" },
            { label: "Low", value: stats.low_risk, icon: Info, gradient: "from-green-500 to-emerald-500" },
          ].map((stat, idx) => {
            const Icon = stat.icon
            return (
              <Card
                key={idx}
                className={`cursor-pointer transition-all duration-300 hover:scale-105 bg-gradient-to-br ${stat.gradient} border-0`}
                onClick={() => setSelectedSeverity(stat.label.toLowerCase())}
              >
                <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                  <CardTitle className="text-sm font-medium text-white/90">
                    {stat.label}
                  </CardTitle>
                  <Icon className="h-4 w-4 text-white" />
                </CardHeader>
                <CardContent>
                  <div className="text-3xl font-bold text-white">{stat.value}</div>
                </CardContent>
              </Card>
            )
          })}
        </div>
      )}

      {/* Backups Panel */}
      {showBackups && (
        <Card className="border-orange-500/30 bg-gradient-to-br from-orange-500/10 to-transparent">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <History className="h-5 w-5 text-orange-500" />
              Task Backups
            </CardTitle>
            <CardDescription>Restore previously removed tasks</CardDescription>
          </CardHeader>
          <CardContent>
            {backups.length === 0 ? (
              <div className="text-center py-8">
                <Shield className="mx-auto h-12 w-12 text-muted-foreground mb-4" />
                <p className="text-sm text-muted-foreground">No backups available</p>
              </div>
            ) : (
              <div className="space-y-3">
                {backups.map((backup) => (
                  <div
                    key={backup.filename}
                    className="p-4 border rounded-lg bg-gradient-to-br from-orange-500/5 to-yellow-500/5 hover:from-orange-500/10 hover:to-yellow-500/10 transition-all"
                  >
                    <div className="flex items-start justify-between">
                      <div className="flex-1">
                        <p className="font-medium">{backup.task_name}</p>
                        <p className="text-xs text-muted-foreground mt-1">
                          {backup.task_path}
                        </p>
                        <div className="flex items-center gap-2 mt-2">
                          <Badge variant="outline" className="text-xs">
                            <User className="h-3 w-3 mr-1" />
                            {backup.author}
                          </Badge>
                          <span className="text-xs text-muted-foreground">
                            {new Date(backup.backed_up_at).toLocaleString()}
                          </span>
                        </div>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {/* Search */}
      <div className="flex gap-4">
        <div className="flex-1 relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder="Search by name or path..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="pl-10"
          />
        </div>
      </div>

      {/* Tasks Timeline */}
      {filteredTasks.length === 0 ? (
        <Card>
          <CardContent className="py-16">
            <div className="text-center">
              <Shield className="mx-auto h-16 w-16 text-muted-foreground mb-4" />
              <p className="text-lg font-medium">No suspicious tasks found</p>
              <p className="text-sm text-muted-foreground mt-2">
                {tasks.length === 0
                  ? "Click 'Scan Tasks' to start scanning"
                  : "Try adjusting your filters"}
              </p>
            </div>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-4">
          {filteredTasks.map((task) => (
            <Card
              key={task.id}
              className="overflow-hidden hover:shadow-xl transition-all duration-300 border-l-4 bg-gradient-to-r from-slate-900/80 to-slate-800/80 backdrop-blur-sm"
              style={{ borderLeftColor: task.risk_score >= 60 ? '#ef4444' : task.risk_score >= 40 ? '#f59e0b' : '#10b981' }}
            >
              <CardContent className="p-6">
                <div className="flex items-start justify-between mb-4">
                  <div className="flex-1">
                    <div className="flex items-center gap-3 mb-2">
                      <h3 className="text-xl font-bold">{task.task_name}</h3>
                      {getRiskBadge(task.risk_score)}
                      <Badge variant={task.enabled ? "default" : "outline"} className="text-xs">
                        {task.enabled ? <CheckCircle2 className="h-3 w-3 mr-1" /> : <XCircle className="h-3 w-3 mr-1" />}
                        {task.enabled ? "Enabled" : "Disabled"}
                      </Badge>
                    </div>
                    <div className="flex items-center gap-2 text-sm text-muted-foreground">
                      <MapPin className="h-3 w-3" />
                      <span className="font-mono text-xs">{task.path}</span>
                    </div>
                  </div>
                  <div className="text-right">
                    <div className={`text-3xl font-bold bg-gradient-to-r ${getRiskColor(task.risk_score)} bg-clip-text text-transparent`}>
                      {task.risk_score}
                    </div>
                    <div className="text-xs text-muted-foreground">Risk Score</div>
                  </div>
                </div>

                {/* Actions */}
                {task.actions.length > 0 && (
                  <div className="mb-4">
                    <p className="text-xs text-muted-foreground mb-2 flex items-center gap-1">
                      <Play className="h-3 w-3" />
                      Actions
                    </p>
                    {task.actions.map((action, idx) => (
                      <div key={idx} className="text-sm font-mono bg-black/40 px-3 py-2 rounded mb-1">
                        <span className="text-green-400">{action.path}</span>
                        {action.arguments && (
                          <span className="text-blue-400 ml-2">{action.arguments}</span>
                        )}
                      </div>
                    ))}
                  </div>
                )}

                {/* Triggers */}
                {task.triggers.length > 0 && (
                  <div className="mb-4">
                    <p className="text-xs text-muted-foreground mb-2">Triggers</p>
                    <div className="flex flex-wrap gap-1">
                      {task.triggers.map((trigger, idx) => (
                        <Badge
                          key={idx}
                          variant="outline"
                          className="text-xs bg-orange-500/10 border-orange-500/30"
                        >
                          {getTriggerIcon(trigger.type)}
                          <span className="ml-1">{trigger.type.replace("TASK_TRIGGER_", "")}</span>
                        </Badge>
                      ))}
                    </div>
                  </div>
                )}

                {/* Indicators */}
                {task.indicators.length > 0 && (
                  <div className="mb-4">
                    <p className="text-xs text-muted-foreground mb-2">Threat Indicators</p>
                    <div className="flex flex-wrap gap-1">
                      {task.indicators.map((indicator, idx) => (
                        <Badge
                          key={idx}
                          variant="outline"
                          className="text-xs bg-red-500/10 border-red-500/30 text-red-400"
                        >
                          <AlertTriangle className="h-3 w-3 mr-1" />
                          {indicator}
                        </Badge>
                      ))}
                    </div>
                  </div>
                )}

                {/* Schedule Info */}
                <div className="flex items-center gap-4 text-xs text-muted-foreground mb-4">
                  <div>
                    <span className="font-medium">Last Run:</span> {task.last_run}
                  </div>
                  <div>
                    <span className="font-medium">Next Run:</span> {task.next_run}
                  </div>
                  <div>
                    <span className="font-medium">Author:</span> {task.author}
                  </div>
                </div>

                {/* Action Button */}
                <Button
                  variant="destructive"
                  onClick={() => handleRemove(task)}
                  disabled={removing === task.id}
                  className="w-full"
                >
                  {removing === task.id ? (
                    <Loader2 className="h-4 w-4 animate-spin" />
                  ) : (
                    <>
                      <Trash2 className="mr-2 h-4 w-4" />
                      Remove Task
                    </>
                  )}
                </Button>
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      {/* Warning */}
      <Alert className="border-yellow-500/50 bg-gradient-to-r from-yellow-500/10 to-orange-500/10">
        <AlertTriangle className="h-4 w-4 text-yellow-500" />
        <AlertDescription>
          <strong>Administrator Rights Required:</strong> Modifying scheduled tasks requires elevated privileges. All tasks are automatically backed up before removal.
        </AlertDescription>
      </Alert>
    </div>
    </ProtectedRoute>
  )
}