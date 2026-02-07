"use client"

import { useState, useEffect } from "react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Input } from "@/components/ui/input"
import {
  AlertTriangle,
  Database,
  Search,
  Trash2,
  RefreshCw,
  Info,
  ChevronDown,
  ChevronUp,
  History,
  Shield,
  Loader2,
  Zap
} from "lucide-react"
import { toast } from "sonner"
import ProtectedRoute from '@/components/ProtectedRoute'

interface RegistryEntry {
  id: string
  hive: string
  key_path: string
  value_name: string
  value_data: string
  value_type: string
  risk_score: number
  indicators: string[]
  scanned_at: string
}

interface RegistryStats {
  total_suspicious: number
  critical_risk: number
  high_risk: number
  medium_risk: number
  low_risk: number
  by_hive: Record<string, number>
}

interface BackupFile {
  filename: string
  filepath: string
  hive: string
  key_path: string
  value_name: string
  backed_up_at: string
}

export default function RegistryCleanupPage() {
  const [scanning, setScanning] = useState(false)
  const [entries, setEntries] = useState<RegistryEntry[]>([])
  const [stats, setStats] = useState<RegistryStats | null>(null)
  const [searchQuery, setSearchQuery] = useState("")
  const [selectedSeverity, setSelectedSeverity] = useState<string>("all")
  const [expandedEntry, setExpandedEntry] = useState<string | null>(null)
  const [backups, setBackups] = useState<BackupFile[]>([])
  const [showBackups, setShowBackups] = useState(false)
  const [removing, setRemoving] = useState<string | null>(null)

  useEffect(() => {
    handleScan()
  }, [])

  // 🔥 DESKTOP AGENT INTEGRATION - Real Windows Registry Scan
  const handleScan = async () => {
    setScanning(true)
    try {
      // Use window.__TAURI__ directly (more reliable than import)
      const invoke = (window as any).__TAURI__.core.invoke
      const result: any = await invoke('scan_windows_registry')
      
      if (result && result.entries) {
        setEntries(result.entries)
        setStats(result.statistics)
        
        toast.success("Registry Scan Complete", {
          description: `Found ${result.entries.length} suspicious entries`,
        })
      }
    } catch (error) {
      console.error("Registry scan failed:", error)
      toast.error("Scan Failed", {
        description: error?.toString() || "An error occurred during registry scan",
      })
    } finally {
      setScanning(false)
    }
  }

  const handleRemove = async (entry: RegistryEntry) => {
    if (!confirm(`⚠️ PERMANENTLY DELETE this registry entry?\n\n${entry.hive}\\${entry.key_path}\\${entry.value_name}\n\nA backup will be created automatically.\n\n⚠️ This action requires administrator privileges!`)) {
      return
    }

    setRemoving(entry.id)
    try {
      // Note: Remove functionality would need additional Tauri command
      toast.info("Remove Functionality", {
        description: "Registry removal requires additional implementation",
      })
    } catch (error) {
      toast.error("Error", {
        description: "An error occurred during removal"
      })
    } finally {
      setRemoving(null)
    }
  }

  const getRiskColor = (score: number) => {
    if (score >= 80) return "from-red-500 to-pink-500"
    if (score >= 60) return "from-orange-500 to-red-500"
    if (score >= 40) return "from-yellow-500 to-orange-500"
    return "from-blue-500 to-cyan-500"
  }

  const getRiskBadge = (score: number) => {
    if (score >= 80) {
      return <Badge className="bg-red-500/20 text-red-400 border-red-500/30">Critical</Badge>
    } else if (score >= 60) {
      return <Badge className="bg-orange-500/20 text-orange-400 border-orange-500/30">High</Badge>
    } else if (score >= 40) {
      return <Badge className="bg-yellow-500/20 text-yellow-400 border-yellow-500/30">Medium</Badge>
    } else {
      return <Badge className="bg-blue-500/20 text-blue-400 border-blue-500/30">Low</Badge>
    }
  }

  const filteredEntries = entries.filter((entry) => {
    const matchesSearch =
      entry.key_path.toLowerCase().includes(searchQuery.toLowerCase()) ||
      entry.value_name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      entry.value_data.toLowerCase().includes(searchQuery.toLowerCase())

    const matchesSeverity =
      selectedSeverity === "all" ||
      (selectedSeverity === "critical" && entry.risk_score >= 80) ||
      (selectedSeverity === "high" && entry.risk_score >= 60 && entry.risk_score < 80) ||
      (selectedSeverity === "medium" && entry.risk_score >= 40 && entry.risk_score < 60) ||
      (selectedSeverity === "low" && entry.risk_score < 40)

    return matchesSearch && matchesSeverity
  })

  return (
    <ProtectedRoute>
    <div className="container mx-auto p-6 space-y-6">
      {/* Header */}
      <div className="relative overflow-hidden rounded-2xl bg-gradient-to-br from-blue-600 via-cyan-600 to-teal-600 p-8">
        <div className="absolute inset-0 bg-grid-white/10" />
        <div className="relative flex items-center justify-between">
          <div>
            <h1 className="text-4xl font-bold text-white flex items-center gap-3">
              <div className="p-3 bg-white/20 backdrop-blur-sm rounded-xl">
                <Database className="h-8 w-8" />
              </div>
              Registry Cleanup
            </h1>
            <p className="text-white/90 mt-2 text-lg">
              🖥️ Desktop Agent - Real Windows Registry Scanning
            </p>
          </div>
          <Button
            onClick={handleScan}
            disabled={scanning}
            className="bg-white text-blue-600 hover:bg-white/90"
          >
            {scanning ? (
              <>
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                Scanning...
              </>
            ) : (
              <>
                <Search className="mr-2 h-4 w-4" />
                Scan Registry
              </>
            )}
          </Button>
        </div>
      </div>

      {/* Statistics Cards */}
      {stats && (
        <div className="grid gap-4 md:grid-cols-5">
          {[
            { label: "Total", value: stats.total_suspicious, icon: Database, gradient: "from-blue-500 to-cyan-500" },
            { label: "Critical", value: stats.critical_risk, icon: AlertTriangle, gradient: "from-red-500 to-pink-500" },
            { label: "High", value: stats.high_risk, icon: AlertTriangle, gradient: "from-orange-500 to-red-500" },
            { label: "Medium", value: stats.medium_risk, icon: AlertTriangle, gradient: "from-yellow-500 to-orange-500" },
            { label: "Low", value: stats.low_risk, icon: Info, gradient: "from-blue-500 to-cyan-500" },
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

      {/* Search */}
      <div className="flex gap-4">
        <div className="flex-1 relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder="Search registry entries..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="pl-10"
          />
        </div>
      </div>

      {/* Registry Entries */}
      {filteredEntries.length === 0 ? (
        <Card>
          <CardContent className="py-16">
            <div className="text-center">
              <Shield className="mx-auto h-16 w-16 text-muted-foreground mb-4" />
              <p className="text-lg font-medium">No suspicious entries found</p>
              <p className="text-sm text-muted-foreground mt-2">
                {entries.length === 0
                  ? "Click 'Scan Registry' to start scanning"
                  : "Try adjusting your filters"}
              </p>
            </div>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-4">
          {filteredEntries.map((entry) => (
            <Card
              key={entry.id}
              className="overflow-hidden hover:shadow-lg transition-all duration-300"
            >
              <div className={`h-2 bg-gradient-to-r ${getRiskColor(entry.risk_score)}`} />
              <CardHeader>
                <div className="flex items-start justify-between">
                  <div className="flex-1">
                    <div className="flex items-center gap-2 mb-2">
                      {getRiskBadge(entry.risk_score)}
                      <Badge variant="outline" className="text-xs">{entry.hive}</Badge>
                    </div>
                    <CardTitle className="text-lg font-mono text-sm">
                      {entry.key_path}\\{entry.value_name}
                    </CardTitle>
                  </div>
                  <div className="text-right">
                    <div className={`text-2xl font-bold bg-gradient-to-r ${getRiskColor(entry.risk_score)} bg-clip-text text-transparent`}>
                      {entry.risk_score}
                    </div>
                    <div className="text-xs text-muted-foreground">Risk Score</div>
                  </div>
                </div>
              </CardHeader>
              <CardContent className="space-y-4">
                {/* Value Data */}
                <div>
                  <p className="text-xs text-muted-foreground mb-1">Value Data</p>
                  <p className="text-sm font-mono bg-black/30 px-2 py-1 rounded break-all">
                    {entry.value_data}
                  </p>
                </div>

                {/* Indicators */}
                {entry.indicators.length > 0 && (
                  <div>
                    <p className="text-xs text-muted-foreground mb-2">Threat Indicators</p>
                    <div className="flex flex-wrap gap-1">
                      {entry.indicators.map((indicator, idx) => (
                        <Badge
                          key={idx}
                          variant="outline"
                          className="text-xs bg-red-500/10 border-red-500/30 text-red-400"
                        >
                          <Zap className="h-3 w-3 mr-1" />
                          {indicator}
                        </Badge>
                      ))}
                    </div>
                  </div>
                )}

                {/* Actions */}
                <div className="flex gap-2 pt-4 border-t border-white/10">
                  <Button
                    size="sm"
                    variant="destructive"
                    onClick={() => handleRemove(entry)}
                    disabled={removing === entry.id}
                    className="flex-1"
                  >
                    {removing === entry.id ? (
                      <Loader2 className="h-4 w-4 animate-spin" />
                    ) : (
                      <>
                        <Trash2 className="mr-2 h-4 w-4" />
                        Remove
                      </>
                    )}
                  </Button>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      {/* Warning */}
      <Alert className="border-yellow-500/50 bg-gradient-to-r from-yellow-500/10 to-orange-500/10">
        <AlertTriangle className="h-4 w-4 text-yellow-500" />
        <AlertDescription>
          <strong>Desktop Agent Active:</strong> This page uses the Tauri Desktop Agent to scan real Windows registry entries locally on your machine. All scanning is performed directly on your system without backend API calls.
        </AlertDescription>
      </Alert>
    </div>
    </ProtectedRoute>
  )
}