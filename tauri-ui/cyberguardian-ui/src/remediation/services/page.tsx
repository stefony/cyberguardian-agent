"use client"

import { useState, useEffect } from "react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Input } from "@/components/ui/input"
import {
  AlertTriangle,
  Settings,
  Search,
  Trash2,
  StopCircle,
  Shield,
  Info,
  History,
  Activity,
  Zap,
  Loader2,
  Play,
  Pause
} from "lucide-react"
import { toast } from "sonner"
import ProtectedRoute from '@/components/ProtectedRoute';

interface Service {
  id: string
  service_name: string
  display_name: string
  binary_path: string
  startup_type: string
  status: string
  description: string
  risk_score: number
  indicators: string[]
  dependencies: string[]
  scanned_at: string
}

interface ServiceStats {
  total_suspicious: number
  critical_risk: number
  high_risk: number
  medium_risk: number
  low_risk: number
  by_status: Record<string, number>
  by_startup_type: Record<string, number>
}

export default function ServicesCleanupPage() {
  const [scanning, setScanning] = useState(false)
  const [services, setServices] = useState<Service[]>([])
  const [stats, setStats] = useState<ServiceStats | null>(null)
  const [searchQuery, setSearchQuery] = useState("")
  const [selectedSeverity, setSelectedSeverity] = useState<string>("all")

  useEffect(() => {
    handleScan()
  }, [])

  // 🔥 DESKTOP AGENT INTEGRATION - Real Windows Services Scan
  const handleScan = async () => {
    setScanning(true)
    try {
      // Use window.__TAURI__ directly (more reliable than import)
      const invoke = (window as any).__TAURI__.core.invoke
      const result: any = await invoke('scan_windows_services')
      
      if (result && result.services) {
        setServices(result.services)
        setStats(result.statistics)
        
        toast.success("Service Scan Complete", {
          description: `Found ${result.services.length} suspicious services`,
        })
      }
    } catch (error) {
      console.error("Service scan failed:", error)
      toast.error("Scan Failed", {
        description: error?.toString() || "An error occurred during service scan",
      })
    } finally {
      setScanning(false)
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

  const getStatusIcon = (status: string) => {
    switch (status.toLowerCase()) {
      case "running":
        return <Play className="h-4 w-4 text-green-500" />
      case "stopped":
        return <Pause className="h-4 w-4 text-gray-500" />
      default:
        return <Activity className="h-4 w-4 text-yellow-500" />
    }
  }

  const filteredServices = services.filter((service) => {
    const matchesSearch =
      service.service_name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      service.display_name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      service.binary_path.toLowerCase().includes(searchQuery.toLowerCase())

    const matchesSeverity =
      selectedSeverity === "all" ||
      (selectedSeverity === "critical" && service.risk_score >= 80) ||
      (selectedSeverity === "high" && service.risk_score >= 60 && service.risk_score < 80) ||
      (selectedSeverity === "medium" && service.risk_score >= 40 && service.risk_score < 60) ||
      (selectedSeverity === "low" && service.risk_score < 40)

    return matchesSearch && matchesSeverity
  })

  return (
    <ProtectedRoute>
    <div className="container mx-auto p-6 space-y-6">
      {/* Header */}
      <div className="relative overflow-hidden rounded-2xl bg-gradient-to-br from-purple-600 via-pink-600 to-cyan-600 p-8">
        <div className="absolute inset-0 bg-grid-white/10" />
        <div className="relative flex items-center justify-between">
          <div>
            <h1 className="text-4xl font-bold text-white flex items-center gap-3">
              <div className="p-3 bg-white/20 backdrop-blur-sm rounded-xl">
                <Settings className="h-8 w-8" />
              </div>
              Services Cleanup
            </h1>
            <p className="text-white/90 mt-2 text-lg">
              🖥️ Desktop Agent - Real Windows Services Scanning
            </p>
          </div>
          <Button
            onClick={handleScan}
            disabled={scanning}
            className="bg-white text-purple-600 hover:bg-white/90"
          >
            {scanning ? (
              <>
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                Scanning...
              </>
            ) : (
              <>
                <Search className="mr-2 h-4 w-4" />
                Scan Services
              </>
            )}
          </Button>
        </div>
      </div>

      {/* Statistics Cards */}
      {stats && (
        <div className="grid gap-4 md:grid-cols-5">
          {[
            { label: "Total", value: stats.total_suspicious, icon: Settings, gradient: "from-purple-500 to-pink-500" },
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
            placeholder="Search by name or path..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="pl-10"
          />
        </div>
      </div>

      {/* Services Grid */}
      {filteredServices.length === 0 ? (
        <Card>
          <CardContent className="py-16">
            <div className="text-center">
              <Shield className="mx-auto h-16 w-16 text-muted-foreground mb-4" />
              <p className="text-lg font-medium">No suspicious services found</p>
              <p className="text-sm text-muted-foreground mt-2">
                {services.length === 0
                  ? "Click 'Scan Services' to start scanning"
                  : "Try adjusting your filters"}
              </p>
            </div>
          </CardContent>
        </Card>
      ) : (
        <div className="grid gap-6 md:grid-cols-2">
          {filteredServices.map((service) => (
            <Card
              key={service.id}
              className="overflow-hidden hover:shadow-lg transition-all duration-300 border-0 bg-gradient-to-br from-slate-900/50 to-slate-800/50 backdrop-blur-sm"
            >
              <div className={`h-2 bg-gradient-to-r ${getRiskColor(service.risk_score)}`} />
              <CardHeader>
                <div className="flex items-start justify-between">
                  <div className="flex-1">
                    <div className="flex items-center gap-2 mb-2">
                      <CardTitle className="text-xl">{service.display_name || service.service_name}</CardTitle>
                      {getStatusIcon(service.status)}
                    </div>
                    <div className="flex items-center gap-2">
                      {getRiskBadge(service.risk_score)}
                      <Badge variant="outline" className="text-xs">
                        {service.startup_type}
                      </Badge>
                      <Badge variant="outline" className="text-xs">
                        {service.status}
                      </Badge>
                    </div>
                  </div>
                  <div className="text-right">
                    <div className="text-2xl font-bold bg-gradient-to-r from-purple-500 to-cyan-500 bg-clip-text text-transparent">
                      {service.risk_score}
                    </div>
                    <div className="text-xs text-muted-foreground">Risk Score</div>
                  </div>
                </div>
              </CardHeader>
              <CardContent className="space-y-4">
                {/* Service Name */}
                <div>
                  <p className="text-xs text-muted-foreground mb-1">Service Name</p>
                  <p className="text-sm font-mono bg-black/30 px-2 py-1 rounded">
                    {service.service_name}
                  </p>
                </div>

                {/* Binary Path */}
                <div>
                  <p className="text-xs text-muted-foreground mb-1">Binary Path</p>
                  <p className="text-sm font-mono bg-black/30 px-2 py-1 rounded break-all">
                    {service.binary_path}
                  </p>
                </div>

                {/* Indicators */}
                {service.indicators.length > 0 && (
                  <div>
                    <p className="text-xs text-muted-foreground mb-2">Threat Indicators</p>
                    <div className="flex flex-wrap gap-1">
                      {service.indicators.map((indicator, idx) => (
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
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      {/* Warning */}
      <Alert className="border-yellow-500/50 bg-gradient-to-r from-yellow-500/10 to-orange-500/10">
        <AlertTriangle className="h-4 w-4 text-yellow-500" />
        <AlertDescription>
          <strong>Desktop Agent Active:</strong> This page uses the Tauri Desktop Agent to scan real Windows services locally using PowerShell. All scanning is performed directly on your system.
        </AlertDescription>
      </Alert>
    </div>
    </ProtectedRoute>
  )
}