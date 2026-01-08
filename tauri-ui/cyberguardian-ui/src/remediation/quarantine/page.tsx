"use client"

import { useState, useEffect } from "react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Input } from "@/components/ui/input"
import {
  AlertTriangle,
  Shield,
  Search,
  Trash2,
  RefreshCw,
  History,
  Zap,
  Loader2,
  CheckCircle2,
  XCircle,
  FileSearch,
  Database,
  Settings,
  Clock,
  Target,
  ShieldAlert,
  Activity,
  ArrowRight
} from "lucide-react"
import { remediationApi } from "@/lib/api"
import { toast } from "sonner"
import ProtectedRoute from '@/components/ProtectedRoute';

// Helper to make authenticated requests
const fetchWithAuth = async (endpoint: string, options?: RequestInit) => {
  const token = typeof window !== 'undefined' ? localStorage.getItem('access_token') : null;
  
  const headers: Record<string, string> = {};
  
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }
  
  // Don't set Content-Type for FormData - browser will set it with boundary
  if (options?.body && !(options.body instanceof FormData)) {
    headers['Content-Type'] = 'application/json';
  }
  
  const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || 'https://cyberguardian-backend-production.up.railway.app';
  
  const response = await fetch(`${API_BASE_URL}${endpoint}`, {
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

interface AnalysisResult {
  analysis_id: string
  target_path: string
  analyzed_at: string
  stages: {
    file_analysis: any
    registry_scan: any
    service_scan: any
    task_scan: any
  }
  threat_level: string
  risk_score: number
  recommendations: string[]
}

interface BackupFile {
  filename: string
  filepath: string
  analysis_id: string
  target_path: string
  threat_level: string
  risk_score: number
  backed_up_at: string
}

export default function DeepQuarantinePage() {
  const [targetPath, setTargetPath] = useState("")
  const [selectedFile, setSelectedFile] = useState<File | null>(null)
  const [analyzing, setAnalyzing] = useState(false)
  const [removing, setRemoving] = useState(false)
  const [analysis, setAnalysis] = useState<AnalysisResult | null>(null)
  const [backups, setBackups] = useState<BackupFile[]>([])
  const [showBackups, setShowBackups] = useState(false)

  useEffect(() => {
    loadBackups()
  }, [])

  const loadBackups = async () => {
    try {
      const response = await remediationApi.listDeepBackups()
      if (response.success && response.data) {
        setBackups(response.data.backups)
      }
    } catch (error) {
      console.error("Failed to load backups:", error)
    }
  }

  const handleAnalyze = async () => {
    if (!selectedFile && !targetPath.trim()) {
      toast.error("Invalid Input", {
        description: "Please select a file or enter a path",
      })
      return
    }

    setAnalyzing(true)
    
    // Show initial toast
    toast.info("Starting Analysis", {
      description: selectedFile ? `Uploading ${selectedFile.name}...` : `Analyzing ${targetPath}...`,
    })

    try {
      let response

      // If file is selected, upload it
      if (selectedFile) {
        console.log("📤 Uploading file:", selectedFile.name, selectedFile.size, "bytes")
        
        const formData = new FormData()
        formData.append("file", selectedFile)

        // Call upload endpoint
const uploadResponse = await fetchWithAuth(
  '/api/remediation/deep-quarantine/upload',
  {
    method: "POST",
    body: formData,
  }
)

console.log("📥 Upload response status:", uploadResponse.status)

const data = await uploadResponse.json()
        console.log("✅ Analysis result:", data)
        response = { success: true, data }
      } else {

        
        // Use path-based analysis
        console.log("📂 Analyzing path:", targetPath)
        response = await remediationApi.analyzeDeep({ file_path: targetPath })
        console.log("✅ Analysis result:", response)
      }

      if (response.success && response.data) {
        console.log("🔍 Checking analysis data:", response.data)
        
        // Check if threat_level exists (means analysis succeeded)
        if (!response.data.threat_level) {
          console.warn("⚠️ No threat_level in response:", response.data)
          toast.warning("Analysis Not Supported", {
            description: response.data.message || "Deep Quarantine is only available on Windows systems",
          })
          return
        }

        console.log("✅ Analysis complete! Threat level:", response.data.threat_level)
        setAnalysis(response.data)
        toast.success("Analysis Complete", {
          description: `Threat Level: ${response.data.threat_level.toUpperCase()} | Risk Score: ${response.data.risk_score}`,
        })
      } else {
        console.error("❌ Analysis failed:", response)
        toast.error("Analysis Failed", {
          description: response.error || "Failed to analyze target",
        })
      }
    } catch (error) {
      console.error("❌ Error during analysis:", error)
      toast.error("Error", {
        description: error instanceof Error ? error.message : "An error occurred during analysis",
      })
    } finally {
      setAnalyzing(false)
    }
  }

  const handleRemove = async () => {
    if (!analysis) return

    if (!confirm(`⚠️ COMPLETE REMOVAL\n\nThis will remove:\n- Target file(s)\n- Registry references\n- Service dependencies\n- Task references\n\nA complete backup will be created.\n\n⚠️ This action requires administrator privileges!\n\nProceed?`)) {
      return
    }

    setRemoving(true)
    try {
      const response = await remediationApi.removeDeep({
        analysis_id: analysis.analysis_id,
        analysis_data: analysis,
      })

      if (response.success && response.data?.success) {
        toast.success("Complete Removal Successful", {
          description: `Backup: ${response.data.backup_file}`,
        })
        setAnalysis(null)
        setTargetPath("")
        loadBackups()
      } else {
        toast.error("Removal Failed", {
          description: response.data?.message || response.error,
        })
      }
    } catch (error) {
      toast.error("Error", {
        description: "An error occurred during removal",
      })
    } finally {
      setRemoving(false)
    }
  }

  const getThreatColor = (level: string) => {
    switch (level) {
      case "critical": return "from-red-600 to-pink-600"
      case "high": return "from-orange-600 to-red-600"
      case "medium": return "from-yellow-600 to-orange-600"
      case "low": return "from-blue-600 to-cyan-600"
      default: return "from-gray-600 to-slate-600"
    }
  }

  const getThreatBadge = (level: string) => {
    switch (level) {
      case "critical":
        return <Badge className="bg-red-500/20 text-red-400 border-red-500/30 text-lg px-4 py-1">CRITICAL</Badge>
      case "high":
        return <Badge className="bg-orange-500/20 text-orange-400 border-orange-500/30 text-lg px-4 py-1">HIGH</Badge>
      case "medium":
        return <Badge className="bg-yellow-500/20 text-yellow-400 border-yellow-500/30 text-lg px-4 py-1">MEDIUM</Badge>
      case "low":
        return <Badge className="bg-blue-500/20 text-blue-400 border-blue-500/30 text-lg px-4 py-1">LOW</Badge>
      default:
        return <Badge className="bg-gray-500/20 text-gray-400 border-gray-500/30 text-lg px-4 py-1">MINIMAL</Badge>
    }
  }

  return (
      <ProtectedRoute>
    <div className="container mx-auto p-6 space-y-6">
      {/* Header with Gradient */}
      <div className="relative overflow-hidden rounded-2xl bg-gradient-to-br from-red-600 via-pink-600 to-purple-600 p-8">
        <div className="absolute inset-0 bg-grid-white/10" />
        <div className="relative flex items-center justify-between">
          <div>
            <h1 className="text-4xl font-bold text-white flex items-center gap-3">
              <div className="p-3 bg-white/20 backdrop-blur-sm rounded-xl">
                <ShieldAlert className="h-8 w-8" />
              </div>
              Deep Quarantine
            </h1>
            <p className="text-white/90 mt-2 text-lg">
              Complete malware removal with multi-stage analysis
            </p>
          </div>
          <Button
            variant="secondary"
            className="bg-white/20 backdrop-blur-sm border-white/30 text-white hover:bg-white/30"
            onClick={() => setShowBackups(!showBackups)}
          >
            <History className="mr-2 h-4 w-4" />
            Backups ({backups.length})
          </Button>
        </div>
      </div>

      {/* Backups Panel */}
      {showBackups && (
        <Card className="border-red-500/30 bg-gradient-to-br from-red-500/10 to-transparent">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <History className="h-5 w-5 text-red-500" />
              Deep Quarantine Backups
            </CardTitle>
            <CardDescription>Comprehensive backups of removed threats</CardDescription>
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
                    className="p-4 border rounded-lg bg-gradient-to-br from-red-500/5 to-purple-500/5 hover:from-red-500/10 hover:to-purple-500/10 transition-all"
                  >
                    <div className="flex items-start justify-between">
                      <div className="flex-1">
                        <div className="flex items-center gap-2 mb-2">
                          <p className="font-medium">{backup.target_path}</p>
                          {getThreatBadge(backup.threat_level)}
                        </div>
                        <div className="flex items-center gap-3 text-xs text-muted-foreground">
                          <span>Risk: {backup.risk_score}</span>
                          <span>•</span>
                          <span>{new Date(backup.backed_up_at).toLocaleString()}</span>
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

      {/* Analysis Input */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Target className="h-5 w-5 text-red-500" />
            Target Analysis
          </CardTitle>
          <CardDescription>
            Select a file or enter a directory path for comprehensive malware analysis
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex gap-3">
            {/* File Upload Button */}
            <div className="flex-1">
              <label htmlFor="file-upload" className="cursor-pointer">
                <div className="flex items-center gap-2 px-4 py-2 border rounded-lg hover:bg-accent transition-colors">
                  <FileSearch className="h-4 w-4 text-muted-foreground" />
                  <span className="text-sm">
                    {targetPath ? targetPath : "Choose file to analyze..."}
                  </span>
                </div>
              </label>
              <input
                id="file-upload"
                type="file"
                className="hidden"
                onChange={(e) => {
                  const file = e.target.files?.[0]
                  if (file) {
                    setSelectedFile(file)
                    setTargetPath(file.name)
                  }
                }}
              />
            </div>
            
            {/* Manual Path Input (Optional) */}
            <div className="flex-1 relative">
              <Input
                placeholder="Or enter path: C:\Path\To\File.exe"
                value={targetPath}
                onChange={(e) => {
                  setTargetPath(e.target.value)
                  setSelectedFile(null) // Clear file selection when typing path
                }}
                onKeyDown={(e) => e.key === "Enter" && handleAnalyze()}
              />
            </div>
            
            <Button
              onClick={handleAnalyze}
              disabled={analyzing || (!selectedFile && !targetPath.trim())}
              className="bg-gradient-to-r from-red-600 to-pink-600 hover:from-red-700 hover:to-pink-700"
            >
              {analyzing ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  Analyzing...
                </>
              ) : (
                <>
                  <Search className="mr-2 h-4 w-4" />
                  Deep Analyze
                </>
              )}
            </Button>
          </div>

          {analysis && (
            <Alert className="border-red-500/50 bg-gradient-to-r from-red-500/10 to-pink-500/10">
              <AlertTriangle className="h-4 w-4 text-red-500" />
              <AlertDescription>
                <strong>Analysis Complete:</strong> Target analyzed across 4 stages. Review results below.
              </AlertDescription>
            </Alert>
          )}
        </CardContent>
      </Card>

      {/* Analysis Results */}
      {analysis && (
        <div className="space-y-6">
          {/* Threat Overview */}
          <Card className={`border-0 bg-gradient-to-br ${getThreatColor(analysis.threat_level)}`}>
            <CardContent className="p-8">
              <div className="flex items-center justify-between text-white">
                <div>
                  <p className="text-sm text-white/80 mb-2">Threat Assessment</p>
                  <h2 className="text-4xl font-bold mb-2">{analysis.threat_level.toUpperCase()}</h2>
                  <p className="text-white/90">{analysis.target_path}</p>
                </div>
                <div className="text-right">
                  <div className="text-6xl font-bold">{analysis.risk_score}</div>
                  <div className="text-sm text-white/80">Risk Score</div>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Multi-Stage Analysis */}
          <div className="grid gap-4 md:grid-cols-2">
            {/* Stage 1: File Analysis */}
            <Card className="border-red-500/30">
              <CardHeader>
                <CardTitle className="flex items-center gap-2 text-lg">
                  <FileSearch className="h-5 w-5 text-red-500" />
                  Stage 1: File Analysis
                </CardTitle>
              </CardHeader>
              <CardContent>
                {analysis.stages.file_analysis.status === "success" ? (
                  <div className="space-y-3">
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-muted-foreground">Type</span>
                      <Badge variant="outline">{analysis.stages.file_analysis.type}</Badge>
                    </div>
                    {analysis.stages.file_analysis.suspicious && (
                      <div>
                        <p className="text-sm text-muted-foreground mb-2">Indicators</p>
                        <div className="flex flex-wrap gap-1">
                          {analysis.stages.file_analysis.indicators.map((ind: string, idx: number) => (
                            <Badge key={idx} variant="outline" className="text-xs bg-red-500/10 border-red-500/30 text-red-400">
                              <AlertTriangle className="h-3 w-3 mr-1" />
                              {ind}
                            </Badge>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                ) : (
                  <p className="text-sm text-muted-foreground">No issues detected</p>
                )}
              </CardContent>
            </Card>

            {/* Stage 2: Registry */}
            <Card className="border-orange-500/30">
              <CardHeader>
                <CardTitle className="flex items-center gap-2 text-lg">
                  <Database className="h-5 w-5 text-orange-500" />
                  Stage 2: Registry Scan
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-muted-foreground">References Found</span>
                    <Badge variant={analysis.stages.registry_scan.has_references ? "destructive" : "outline"}>
                      {analysis.stages.registry_scan.related_entries || 0}
                    </Badge>
                  </div>
                  {analysis.stages.registry_scan.has_references ? (
                    <Alert variant="destructive">
                      <AlertDescription className="text-xs">
                        Found registry references to target
                      </AlertDescription>
                    </Alert>
                  ) : (
                    <p className="text-sm text-muted-foreground">No registry references</p>
                  )}
                </div>
              </CardContent>
            </Card>

            {/* Stage 3: Services */}
            <Card className="border-yellow-500/30">
              <CardHeader>
                <CardTitle className="flex items-center gap-2 text-lg">
                  <Settings className="h-5 w-5 text-yellow-500" />
                  Stage 3: Service Scan
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-muted-foreground">Dependencies Found</span>
                    <Badge variant={analysis.stages.service_scan.has_dependencies ? "destructive" : "outline"}>
                      {analysis.stages.service_scan.related_services || 0}
                    </Badge>
                  </div>
                  {analysis.stages.service_scan.has_dependencies ? (
                    <Alert variant="destructive">
                      <AlertDescription className="text-xs">
                        Found service dependencies
                      </AlertDescription>
                    </Alert>
                  ) : (
                    <p className="text-sm text-muted-foreground">No service dependencies</p>
                  )}
                </div>
              </CardContent>
            </Card>

            {/* Stage 4: Tasks */}
            <Card className="border-green-500/30">
              <CardHeader>
                <CardTitle className="flex items-center gap-2 text-lg">
                  <Clock className="h-5 w-5 text-green-500" />
                  Stage 4: Task Scan
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-muted-foreground">References Found</span>
                    <Badge variant={analysis.stages.task_scan.has_references ? "destructive" : "outline"}>
                      {analysis.stages.task_scan.related_tasks || 0}
                    </Badge>
                  </div>
                  {analysis.stages.task_scan.has_references ? (
                    <Alert variant="destructive">
                      <AlertDescription className="text-xs">
                        Found task references
                      </AlertDescription>
                    </Alert>
                  ) : (
                    <p className="text-sm text-muted-foreground">No task references</p>
                  )}
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Recommendations */}
          <Card className="border-purple-500/30">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Zap className="h-5 w-5 text-purple-500" />
                Removal Plan
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-2 mb-4">
                {analysis.recommendations.map((rec, idx) => (
                  <div key={idx} className="flex items-center gap-2 text-sm">
                    <ArrowRight className="h-4 w-4 text-purple-500" />
                    <span>{rec}</span>
                  </div>
                ))}
              </div>
              <Button
                onClick={handleRemove}
                disabled={removing}
                variant="destructive"
                className="w-full"
                size="lg"
              >
                {removing ? (
                  <>
                    <Loader2 className="mr-2 h-5 w-5 animate-spin" />
                    Removing...
                  </>
                ) : (
                  <>
                    <Trash2 className="mr-2 h-5 w-5" />
                    Complete Removal
                  </>
                )}
              </Button>
            </CardContent>
          </Card>
        </div>
      )}

      {/* Warning */}
      <Alert className="border-red-500/50 bg-gradient-to-r from-red-500/10 to-pink-500/10">
        <ShieldAlert className="h-4 w-4 text-red-500" />
        <AlertDescription>
          <strong>Deep Quarantine Warning:</strong> This performs comprehensive removal including registry entries, services, tasks, and files. Administrator privileges required. Always review analysis before removal.
        </AlertDescription>
      </Alert>
    </div>
    </ProtectedRoute>
  )
}