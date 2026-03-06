"use client"

import { useEffect, useState } from "react"
import {
  Shield,
  TrendingUp,
  DollarSign,
  Clock,
  Target,
  Activity,
  AlertTriangle,
  CheckCircle2
} from "lucide-react"
import { api } from "@/lib/api"
import { PieChart, Pie, Cell, ResponsiveContainer, Legend, Tooltip, BarChart, Bar, XAxis, YAxis, CartesianGrid } from "recharts"
import ProtectedRoute from '@/components/ProtectedRoute';

// Types
type KPIs = {
  security_score: number
  threats_blocked: number
  money_saved: number
  mttr_minutes: number
  mttd_minutes: number
  active_honeypots: number
  ai_accuracy: number
}

type Statistics = {
  total_threats: number
  critical_threats: number
  block_rate: number
}

type ThreatDistribution = {
  type: string
  count: number
}

type SeverityDistribution = {
  severity: string
  count: number
}

type RiskAnalysis = {
  risk_level: string
  risk_score: number
  factors: {
    critical_threats: number
    unresolved_threats: number
  }
  recommendations: Array<{
    priority: string
    title: string
    description: string
    action: string
  }>
}

type NIS2Control = {
  label: string
  score: number
  article: string
  status: "ok" | "warning" | "critical"
}

const COLORS = {
  primary: "#3b82f6",
  success: "#10b981",
  warning: "#f59e0b",
  danger: "#ef4444",
  purple: "#8b5cf6",
  cyan: "#06b6d4"
}

// Изчислява NIS2 controls от реални backend данни
function computeNIS2Controls(kpis: KPIs | null, statistics: Statistics | null): NIS2Control[] {
  const blockRate = statistics?.block_rate ?? 0
  const securityScore = kpis?.security_score ?? 0
  const mttr = kpis?.mttr_minutes ?? 999
  const mttd = kpis?.mttd_minutes ?? 999
  const aiAccuracy = kpis?.ai_accuracy ?? 0

  // Incident Response score — под 30 мин = 100%, 60 мин = 80%, 120 мин = 60%
  const incidentResponseScore = Math.max(0, Math.min(100, Math.round(100 - (mttr / 120) * 40)))

  // Incident Detection score — от block_rate
  const incidentDetectionScore = Math.min(100, Math.round(blockRate))

  // Logging & Monitoring — от security_score
  const loggingScore = Math.min(100, Math.round(securityScore * 1.05))

  // Supply Chain — от ai_accuracy (ML detection coverage)
  const supplyChainScore = Math.min(100, Math.round(aiAccuracy * 0.8))

  // Access Control — от security_score
  const accessControlScore = Math.min(100, Math.round(securityScore * 0.9))

  // Vulnerability — от mttd (под 5 мин = 95%, 30 мин = 70%)
  const vulnerabilityScore = Math.max(0, Math.min(100, Math.round(100 - (mttd / 30) * 30)))

  const controls: NIS2Control[] = [
    {
      label: "Logging & Monitoring",
      score: loggingScore,
      article: "Art. 21(2)(g)",
      status: loggingScore >= 80 ? "ok" : loggingScore >= 60 ? "warning" : "critical",
    },
    {
      label: "Incident Detection",
      score: incidentDetectionScore,
      article: "Art. 21(2)(a)",
      status: incidentDetectionScore >= 80 ? "ok" : incidentDetectionScore >= 60 ? "warning" : "critical",
    },
    {
      label: "Incident Response",
      score: incidentResponseScore,
      article: "Art. 21(2)(c)",
      status: incidentResponseScore >= 80 ? "ok" : incidentResponseScore >= 60 ? "warning" : "critical",
    },
    {
      label: "Vulnerability Management",
      score: vulnerabilityScore,
      article: "Art. 21(2)(e)",
      status: vulnerabilityScore >= 80 ? "ok" : vulnerabilityScore >= 60 ? "warning" : "critical",
    },
    {
      label: "Supply Chain Security",
      score: supplyChainScore,
      article: "Art. 21(2)(d)",
      status: supplyChainScore >= 80 ? "ok" : supplyChainScore >= 60 ? "warning" : "critical",
    },
    {
      label: "Access Control",
      score: accessControlScore,
      article: "Art. 21(2)(i)",
      status: accessControlScore >= 80 ? "ok" : accessControlScore >= 60 ? "warning" : "critical",
    },
  ]

  return controls
}

export default function ExecutiveDashboardPage() {
  const [kpis, setKpis] = useState<KPIs | null>(null)
  const [statistics, setStatistics] = useState<Statistics | null>(null)
  const [threatDistribution, setThreatDistribution] = useState<ThreatDistribution[]>([])
  const [severityDistribution, setSeverityDistribution] = useState<SeverityDistribution[]>([])
  const [riskAnalysis, setRiskAnalysis] = useState<RiskAnalysis | null>(null)
  const [isLoading, setIsLoading] = useState(true)

  useEffect(() => {
    const fetchData = async () => {
      try {
        setIsLoading(true)

        const [overviewRes, trendsRes, riskRes] = await Promise.all([
          api.executive.getOverview(),
          api.executive.getTrends(30),
          api.executive.getRiskAnalysis()
        ])

        if (overviewRes.success && overviewRes.data) {
          setKpis(overviewRes.data.kpis)
          setStatistics(overviewRes.data.statistics)
        }

        if (trendsRes.success && trendsRes.data) {
          setThreatDistribution(trendsRes.data.trends.threat_distribution)
          setSeverityDistribution(trendsRes.data.trends.severity_distribution)
        }

        if (riskRes.success && riskRes.data) {
          setRiskAnalysis(riskRes.data)
        }
      } catch (err) {
        console.error("Error fetching executive data:", err)
      } finally {
        setIsLoading(false)
      }
    }

    fetchData()
  }, [])

  const getScoreColor = (score: number) => {
    if (score >= 80) return "text-green-500"
    if (score >= 60) return "text-yellow-500"
    if (score >= 40) return "text-orange-500"
    return "text-red-500"
  }

  const getRiskBadgeColor = (level: string) => {
    const colors: Record<string, string> = {
      low: "badge badge--ok",
      medium: "badge badge--warn",
      high: "badge badge--err"
    }
    return colors[level] || "badge"
  }

  const formatCurrency = (value: number) => {
    return new Intl.NumberFormat('en-US', {
      style: 'currency',
      currency: 'EUR',
      minimumFractionDigits: 0,
      maximumFractionDigits: 0
    }).format(value)
  }

  const SEVERITY_COLORS: Record<string, string> = {
    critical: COLORS.danger,
    high: COLORS.warning,
    medium: COLORS.primary,
    low: COLORS.success
  }

  // Динамични NIS2 данни
  const nis2Controls = computeNIS2Controls(kpis, statistics)
  const nis2Score = nis2Controls.length > 0
    ? Math.round(nis2Controls.reduce((sum, c) => sum + c.score, 0) / nis2Controls.length)
    : 0
  const nis2Passed = nis2Controls.filter(c => c.status === "ok").length
  const nis2RiskLevel = nis2Score >= 80 ? "LOW" : nis2Score >= 60 ? "MEDIUM" : "HIGH"
  const nis2RiskColor = nis2Score >= 80 ? "text-green-400" : nis2Score >= 60 ? "text-yellow-400" : "text-red-400"

  const worstControl = [...nis2Controls].sort((a, b) => a.score - b.score)[0]
  const bestControl = [...nis2Controls].sort((a, b) => b.score - a.score)[0]
  const warningControl = nis2Controls.find(c => c.status === "warning")

  return (
    <ProtectedRoute>
      <main className="pb-12">
        {/* Hero */}
        <div className="page-container page-hero pt-12 md:pt-16 px-6">
          <div>
            <h1 className="text-3xl md:text-4xl font-bold tracking-tight bg-gradient-to-r from-cyan-400 via-blue-500 to-purple-500 bg-clip-text text-transparent">
              Executive Dashboard
            </h1>
            <p className="mt-2 text-muted-foreground">
              High-level security overview and KPIs for decision makers
            </p>
          </div>
        </div>

        {/* Main Content */}
        <div className="section">
          <div className="page-container space-y-6 px-6">

            {/* KPI Cards Grid */}
            {kpis && (
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">

                <div className="card-premium p-6 transition-all duration-300 hover:scale-105 hover:shadow-lg hover:shadow-blue-500/30">
                  <div className="flex items-center justify-between mb-4">
                    <Shield className="h-8 w-8 text-blue-500" />
                    <div className={`text-5xl font-bold ${getScoreColor(kpis.security_score)}`}>
                      {kpis.security_score}
                    </div>
                  </div>
                  <div className="text-sm text-muted-foreground">Security Score</div>
                  <div className="mt-2 h-2 bg-card rounded-full overflow-hidden">
                    <div className="h-full bg-blue-500 transition-all" style={{ width: `${kpis.security_score}%` }} />
                  </div>
                </div>

                <div className="card-premium p-6 transition-all duration-300 hover:scale-105 hover:shadow-lg hover:shadow-green-500/30">
                  <div className="flex items-center justify-between mb-4">
                    <CheckCircle2 className="h-8 w-8 text-green-500" />
                    <div className="text-5xl font-bold text-green-500">{kpis.threats_blocked}</div>
                  </div>
                  <div className="text-sm text-muted-foreground">Threats Blocked</div>
                  <div className="text-xs text-green-400 mt-2">Last 30 days</div>
                </div>

                <div className="card-premium p-6 transition-all duration-300 hover:scale-105 hover:shadow-lg hover:shadow-yellow-500/30">
                  <div className="flex items-center justify-between mb-4">
                    <DollarSign className="h-8 w-8 text-yellow-500" />
                    <div className="text-5xl font-bold text-yellow-500">{formatCurrency(kpis.money_saved)}</div>
                  </div>
                  <div className="text-sm text-muted-foreground">Money Saved</div>
                  <div className="text-xs text-yellow-400 mt-2">Estimated ROI</div>
                </div>

                <div className="card-premium p-6 transition-all duration-300 hover:scale-105 hover:shadow-lg hover:shadow-purple-500/30">
                  <div className="flex items-center justify-between mb-4">
                    <Target className="h-8 w-8 text-purple-500" />
                    <div className="text-5xl font-bold text-purple-500">{kpis.ai_accuracy}%</div>
                  </div>
                  <div className="text-sm text-muted-foreground">AI Accuracy</div>
                  <div className="text-xs text-purple-400 mt-2">Prediction success rate</div>
                </div>

              </div>
            )}

            {/* Performance Metrics */}
            {kpis && (
              <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                <div className="card-premium p-6">
                  <div className="flex items-center gap-3 mb-3">
                    <Clock className="h-6 w-6 text-cyan-500" />
                    <div className="text-sm text-muted-foreground">Mean Time to Detect</div>
                  </div>
                  <div className="text-4xl font-bold text-cyan-500">{kpis.mttd_minutes} min</div>
                  <div className="text-xs text-muted-foreground mt-2">Average detection time</div>
                </div>

                <div className="card-premium p-6">
                  <div className="flex items-center gap-3 mb-3">
                    <TrendingUp className="h-6 w-6 text-orange-500" />
                    <div className="text-sm text-muted-foreground">Mean Time to Respond</div>
                  </div>
                  <div className="text-4xl font-bold text-orange-500">{kpis.mttr_minutes} min</div>
                  <div className="text-xs text-muted-foreground mt-2">Average response time</div>
                </div>

                <div className="card-premium p-6">
                  <div className="flex items-center gap-3 mb-3">
                    <Activity className="h-6 w-6 text-pink-500" />
                    <div className="text-sm text-muted-foreground">Active Honeypots</div>
                  </div>
                  <div className="text-4xl font-bold text-pink-500">{kpis.active_honeypots}</div>
                  <div className="text-xs text-muted-foreground mt-2">Deception layers active</div>
                </div>
              </div>
            )}

            {/* Charts Grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              {threatDistribution.length > 0 && (
                <div className="card-premium p-6">
                  <h2 className="text-xl font-semibold mb-6">Threat Distribution</h2>
                  <ResponsiveContainer width="95%" height={300}>
                    <PieChart>
                      <Pie data={threatDistribution} dataKey="count" nameKey="type" cx="50%" cy="50%" outerRadius={100} label>
                        {threatDistribution.map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={Object.values(COLORS)[index % Object.values(COLORS).length]} />
                        ))}
                      </Pie>
                      <Tooltip />
                      <Legend />
                    </PieChart>
                  </ResponsiveContainer>
                </div>
              )}

              {severityDistribution.length > 0 && (
                <div className="card-premium p-6">
                  <h2 className="text-xl font-semibold mb-6">Severity Distribution</h2>
                  <ResponsiveContainer width="95%" height={300}>
                    <BarChart data={severityDistribution}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                      <XAxis dataKey="severity" stroke="#9ca3af" />
                      <YAxis stroke="#9ca3af" />
                      <Tooltip contentStyle={{ backgroundColor: '#1f2937', border: '1px solid #374151' }} />
                      <Bar dataKey="count" radius={[8, 8, 0, 0]}>
                        {severityDistribution.map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={SEVERITY_COLORS[entry.severity.toLowerCase()] || COLORS.primary} />
                        ))}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              )}
            </div>

            {/* Risk Analysis */}
            {riskAnalysis && (
              <div className="card-premium p-6">
                <div className="flex items-center justify-between mb-6">
                  <h2 className="text-xl font-semibold">Risk Analysis</h2>
                  <div className="relative">
                    {riskAnalysis.risk_level.toLowerCase() === 'low' && <div className="absolute inset-0 blur-xl rounded-full bg-green-500/60 animate-pulse"></div>}
                    {riskAnalysis.risk_level.toLowerCase() === 'medium' && <div className="absolute inset-0 blur-xl rounded-full bg-yellow-500/60 animate-pulse"></div>}
                    {riskAnalysis.risk_level.toLowerCase() === 'high' && <div className="absolute inset-0 blur-xl rounded-full bg-red-500/60 animate-pulse"></div>}
                    <span className={`relative ${getRiskBadgeColor(riskAnalysis.risk_level.toLowerCase())}`}>
                      {riskAnalysis.risk_level.toUpperCase()} RISK
                    </span>
                  </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-6">
                  <div>
                    <div className="text-sm text-muted-foreground mb-2">Risk Score</div>
                    <div className="text-3xl font-bold text-orange-500">{riskAnalysis.risk_score}/100</div>
                  </div>
                  <div>
                    <div className="text-sm text-muted-foreground mb-2">Critical Threats</div>
                    <div className="text-3xl font-bold text-red-500">{riskAnalysis.factors.critical_threats}</div>
                  </div>
                  <div>
                    <div className="text-sm text-muted-foreground mb-2">Unresolved Threats</div>
                    <div className="text-3xl font-bold text-yellow-500">{riskAnalysis.factors.unresolved_threats}</div>
                  </div>
                </div>

                {riskAnalysis.recommendations.length > 0 && (
                  <div>
                    <h3 className="text-lg font-semibold mb-4">Executive Recommendations</h3>
                    <div className="space-y-3">
                      {riskAnalysis.recommendations.map((rec, idx) => (
                        <div key={idx} className="card-premium p-4 flex items-start gap-4">
                          <AlertTriangle className={`h-5 w-5 flex-shrink-0 mt-0.5 ${
                            rec.priority === 'critical' ? 'text-red-500' :
                            rec.priority === 'high' ? 'text-orange-500' : 'text-yellow-500'
                          }`} />
                          <div className="flex-1">
                            <div className="flex items-center gap-2 mb-1">
                              <h4 className="font-semibold">{rec.title}</h4>
                              <span className={`badge ${
                                rec.priority === 'critical' ? 'badge--err' :
                                rec.priority === 'high' ? 'badge--warn' : 'badge--info'
                              }`}>
                                {rec.priority}
                              </span>
                            </div>
                            <p className="text-sm text-muted-foreground mb-2">{rec.description}</p>
                            <div className="text-sm text-blue-400"><strong>Action:</strong> {rec.action}</div>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* NIS2 Board Risk Section — динамични данни от backend */}
            {kpis && statistics && (
              <div className="card-premium p-6 border border-blue-500/20">
                <div className="flex items-center justify-between mb-6">
                  <div>
                    <div className="flex items-center gap-3 mb-1">
                      <h2 className="text-xl font-semibold">NIS2 Board Risk Overview</h2>
                      <span className="px-2 py-0.5 rounded-full text-xs font-bold bg-blue-500/20 text-blue-400 border border-blue-500/30">
                        ДВ бр.17 / 2026
                      </span>
                    </div>
                    <p className="text-sm text-muted-foreground">Executive summary for board-level NIS2 compliance</p>
                  </div>
                  <a href="/nis2" className="px-4 py-2 text-sm bg-purple-500/10 text-purple-400 border border-purple-500/30 rounded-lg hover:bg-purple-500/20 transition-colors">
                    Full NIS2 Report →
                  </a>
                </div>

                <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
                  <div className="p-4 rounded-lg bg-green-500/5 border border-green-500/20 text-center">
                    <div className={`text-3xl font-bold ${getScoreColor(nis2Score)}`}>{nis2Score}%</div>
                    <div className="text-xs text-muted-foreground mt-1">NIS2 Compliance</div>
                  </div>
                  <div className="p-4 rounded-lg bg-yellow-500/5 border border-yellow-500/20 text-center">
                    <div className={`text-3xl font-bold ${nis2RiskColor}`}>{nis2RiskLevel}</div>
                    <div className="text-xs text-muted-foreground mt-1">Cyber Risk Level</div>
                  </div>
                  <div className="p-4 rounded-lg bg-red-500/5 border border-red-500/20 text-center">
                    <div className="text-3xl font-bold text-red-400">€10M</div>
                    <div className="text-xs text-muted-foreground mt-1">Max Fine Exposure</div>
                  </div>
                  <div className="p-4 rounded-lg bg-blue-500/5 border border-blue-500/20 text-center">
                    <div className="text-3xl font-bold text-blue-400">{nis2Passed}/{nis2Controls.length}</div>
                    <div className="text-xs text-muted-foreground mt-1">Controls Passed</div>
                  </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  {worstControl && (
                    <div className="p-4 rounded-lg bg-red-500/5 border border-red-500/20">
                      <div className="text-xs font-bold text-red-400 mb-2">⚠ ACTION REQUIRED</div>
                      <div className="text-sm font-medium">{worstControl.label}</div>
                      <div className="text-xs text-muted-foreground mt-1">{worstControl.score}% — {worstControl.article}</div>
                    </div>
                  )}
                  {warningControl && (
                    <div className="p-4 rounded-lg bg-yellow-500/5 border border-yellow-500/20">
                      <div className="text-xs font-bold text-yellow-400 mb-2">⚡ IMPROVEMENT NEEDED</div>
                      <div className="text-sm font-medium">{warningControl.label}</div>
                      <div className="text-xs text-muted-foreground mt-1">{warningControl.score}% — {warningControl.article}</div>
                    </div>
                  )}
                  {bestControl && (
                    <div className="p-4 rounded-lg bg-green-500/5 border border-green-500/20">
                      <div className="text-xs font-bold text-green-400 mb-2">✓ COMPLIANT</div>
                      <div className="text-sm font-medium">{bestControl.label}</div>
                      <div className="text-xs text-muted-foreground mt-1">{bestControl.score}% — {bestControl.article}</div>
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* Statistics Summary */}
            {statistics && (
              <div className="card-premium p-6">
                <h2 className="text-xl font-semibold mb-6">Security Summary (Last 30 Days)</h2>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                  <div>
                    <div className="text-sm text-muted-foreground mb-2">Total Threats Detected</div>
                    <div className="text-3xl font-bold">{statistics.total_threats}</div>
                  </div>
                  <div>
                    <div className="text-sm text-muted-foreground mb-2">Critical Threats</div>
                    <div className="text-3xl font-bold text-red-500">{statistics.critical_threats}</div>
                  </div>
                  <div>
                    <div className="text-sm text-muted-foreground mb-2">Block Rate</div>
                    <div className="text-3xl font-bold text-green-500">{statistics.block_rate}%</div>
                  </div>
                </div>
              </div>
            )}

          </div>
        </div>
      </main>
    </ProtectedRoute>
  )
}