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

const COLORS = {
  primary: "#3b82f6",
  success: "#10b981",
  warning: "#f59e0b",
  danger: "#ef4444",
  purple: "#8b5cf6",
  cyan: "#06b6d4"
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

  return (
    <ProtectedRoute>
    <main className="pb-12">
      {/* Hero */}
      <div className="page-container page-hero pt-12 md:pt-16">
        <div>
          <h1 className="heading-accent gradient-cyber text-3xl md:text-4xl font-bold tracking-tight">
            Executive Dashboard
          </h1>
          <p className="mt-2 text-muted-foreground">
            High-level security overview and KPIs for decision makers
          </p>
        </div>
      </div>

      {/* Main Content */}
      <div className="section">
        <div className="page-container space-y-8">

          {/* KPI Cards Grid */}
          {kpis && (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
              
              {/* Security Score */}
              <div className="card-premium p-6 transition-all duration-300 hover:scale-105 hover:shadow-lg hover:shadow-blue-500/30">
                <div className="flex items-center justify-between mb-4">
                  <Shield className="h-8 w-8 text-blue-500" />
                  <div className={`text-4xl font-bold ${getScoreColor(kpis.security_score)}`}>
                    {kpis.security_score}
                  </div>
                </div>
                <div className="text-sm text-muted-foreground">Security Score</div>
                <div className="mt-2 h-2 bg-card rounded-full overflow-hidden">
                  <div 
                    className="h-full bg-blue-500 transition-all"
                    style={{ width: `${kpis.security_score}%` }}
                  />
                </div>
              </div>

              {/* Threats Blocked */}
              <div className="card-premium p-6 transition-all duration-300 hover:scale-105 hover:shadow-lg hover:shadow-green-500/30">
                <div className="flex items-center justify-between mb-4">
                  <CheckCircle2 className="h-8 w-8 text-green-500" />
                  <div className="text-4xl font-bold text-green-500">
                    {kpis.threats_blocked}
                  </div>
                </div>
                <div className="text-sm text-muted-foreground">Threats Blocked</div>
                <div className="text-xs text-green-400 mt-2">Last 30 days</div>
              </div>

              {/* Money Saved */}
              <div className="card-premium p-6 transition-all duration-300 hover:scale-105 hover:shadow-lg hover:shadow-yellow-500/30">
                <div className="flex items-center justify-between mb-4">
                  <DollarSign className="h-8 w-8 text-yellow-500" />
                  <div className="text-3xl font-bold text-yellow-500">
                    {formatCurrency(kpis.money_saved)}
                  </div>
                </div>
                <div className="text-sm text-muted-foreground">Money Saved</div>
                <div className="text-xs text-yellow-400 mt-2">Estimated ROI</div>
              </div>

              {/* AI Accuracy */}
              <div className="card-premium p-6 transition-all duration-300 hover:scale-105 hover:shadow-lg hover:shadow-purple-500/30">
                <div className="flex items-center justify-between mb-4">
                  <Target className="h-8 w-8 text-purple-500" />
                  <div className="text-4xl font-bold text-purple-500">
                    {kpis.ai_accuracy}%
                  </div>
                </div>
                <div className="text-sm text-muted-foreground">AI Accuracy</div>
                <div className="text-xs text-purple-400 mt-2">Prediction success rate</div>
              </div>

            </div>
          )}

          {/* Performance Metrics */}
          {kpis && (
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              
              {/* MTTD */}
              <div className="card-premium p-6">
                <div className="flex items-center gap-3 mb-3">
                  <Clock className="h-6 w-6 text-cyan-500" />
                  <div className="text-sm text-muted-foreground">Mean Time to Detect</div>
                </div>
                <div className="text-3xl font-bold text-cyan-500">
                  {kpis.mttd_minutes} min
                </div>
                <div className="text-xs text-muted-foreground mt-2">Average detection time</div>
              </div>

              {/* MTTR */}
              <div className="card-premium p-6">
                <div className="flex items-center gap-3 mb-3">
                  <TrendingUp className="h-6 w-6 text-orange-500" />
                  <div className="text-sm text-muted-foreground">Mean Time to Respond</div>
                </div>
                <div className="text-3xl font-bold text-orange-500">
                  {kpis.mttr_minutes} min
                </div>
                <div className="text-xs text-muted-foreground mt-2">Average response time</div>
              </div>

              {/* Active Honeypots */}
              <div className="card-premium p-6">
                <div className="flex items-center gap-3 mb-3">
                  <Activity className="h-6 w-6 text-pink-500" />
                  <div className="text-sm text-muted-foreground">Active Honeypots</div>
                </div>
                <div className="text-3xl font-bold text-pink-500">
                  {kpis.active_honeypots}
                </div>
                <div className="text-xs text-muted-foreground mt-2">Deception layers active</div>
              </div>

            </div>
          )}

          {/* Charts Grid */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            
            {/* Threat Distribution */}
            {threatDistribution.length > 0 && (
              <div className="card-premium p-6">
                <h2 className="text-xl font-semibold mb-6">Threat Distribution</h2>
                <ResponsiveContainer width="100%" height={300}>
                  <PieChart>
                    <Pie
                      data={threatDistribution}
                      dataKey="count"
                      nameKey="type"
                      cx="50%"
                      cy="50%"
                      outerRadius={100}
                      label
                    >
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

            {/* Severity Distribution */}
            {severityDistribution.length > 0 && (
              <div className="card-premium p-6">
                <h2 className="text-xl font-semibold mb-6">Severity Distribution</h2>
                <ResponsiveContainer width="100%" height={300}>
                  <BarChart data={severityDistribution}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                    <XAxis dataKey="severity" stroke="#9ca3af" />
                    <YAxis stroke="#9ca3af" />
                    <Tooltip 
                      contentStyle={{ backgroundColor: '#1f2937', border: '1px solid #374151' }}
                    />
                    <Bar dataKey="count" radius={[8, 8, 0, 0]}>
                      {severityDistribution.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={SEVERITY_COLORS[entry.severity] || COLORS.primary} />
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
                <span className={getRiskBadgeColor(riskAnalysis.risk_level)}>
                  {riskAnalysis.risk_level.toUpperCase()} RISK
                </span>
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

              {/* Recommendations */}
              {riskAnalysis.recommendations.length > 0 && (
                <div>
                  <h3 className="text-lg font-semibold mb-4">Executive Recommendations</h3>
                  <div className="space-y-3">
                    {riskAnalysis.recommendations.map((rec, idx) => (
                      <div key={idx} className="card-premium p-4 flex items-start gap-4">
                        <AlertTriangle className={`h-5 w-5 flex-shrink-0 mt-0.5 ${
                          rec.priority === 'critical' ? 'text-red-500' :
                          rec.priority === 'high' ? 'text-orange-500' :
                          'text-yellow-500'
                        }`} />
                        <div className="flex-1">
                          <div className="flex items-center gap-2 mb-1">
                            <h4 className="font-semibold">{rec.title}</h4>
                            <span className={`badge ${
                              rec.priority === 'critical' ? 'badge--err' :
                              rec.priority === 'high' ? 'badge--warn' :
                              'badge--info'
                            }`}>
                              {rec.priority}
                            </span>
                          </div>
                          <p className="text-sm text-muted-foreground mb-2">{rec.description}</p>
                          <div className="text-sm text-blue-400">
                            <strong>Action:</strong> {rec.action}
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
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