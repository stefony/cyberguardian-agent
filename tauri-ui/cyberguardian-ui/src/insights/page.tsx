"use client";

import { useEffect, useState } from "react";
import { Brain, TrendingUp, AlertCircle, Lightbulb, Activity, Shield, FileText } from "lucide-react";
import { aiApi } from "@/lib/api";
import LiveThreatFeed from "@/components/LiveThreatFeed";
import ReportGenerator from "@/components/ReportGenerator";
import ProtectedRoute from '@/components/ProtectedRoute';

// Types
type Prediction = {
  threat_type: string;
  probability: number;
  timeframe: string;
  severity: string;
  confidence: number;
};

type RiskScore = {
  overall_score: number;
  trend: string;
  factors: Record<string, number>;
};

type Recommendation = {
  id: number;
  priority: string;
  category: string;
  title: string;
  description: string;
  impact: string;
  // ✅ NEW FIELDS - ФАЗА 1
  roi_savings?: number;
  risk_reduction_pct?: number;
  implementation_hours?: number;
  complexity?: string;
  compliance?: string[];
  evidence_count?: number;
  evidence_timeframe?: string;
};

type AIStatus = {
  ai_engine_status: string;
  models_loaded: number;
  last_analysis: string;
  predictions_accuracy: number;
};

export default function AIInsightsPage() {
  const [predictions, setPredictions] = useState<Prediction[]>([]);
  const [riskScore, setRiskScore] = useState<RiskScore | null>(null);
  const [recommendations, setRecommendations] = useState<Recommendation[]>([]);
  
  // PHASE 2 - Filter, Sort, Search States
const [filterPriority, setFilterPriority] = useState<string>('all');
const [sortBy, setSortBy] = useState<string>('priority');
const [searchQuery, setSearchQuery] = useState<string>('');
const [expandedRecs, setExpandedRecs] = useState<Set<number>>(new Set());
const [recStatuses, setRecStatuses] = useState<Record<number, string>>({});
  const [status, setStatus] = useState<AIStatus | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [isReportModalOpen, setIsReportModalOpen] = useState(false);

  useEffect(() => {
    const fetchData = async () => {
      try {
        setIsLoading(true);
        
        const [statusRes, predictionsRes, riskRes, recsRes] = await Promise.all([
          aiApi.getStatus(),
          aiApi.getPredictions(),
          aiApi.getRiskScore(),
          aiApi.getRecommendations()
        ]);

        if (statusRes.success) {
          setStatus(statusRes.data || null);
        }

        if (predictionsRes.success) {
          setPredictions(predictionsRes.data || []);
        }

        if (riskRes.success) {
          setRiskScore(riskRes.data || null);
        }

        if (recsRes.success) {
          setRecommendations(recsRes.data || []);
        }
      } catch (err) {
        console.error("Error fetching AI data:", err);
        // No mock data fallback
      } finally {
        setIsLoading(false);
      }
    };

    fetchData();
  }, []);

  const getSeverityColor = (severity: string) => {
    const colors: Record<string, string> = {
      critical: "text-red-500",
      high: "text-orange-500",
      medium: "text-yellow-500",
      low: "text-blue-500"
    };
    return colors[severity] || "text-gray-500";
  };

  const getPriorityBadge = (priority: string) => {
    const badges: Record<string, string> = {
      critical: "badge badge--err",
      high: "badge badge--warn",
      medium: "badge badge--info",
      low: "badge"
    };
    return badges[priority] || "badge";
  };

  const getRiskColor = (score: number) => {
    if (score >= 75) return "text-red-500";
    if (score >= 50) return "text-orange-500";
    if (score >= 25) return "text-yellow-500";
    return "text-green-500";
  };

  return (
    <ProtectedRoute>
      <main className="pb-12">
        {/* Hero */}
        <div className="page-container page-hero pt-12 md:pt-16">
          <div className="flex items-center justify-between">
            <div>
              <h1 className="heading-accent gradient-cyber text-3xl md:text-4xl font-bold tracking-tight">
                AI Insights
              </h1>
              <p className="mt-2 text-muted-foreground">
                AI-powered threat predictions and intelligent security recommendations
              </p>
            </div>
            <button
              onClick={() => setIsReportModalOpen(true)}
              className="btn btn--accent flex items-center gap-2 hover:scale-105 transition-transform"
            >
              <FileText className="h-5 w-5" />
              Generate Report
            </button>
          </div>
        </div>

        {/* Main Content with Sidebar Layout */}
        <div className="section">
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
            
            {/* Left Column - Main Content */}
            <div className="lg:col-span-8 space-y-6">
              
              {/* Status Cards */}
              {status && (
                <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                  <div className="card-premium p-5 transition-all duration-300 hover:scale-105 hover:shadow-lg hover:shadow-purple-500/30">
                    <div className="flex items-center gap-3 mb-2">
                      <Brain className="h-5 w-5 text-purple-500" />
                      <div className="text-sm text-muted-foreground">AI Engine</div>
                    </div>
                    <div className="text-2xl font-bold text-purple-500">
                      {status.ai_engine_status}
                    </div>
                  </div>

                  <div className="card-premium p-5 transition-all duration-300 hover:scale-105 hover:shadow-lg hover:shadow-blue-500/30">
                    <div className="flex items-center gap-3 mb-2">
                      <Shield className="h-5 w-5 text-blue-500" />
                      <div className="text-sm text-muted-foreground">Models Loaded</div>
                    </div>
                    <div className="text-2xl font-bold text-blue-500">
                      {status.models_loaded}
                    </div>
                  </div>

                  <div className="card-premium p-5 transition-all duration-300 hover:scale-105 hover:shadow-lg hover:shadow-green-500/30">
                    <div className="flex items-center gap-3 mb-2">
                      <Activity className="h-5 w-5 text-green-500" />
                      <div className="text-sm text-muted-foreground">Accuracy</div>
                    </div>
                    <div className="text-2xl font-bold text-green-500">
                      {status.predictions_accuracy}%
                    </div>
                  </div>

                  <div className="card-premium p-5 transition-all duration-300 hover:scale-105 hover:shadow-lg hover:shadow-cyan-500/30">
                    <div className="flex items-center gap-3 mb-2">
                      <TrendingUp className="h-5 w-5 text-cyan-500" />
                      <div className="text-sm text-muted-foreground">Predictions</div>
                    </div>
                    <div className="text-2xl font-bold text-cyan-500">
                      {predictions.length}
                    </div>
                  </div>
                </div>
              )}

              {/* Risk Score */}
              {riskScore && (
                <div className="card-premium p-6">
                  <h2 className="text-xl font-semibold mb-6">Overall Risk Score</h2>
                  <div className="flex items-center gap-8 mb-6">
                    <div className="text-center">
                      <div className={`text-6xl font-bold ${getRiskColor(riskScore.overall_score)}`}>
                        {riskScore.overall_score}
                      </div>
                      <div className="text-sm text-muted-foreground mt-2">Risk Level</div>
                    </div>
                    <div className="flex-1">
                      <div className="space-y-3">
                        {Object.entries(riskScore.factors).map(([factor, score]) => (
                          <div key={factor}>
                            <div className="flex justify-between text-sm mb-1">
                              <span className="capitalize">{factor.replace(/_/g, " ")}</span>
                              <span className={getRiskColor(score)}>{score}</span>
                            </div>
                            <div className="h-2 bg-card rounded-full overflow-hidden">
                              <div
                                className={`h-full transition-all ${
                                  score >= 75 ? "bg-red-500" :
                                  score >= 50 ? "bg-orange-500" :
                                  score >= 25 ? "bg-yellow-500" : "bg-green-500"
                                }`}
                                style={{ width: `${score}%` }}
                              />
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                </div>
              )}

              {/* Threat Predictions */}
              <div className="card-premium p-6">
                <h2 className="text-xl font-semibold mb-6">Threat Predictions</h2>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {predictions.map((pred, idx) => (
                    <div key={idx} className="card-premium p-4 transition-all duration-300 hover:scale-105">
                      <div className="flex items-start justify-between mb-3">
                        <h3 className="font-semibold">{pred.threat_type}</h3>
                        <span className={`text-2xl font-bold ${getSeverityColor(pred.severity)}`}>
                          {Math.round(pred.probability * 100)}%
                        </span>
                      </div>
                      <div className="space-y-2 text-sm">
                        <div className="flex justify-between">
                          <span className="text-muted-foreground">Timeframe</span>
                          <span>{pred.timeframe}</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-muted-foreground">Confidence</span>
                          <span>{Math.round(pred.confidence * 100)}%</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-muted-foreground">Severity</span>
                          <span className={`badge ${
                            pred.severity === "critical" ? "badge--err" :
                            pred.severity === "high" ? "badge--warn" :
                            pred.severity === "medium" ? "badge--info" : "badge--ok"
                          }`}>
                            {pred.severity}
                          </span>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

             {/* AI Recommendations - ENHANCED */}
              <div className="card-premium p-6">
                <div className="flex items-center justify-between mb-6">
                  <h2 className="text-xl font-semibold flex items-center gap-2">
                    <Lightbulb className="h-5 w-5 text-yellow-500" />
                    AI Recommendations
                  </h2>
                </div>

                {/* Filter & Sort Controls */}
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
                  {/* Search */}
                  <input
                    type="text"
                    placeholder="Search recommendations..."
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    className="px-4 py-2 bg-slate-800/50 border border-slate-700 rounded-lg text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-cyan-500"
                  />
                  
                  {/* Priority Filter */}
                  <select
                    value={filterPriority}
                    onChange={(e) => setFilterPriority(e.target.value)}
                    className="px-4 py-2 bg-slate-800/50 border border-slate-700 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500"
                  >
                    <option value="all">All Priorities</option>
                    <option value="critical">Critical Only</option>
                    <option value="high">High Only</option>
                    <option value="medium">Medium Only</option>
                    <option value="low">Low Only</option>
                  </select>
                  
                  {/* Sort */}
                  <select
                    value={sortBy}
                    onChange={(e) => setSortBy(e.target.value)}
                    className="px-4 py-2 bg-slate-800/50 border border-slate-700 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500"
                  >
                    <option value="priority">Sort by Priority</option>
                    <option value="roi">Sort by ROI (High to Low)</option>
                    <option value="risk">Sort by Risk Reduction</option>
                    <option value="time">Sort by Implementation Time</option>
                  </select>
                </div>

                <div className="space-y-4">
                  {recommendations
                    .filter(rec => {
                      // Priority filter
                      if (filterPriority !== 'all' && rec.priority !== filterPriority) return false;
                      
                      // Search filter
                      if (searchQuery) {
                        const query = searchQuery.toLowerCase();
                        return rec.title.toLowerCase().includes(query) ||
                               rec.description.toLowerCase().includes(query) ||
                               rec.category.toLowerCase().includes(query);
                      }
                      
                      return true;
                    })
                    .sort((a, b) => {
                      if (sortBy === 'priority') {
                        const priorityOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
                        return priorityOrder[a.priority] - priorityOrder[b.priority];
                      }
                      if (sortBy === 'roi') return (b.roi_savings || 0) - (a.roi_savings || 0);
                      if (sortBy === 'risk') return (b.risk_reduction_pct || 0) - (a.risk_reduction_pct || 0);
                      if (sortBy === 'time') return (a.implementation_hours || 0) - (b.implementation_hours || 0);
                      return 0;
                    })
                    .map((rec) => (
                      <div key={rec.id} className="card-premium p-5 transition-all duration-300 hover:shadow-lg hover:shadow-purple-500/20">
                        <div className="flex items-start gap-4">
                          <AlertCircle className={`h-5 w-5 flex-shrink-0 mt-1 ${
                            rec.priority === "critical" ? "text-red-500" :
                            rec.priority === "high" ? "text-orange-500" :
                            rec.priority === "medium" ? "text-yellow-500" : "text-blue-500"
                          }`} />
                          <div className="flex-1">
                            {/* Header */}
                            <div className="flex items-start justify-between mb-3">
                              <div>
                                <h3 className="font-semibold text-lg">{rec.title}</h3>
                                <div className="flex gap-2 mt-1 flex-wrap">
                                  <span className={getPriorityBadge(rec.priority)}>
                                    {rec.priority}
                                  </span>
                                  <span className="badge">{rec.category}</span>
                                </div>
                              </div>
                            </div>

                            {/* Description */}
                            <p className="text-muted-foreground mb-3">{rec.description}</p>

                            {/* Evidence Citation */}
                            {rec.evidence_count && rec.evidence_count > 0 && (
                              <div className="text-xs text-cyan-400 mb-3 flex items-center gap-1">
                                <span className="font-mono">📊</span>
                                <span>Based on {rec.evidence_count.toLocaleString()} events in {rec.evidence_timeframe}</span>
                              </div>
                            )}

                            {/* Metrics Grid */}
                            <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-3">
                              {/* ROI Savings */}
                              {rec.roi_savings && rec.roi_savings > 0 && (
                                <div className="bg-green-500/10 border border-green-500/20 rounded-lg p-2">
                                  <div className="text-xs text-green-400 mb-1">Annual Savings</div>
                                  <div className="text-lg font-bold text-green-500">
                                    ${(rec.roi_savings / 1000).toFixed(0)}K
                                  </div>
                                </div>
                              )}

                              {/* Risk Reduction */}
                              {rec.risk_reduction_pct && rec.risk_reduction_pct > 0 && (
                                <div className="bg-purple-500/10 border border-purple-500/20 rounded-lg p-2">
                                  <div className="text-xs text-purple-400 mb-1">Risk Reduction</div>
                                  <div className="flex items-center gap-2">
                                    <div className="flex-1 h-2 bg-card rounded-full overflow-hidden">
                                      <div 
                                        className="h-full bg-gradient-to-r from-purple-500 to-pink-500 transition-all duration-1000 ease-out"
                                        style={{ width: `${rec.risk_reduction_pct}%` }}
                                      />
                                    </div>
                                    <span className="text-sm font-bold text-purple-500">{rec.risk_reduction_pct}%</span>
                                  </div>
                                </div>
                              )}

                              {/* Implementation Time */}
                              {rec.implementation_hours && rec.implementation_hours > 0 && (
                                <div className="bg-blue-500/10 border border-blue-500/20 rounded-lg p-2">
                                  <div className="text-xs text-blue-400 mb-1">Implementation</div>
                                  <div className="text-lg font-bold text-blue-500">
                                    {rec.implementation_hours}h
                                  </div>
                                </div>
                              )}

                              {/* Complexity */}
                              {rec.complexity && (
                                <div className={`border rounded-lg p-2 ${
                                  rec.complexity === 'low' ? 'bg-green-500/10 border-green-500/20' :
                                  rec.complexity === 'medium' ? 'bg-yellow-500/10 border-yellow-500/20' :
                                  'bg-red-500/10 border-red-500/20'
                                }`}>
                                  <div className="text-xs text-muted-foreground mb-1">Complexity</div>
                                  <div className={`text-sm font-semibold capitalize ${
                                    rec.complexity === 'low' ? 'text-green-500' :
                                    rec.complexity === 'medium' ? 'text-yellow-500' :
                                    'text-red-500'
                                  }`}>
                                    {rec.complexity}
                                  </div>
                                </div>
                              )}
                            </div>

                            {/* Impact */}
                            <div className="text-sm text-green-400 mb-3">
                              <strong>Impact:</strong> {rec.impact}
                            </div>

                           {/* Compliance Frameworks */}
                            {rec.compliance && rec.compliance.length > 0 && (
                              <div className="flex flex-wrap gap-1.5">
                                {rec.compliance.map((framework, idx) => (
                                  <span 
                                    key={idx}
                                    className="text-xs px-2 py-1 rounded-full bg-cyan-500/10 text-cyan-400 border border-cyan-500/20"
                                  >
                                    {framework}
                                  </span>
                                ))}
                              </div>
                            )}

                            {/* Action Buttons */}
                            <div className="flex gap-2 mt-4 pt-3 border-t border-slate-700/50">
                              <button className="px-3 py-1.5 bg-green-500/10 text-green-500 border border-green-500/30 rounded-lg text-sm font-medium hover:bg-green-500/20 transition-colors">
                                ✓ Implement
                              </button>
                              <button className="px-3 py-1.5 bg-blue-500/10 text-blue-500 border border-blue-500/30 rounded-lg text-sm font-medium hover:bg-blue-500/20 transition-colors">
                                📖 Learn More
                              </button>
                              <button className="px-3 py-1.5 bg-slate-500/10 text-slate-400 border border-slate-600/30 rounded-lg text-sm font-medium hover:bg-slate-500/20 transition-colors">
                                ✕ Dismiss
                              </button>
                            </div>
                          </div>
                        </div>
                      </div>
                    ))}
                </div>
              </div>
            </div>

            {/* Right Sidebar - Live Threat Feed */}
            <div className="lg:col-span-4">
              <div className="lg:sticky lg:top-6">
                <LiveThreatFeed />
              </div>
            </div>

          </div>
        </div>

        {/* Report Generator Modal */}
        <ReportGenerator 
          isOpen={isReportModalOpen} 
          onClose={() => setIsReportModalOpen(false)} 
        />
      </main>
    </ProtectedRoute>
  );
}