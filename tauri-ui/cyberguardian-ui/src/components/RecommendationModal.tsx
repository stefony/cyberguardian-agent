"use client";

import { X } from "lucide-react";
import { useState } from "react";

type Recommendation = {
  id: number;
  title: string;
  description: string;
  impact: string;
  roi_savings?: number;
  risk_reduction_pct?: number;
  implementation_hours?: number;
  complexity?: string;
  compliance?: string[];
  evidence_count?: number;
  evidence_timeframe?: string;
};

type Props = {
  recommendation: Recommendation | undefined;
  onClose: () => void;
};

export default function RecommendationModal({ recommendation, onClose }: Props) {
  const [activeTab, setActiveTab] = useState<'overview' | 'implementation' | 'compliance'>('overview');

  if (!recommendation) return null;

  return (
    <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center z-50 p-4">
      <div className="bg-slate-900 border border-slate-700 rounded-xl max-w-3xl w-full max-h-[80vh] overflow-hidden shadow-2xl">
        
        {/* Header */}
        <div className="flex items-start justify-between p-6 border-b border-slate-700">
          <div className="flex-1">
            <h2 className="text-2xl font-bold text-white mb-2">{recommendation.title}</h2>
            <p className="text-slate-400 text-sm">{recommendation.description}</p>
          </div>
          <button 
            onClick={onClose}
            className="ml-4 p-2 hover:bg-slate-800 rounded-lg transition-colors"
          >
            <X className="h-5 w-5 text-slate-400" />
          </button>
        </div>

        {/* Tabs */}
        <div className="flex gap-2 px-6 pt-4 border-b border-slate-700">
          <button
            onClick={() => setActiveTab('overview')}
            className={`px-4 py-2 text-sm font-medium rounded-t-lg transition-colors ${
              activeTab === 'overview' 
                ? 'bg-slate-800 text-cyan-400 border-b-2 border-cyan-400' 
                : 'text-slate-400 hover:text-slate-300'
            }`}
          >
            Overview
          </button>
          <button
            onClick={() => setActiveTab('implementation')}
            className={`px-4 py-2 text-sm font-medium rounded-t-lg transition-colors ${
              activeTab === 'implementation' 
                ? 'bg-slate-800 text-cyan-400 border-b-2 border-cyan-400' 
                : 'text-slate-400 hover:text-slate-300'
            }`}
          >
            Implementation
          </button>
          <button
            onClick={() => setActiveTab('compliance')}
            className={`px-4 py-2 text-sm font-medium rounded-t-lg transition-colors ${
              activeTab === 'compliance' 
                ? 'bg-slate-800 text-cyan-400 border-b-2 border-cyan-400' 
                : 'text-slate-400 hover:text-slate-300'
            }`}
          >
            Compliance
          </button>
        </div>

        {/* Content */}
        <div className="p-6 overflow-y-auto max-h-[calc(80vh-200px)]">
          
          {/* Overview Tab */}
          {activeTab === 'overview' && (
            <div className="space-y-6">
              {/* Metrics Grid */}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                {recommendation.roi_savings && recommendation.roi_savings > 0 && (
                  <div className="bg-green-500/10 border border-green-500/20 rounded-lg p-4">
                    <div className="text-xs text-green-400 mb-1">Annual Savings</div>
                    <div className="text-2xl font-bold text-green-500">
                      ${(recommendation.roi_savings / 1000).toFixed(0)}K
                    </div>
                  </div>
                )}
                
                {recommendation.risk_reduction_pct && recommendation.risk_reduction_pct > 0 && (
                  <div className="bg-purple-500/10 border border-purple-500/20 rounded-lg p-4">
                    <div className="text-xs text-purple-400 mb-1">Risk Reduction</div>
                    <div className="text-2xl font-bold text-purple-500">
                      {recommendation.risk_reduction_pct}%
                    </div>
                  </div>
                )}
                
                {recommendation.implementation_hours && recommendation.implementation_hours > 0 && (
                  <div className="bg-blue-500/10 border border-blue-500/20 rounded-lg p-4">
                    <div className="text-xs text-blue-400 mb-1">Time Estimate</div>
                    <div className="text-2xl font-bold text-blue-500">
                      {recommendation.implementation_hours}h
                    </div>
                  </div>
                )}
                
                {recommendation.complexity && (
                  <div className={`border rounded-lg p-4 ${
                    recommendation.complexity === 'low' ? 'bg-green-500/10 border-green-500/20' :
                    recommendation.complexity === 'medium' ? 'bg-yellow-500/10 border-yellow-500/20' :
                    'bg-red-500/10 border-red-500/20'
                  }`}>
                    <div className="text-xs text-slate-400 mb-1">Complexity</div>
                    <div className={`text-lg font-semibold capitalize ${
                      recommendation.complexity === 'low' ? 'text-green-500' :
                      recommendation.complexity === 'medium' ? 'text-yellow-500' :
                      'text-red-500'
                    }`}>
                      {recommendation.complexity}
                    </div>
                  </div>
                )}
              </div>

              {/* Impact */}
              <div className="bg-slate-800/50 border border-slate-700 rounded-lg p-4">
                <h3 className="text-sm font-semibold text-cyan-400 mb-2">Expected Impact</h3>
                <p className="text-slate-300">{recommendation.impact}</p>
              </div>

              {/* Evidence */}
              {recommendation.evidence_count && recommendation.evidence_count > 0 && (
                <div className="bg-cyan-500/10 border border-cyan-500/20 rounded-lg p-4">
                  <h3 className="text-sm font-semibold text-cyan-400 mb-2">Data-Driven Insight</h3>
                  <p className="text-slate-300">
                    This recommendation is based on analysis of <strong className="text-cyan-400">{recommendation.evidence_count.toLocaleString()} security events</strong> detected in your environment over the past {recommendation.evidence_timeframe}.
                  </p>
                </div>
              )}
            </div>
          )}

          {/* Implementation Tab */}
          {activeTab === 'implementation' && (
            <div className="space-y-4">
              <h3 className="text-lg font-semibold text-white mb-4">Implementation Guide</h3>
              
              <div className="space-y-3">
                <div className="flex gap-3">
                  <div className="flex-shrink-0 w-8 h-8 bg-cyan-500/20 border border-cyan-500/30 rounded-full flex items-center justify-center text-cyan-400 font-semibold">
                    1
                  </div>
                  <div>
                    <h4 className="font-semibold text-white">Review Details</h4>
                    <p className="text-slate-400 text-sm">Carefully review the recommendation metrics including ROI, risk reduction, and complexity level.</p>
                  </div>
                </div>

                <div className="flex gap-3">
                  <div className="flex-shrink-0 w-8 h-8 bg-cyan-500/20 border border-cyan-500/30 rounded-full flex items-center justify-center text-cyan-400 font-semibold">
                    2
                  </div>
                  <div>
                    <h4 className="font-semibold text-white">Plan Deployment</h4>
                    <p className="text-slate-400 text-sm">Schedule implementation within your change management process. Estimated time: {recommendation.implementation_hours || 'N/A'} hours.</p>
                  </div>
                </div>

                <div className="flex gap-3">
                  <div className="flex-shrink-0 w-8 h-8 bg-cyan-500/20 border border-cyan-500/30 rounded-full flex items-center justify-center text-cyan-400 font-semibold">
                    3
                  </div>
                  <div>
                    <h4 className="font-semibold text-white">Test in Staging</h4>
                    <p className="text-slate-400 text-sm">Deploy to a non-production environment first to validate functionality and identify potential issues.</p>
                  </div>
                </div>

                <div className="flex gap-3">
                  <div className="flex-shrink-0 w-8 h-8 bg-cyan-500/20 border border-cyan-500/30 rounded-full flex items-center justify-center text-cyan-400 font-semibold">
                    4
                  </div>
                  <div>
                    <h4 className="font-semibold text-white">Deploy to Production</h4>
                    <p className="text-slate-400 text-sm">Roll out the changes to your production environment following your organization's deployment procedures.</p>
                  </div>
                </div>

                <div className="flex gap-3">
                  <div className="flex-shrink-0 w-8 h-8 bg-cyan-500/20 border border-cyan-500/30 rounded-full flex items-center justify-center text-cyan-400 font-semibold">
                    5
                  </div>
                  <div>
                    <h4 className="font-semibold text-white">Monitor & Validate</h4>
                    <p className="text-slate-400 text-sm">Track the security improvements and validate that the expected risk reduction is achieved.</p>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Compliance Tab */}
          {activeTab === 'compliance' && (
            <div className="space-y-4">
              <h3 className="text-lg font-semibold text-white mb-4">Compliance & Standards</h3>
              
              {recommendation.compliance && recommendation.compliance.length > 0 ? (
                <div className="space-y-3">
                  <p className="text-slate-400">This recommendation helps you meet requirements from the following frameworks:</p>
                  
                  <div className="space-y-2">
                    {recommendation.compliance.map((framework, idx) => (
                      <div key={idx} className="bg-slate-800/50 border border-slate-700 rounded-lg p-3 flex items-center gap-3">
                        <div className="flex-shrink-0 w-8 h-8 bg-cyan-500/20 rounded-full flex items-center justify-center">
                          <span className="text-cyan-400">✓</span>
                        </div>
                        <span className="text-white font-medium">{framework}</span>
                      </div>
                    ))}
                  </div>
                </div>
              ) : (
                <div className="bg-slate-800/50 border border-slate-700 rounded-lg p-4 text-center">
                  <p className="text-slate-400">No specific compliance frameworks mapped for this recommendation.</p>
                </div>
              )}
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="flex gap-3 p-6 border-t border-slate-700 bg-slate-800/50">
          <button
            onClick={onClose}
            className="flex-1 px-4 py-2 bg-slate-700 hover:bg-slate-600 text-white rounded-lg transition-colors"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
}