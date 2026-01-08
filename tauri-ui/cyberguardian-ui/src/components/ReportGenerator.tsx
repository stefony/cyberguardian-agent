'use client'

import { useState } from 'react'
import { X, FileText, Download, AlertCircle } from 'lucide-react'
import { api } from '@/lib/api'

interface ReportGeneratorProps {
  isOpen: boolean
  onClose: () => void
}

const REPORT_TYPES = [
  {
    id: 'executive-summary',
    name: 'Executive Security Summary',
    description: 'High-level overview for management',
    icon: '📊',
  },
  {
    id: 'pci-dss',
    name: 'PCI-DSS Compliance Report',
    description: 'Payment Card Industry compliance',
    icon: '💳',
  },
  {
    id: 'iso-27001',
    name: 'ISO 27001 Report',
    description: 'Information Security Management',
    icon: '🔒',
  },
  {
    id: 'gdpr',
    name: 'GDPR Compliance Report',
    description: 'Data Protection Regulation',
    icon: '🇪🇺',
  },
  {
    id: 'nis2',
    name: 'NIS2 Directive Report',
    description: 'Network & Information Security',
    icon: '🛡️',
  },
]

export default function ReportGenerator({ isOpen, onClose }: ReportGeneratorProps) {
  const [selectedReport, setSelectedReport] = useState<string>('executive-summary')
  const [isGenerating, setIsGenerating] = useState(false)
  const [error, setError] = useState<string | null>(null)

  if (!isOpen) return null

  const handleGenerate = async () => {
    try {
      setIsGenerating(true)
      setError(null)

      console.log('🔄 Generating report:', selectedReport)

      // Call API to generate report
      const blob = await api.reports.generateReport({
        report_type: selectedReport,
        date_from: null,
        date_to: null,
      })

      // Create download link
      const url = window.URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `CyberGuardian_${selectedReport.toUpperCase()}_${new Date().getTime()}.pdf`
      document.body.appendChild(a)
      a.click()
      window.URL.revokeObjectURL(url)
      document.body.removeChild(a)

      console.log('✅ Report downloaded successfully')

      // Close modal after successful generation
      setTimeout(() => {
        onClose()
      }, 500)
    } catch (err) {
      console.error('❌ Report generation failed:', err)
      setError(err instanceof Error ? err.message : 'Failed to generate report')
    } finally {
      setIsGenerating(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur-sm p-4">
      <div className="relative w-full max-w-2xl bg-slate-900 border border-slate-700 rounded-lg shadow-2xl flex flex-col max-h-[90vh]">
        {/* Header */}
        <div className="flex items-center justify-between p-6 border-b border-slate-700 flex-shrink-0">
          <div className="flex items-center gap-3">
            <FileText className="w-6 h-6 text-blue-400" />
            <h2 className="text-xl font-bold text-white">Generate Compliance Report</h2>
          </div>
          <button
            onClick={onClose}
            className="p-2 hover:bg-slate-800 rounded-lg transition-colors"
            disabled={isGenerating}
          >
            <X className="w-5 h-5 text-slate-400" />
          </button>
        </div>

        {/* Content - Scrollable */}
        <div className="p-6 space-y-6 overflow-y-auto flex-1">
          {/* Report Type Selection */}
          <div>
            <label className="block text-sm font-medium text-slate-300 mb-3">
              Select Report Type
            </label>
            <div className="grid grid-cols-1 gap-3">
              {REPORT_TYPES.map((report) => (
                <button
                  key={report.id}
                  onClick={() => setSelectedReport(report.id)}
                  disabled={isGenerating}
                  className={`p-4 rounded-lg border-2 transition-all text-left ${
                    selectedReport === report.id
                      ? 'border-blue-500 bg-blue-500/10'
                      : 'border-slate-700 bg-slate-800/50 hover:border-slate-600'
                  } ${isGenerating ? 'opacity-50 cursor-not-allowed' : ''}`}
                >
                  <div className="flex items-start gap-3">
                    <span className="text-2xl">{report.icon}</span>
                    <div className="flex-1">
                      <div className="font-semibold text-white">{report.name}</div>
                      <div className="text-sm text-slate-400 mt-1">{report.description}</div>
                    </div>
                    {selectedReport === report.id && (
                      <div className="w-5 h-5 rounded-full bg-blue-500 flex items-center justify-center">
                        <div className="w-2 h-2 bg-white rounded-full" />
                      </div>
                    )}
                  </div>
                </button>
              ))}
            </div>
          </div>

          {/* Error Message */}
          {error && (
            <div className="flex items-start gap-3 p-4 bg-red-500/10 border border-red-500/50 rounded-lg">
              <AlertCircle className="w-5 h-5 text-red-400 flex-shrink-0 mt-0.5" />
              <div>
                <div className="font-semibold text-red-400">Error</div>
                <div className="text-sm text-red-300 mt-1">{error}</div>
              </div>
            </div>
          )}

          {/* Info */}
          <div className="p-4 bg-blue-500/10 border border-blue-500/50 rounded-lg">
            <div className="text-sm text-blue-300">
              <strong>Report Period:</strong> Last 30 days
              <br />
              <strong>Format:</strong> PDF (Professional layout)
              <br />
              <strong>Data:</strong> Real-time from your dashboard
            </div>
          </div>
        </div>

        {/* Footer - Fixed at bottom */}
        <div className="flex items-center justify-end gap-3 p-6 border-t border-slate-700 flex-shrink-0">
          <button
            onClick={onClose}
            disabled={isGenerating}
            className="px-4 py-2 text-slate-300 hover:text-white hover:bg-slate-800 rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          >
            Cancel
          </button>
          <button
            onClick={handleGenerate}
            disabled={isGenerating}
            className="px-6 py-2 bg-blue-600 hover:bg-blue-700 text-white font-medium rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2"
          >
            {isGenerating ? (
              <>
                <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                Generating...
              </>
            ) : (
              <>
                <Download className="w-4 h-4" />
                Generate Report
              </>
            )}
          </button>
        </div>
      </div>
    </div>
  )
}