'use client'

import { useState, useEffect } from 'react'
import { api } from '@/lib/api'
import { Plus, Trash2, FolderOpen, FileCode, Cpu, Shield, AlertCircle, CheckCircle2 } from 'lucide-react'

export default function ExclusionsManager() {
  const [exclusions, setExclusions] = useState<any[]>([])
  const [loading, setLoading] = useState(false)
  const [type, setType] = useState('path')
  const [value, setValue] = useState('')
  const [reason, setReason] = useState('')
  const [message, setMessage] = useState<{ type: 'success' | 'error', text: string } | null>(null)

  useEffect(() => {
    loadExclusions()
  }, [])

  const loadExclusions = async () => {
    try {
      const response = await api.exclusions.getExclusions()
      if (response.success && response.data) {
        setExclusions(response.data)
      }
    } catch (error) {
      console.error('Failed to load exclusions:', error)
    }
  }

  const handleAdd = async () => {
    if (!value.trim()) return
    
    setLoading(true)
    setMessage(null)
    
    try {
      const response = await api.exclusions.addExclusion({
        type,
        value: value.trim(),
        reason: reason.trim() || undefined
      })

      if (response.success) {
        setValue('')
        setReason('')
        setMessage({ type: 'success', text: 'Exclusion added successfully!' })
        await loadExclusions()
        setTimeout(() => setMessage(null), 3000)
      }
    } catch (error: any) {
      setMessage({ type: 'error', text: error.message || 'Failed to add exclusion' })
    } finally {
      setLoading(false)
    }
  }

  const handleDelete = async (id: number) => {
    setLoading(true)
    try {
      const response = await api.exclusions.deleteExclusion(id)
      if (response.success) {
        setMessage({ type: 'success', text: 'Exclusion removed!' })
        await loadExclusions()
        setTimeout(() => setMessage(null), 3000)
      }
    } catch (error) {
      setMessage({ type: 'error', text: 'Failed to delete exclusion' })
    } finally {
      setLoading(false)
    }
  }

  const getIcon = (type: string) => {
    switch (type) {
      case 'path': return <FolderOpen className="w-5 h-5" />
      case 'extension': return <FileCode className="w-5 h-5" />
      case 'process': return <Cpu className="w-5 h-5" />
      default: return <Shield className="w-5 h-5" />
    }
  }

  const getTypeColor = (type: string) => {
    switch (type) {
      case 'path': return 'from-blue-500 to-cyan-500'
      case 'extension': return 'from-purple-500 to-pink-500'
      case 'process': return 'from-green-500 to-emerald-500'
      default: return 'from-gray-500 to-gray-600'
    }
  }

  const getPlaceholder = () => {
    switch (type) {
      case 'path': return 'e.g., C:\\Temp\\* or /var/log/*'
      case 'extension': return 'e.g., .tmp, .log, .bak'
      case 'process': return 'e.g., chrome.exe, steam.exe'
      default: return ''
    }
  }

  return (
    <div className="space-y-6">
      {/* Success/Error Message */}
      {message && (
        <div className={`p-4 rounded-xl border-2 backdrop-blur-sm animate-in slide-in-from-top-2 duration-300 ${
          message.type === 'success' 
            ? 'bg-green-500/10 border-green-500/30 text-green-400' 
            : 'bg-red-500/10 border-red-500/30 text-red-400'
        }`}>
          <div className="flex items-center gap-2">
            {message.type === 'success' ? (
              <CheckCircle2 className="w-5 h-5" />
            ) : (
              <AlertCircle className="w-5 h-5" />
            )}
            <span className="font-medium">{message.text}</span>
          </div>
        </div>
      )}

      {/* Add Form - PREMIUM DESIGN */}
      <div className="relative group">
        {/* Glow Effect */}
        <div className="absolute -inset-0.5 bg-gradient-to-r from-purple-600 to-cyan-600 rounded-xl opacity-20 group-hover:opacity-30 blur transition duration-300" />
        
        <div className="relative p-6 bg-dark-card/90 backdrop-blur-xl border border-dark-border/50 rounded-xl shadow-2xl">
          <div className="flex items-center gap-3 mb-6">
            <div className="p-2 bg-gradient-to-br from-purple-500 to-cyan-500 rounded-lg">
              <Plus className="w-5 h-5 text-white" />
            </div>
            <h3 className="text-xl font-bold bg-gradient-to-r from-purple-400 to-cyan-400 bg-clip-text text-transparent">
              Add New Exclusion
            </h3>
          </div>
          
          <div className="space-y-4">
            {/* Type Select - PREMIUM */}
            <div>
              <label className="block text-sm font-semibold text-gray-300 mb-2">
                Exclusion Type
              </label>
              <div className="relative">
                <select
                  value={type}
                  onChange={(e) => setType(e.target.value)}
                  className="w-full px-4 py-3 bg-dark-bg/50 backdrop-blur-sm border-2 border-dark-border/50 hover:border-purple-500/50 focus:border-purple-500 rounded-xl text-white font-medium cursor-pointer transition-all duration-300 appearance-none relative z-10"
                  style={{ colorScheme: 'dark' }}
                >
                  <option value="path">📁 File/Folder Path</option>
                  <option value="extension">📄 File Extension</option>
                  <option value="process">⚙️ Process Name</option>
                </select>
                <div className="absolute right-4 top-1/2 -translate-y-1/2 pointer-events-none">
                  <svg className="w-4 h-4 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                  </svg>
                </div>
              </div>
            </div>

            {/* Value Input - PREMIUM */}
            <div>
              <label className="block text-sm font-semibold text-gray-300 mb-2">
                Value to Exclude
              </label>
              <input
                type="text"
                value={value}
                onChange={(e) => setValue(e.target.value)}
                placeholder={getPlaceholder()}
                className="w-full px-4 py-3 bg-dark-bg/50 backdrop-blur-sm border-2 border-dark-border/50 hover:border-purple-500/50 focus:border-purple-500 rounded-xl text-white font-medium transition-all duration-300 placeholder:text-gray-500"
              />
            </div>

            {/* Reason Input - PREMIUM */}
            <div>
              <label className="block text-sm font-semibold text-gray-300 mb-2">
                Reason <span className="text-gray-500">(optional)</span>
              </label>
              <input
                type="text"
                value={reason}
                onChange={(e) => setReason(e.target.value)}
                placeholder="Why should this be excluded?"
                className="w-full px-4 py-3 bg-dark-bg/50 backdrop-blur-sm border-2 border-dark-border/50 hover:border-purple-500/50 focus:border-purple-500 rounded-xl text-white font-medium transition-all duration-300 placeholder:text-gray-500"
              />
            </div>

            {/* Add Button - PREMIUM & GUARANTEED WORKING */}
            <button
              onClick={handleAdd}
              disabled={loading || !value.trim()}
              className="group/btn relative w-full px-6 py-4 bg-gradient-to-r from-purple-600 to-cyan-600 hover:from-purple-500 hover:to-cyan-500 disabled:from-gray-600 disabled:to-gray-700 rounded-xl font-bold text-white shadow-lg hover:shadow-purple-500/50 transition-all duration-300 transform hover:scale-[1.02] active:scale-[0.98] disabled:scale-100 disabled:cursor-not-allowed cursor-pointer overflow-hidden"
              style={{ position: 'relative', zIndex: 10 }}
            >
              {/* Shine Effect */}
              <div className="absolute inset-0 bg-gradient-to-r from-transparent via-white/20 to-transparent translate-x-[-200%] group-hover/btn:translate-x-[200%] transition-transform duration-1000" />
              
              <div className="relative flex items-center justify-center gap-2">
                <Plus className="w-5 h-5" />
                {loading ? 'Adding...' : 'Add Exclusion'}
              </div>
            </button>
          </div>
        </div>
      </div>

      {/* Exclusions List - PREMIUM DESIGN */}
      <div className="relative group">
        {/* Glow Effect */}
        <div className="absolute -inset-0.5 bg-gradient-to-r from-cyan-600 to-purple-600 rounded-xl opacity-20 group-hover:opacity-30 blur transition duration-300" />
        
        <div className="relative p-6 bg-dark-card/90 backdrop-blur-xl border border-dark-border/50 rounded-xl shadow-2xl">
          <div className="flex items-center justify-between mb-6">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-gradient-to-br from-cyan-500 to-purple-500 rounded-lg">
                <Shield className="w-5 h-5 text-white" />
              </div>
              <h3 className="text-xl font-bold bg-gradient-to-r from-cyan-400 to-purple-400 bg-clip-text text-transparent">
                Active Exclusions
              </h3>
            </div>
            <div className="px-4 py-1.5 bg-purple-500/20 border border-purple-500/30 rounded-full">
              <span className="text-sm font-bold text-purple-400">{exclusions.length} Total</span>
            </div>
          </div>
          
          {exclusions.length === 0 ? (
            <div className="text-center py-12">
              <div className="inline-flex p-4 bg-gray-800/50 rounded-full mb-4">
                <Shield className="w-8 h-8 text-gray-600" />
              </div>
              <p className="text-gray-400 font-medium">No exclusions configured yet</p>
              <p className="text-sm text-gray-500 mt-2">Add your first exclusion above</p>
            </div>
          ) : (
            <div className="space-y-3">
              {exclusions.map((exclusion, index) => (
                <div
                  key={exclusion.id}
                  className="group/item relative animate-in slide-in-from-left duration-300"
                  style={{ animationDelay: `${index * 50}ms` }}
                >
                  {/* Item Glow */}
                  <div className={`absolute -inset-0.5 bg-gradient-to-r ${getTypeColor(exclusion.type)} rounded-xl opacity-0 group-hover/item:opacity-20 blur transition duration-300`} />
                  
                  <div className="relative flex items-center justify-between p-4 bg-dark-bg/50 backdrop-blur-sm border border-dark-border/50 group-hover/item:border-purple-500/30 rounded-xl transition-all duration-300">
                    <div className="flex items-center gap-4 flex-1 min-w-0">
                      {/* Icon with Gradient */}
                      <div className={`flex-shrink-0 p-2.5 bg-gradient-to-br ${getTypeColor(exclusion.type)} rounded-lg shadow-lg`}>
                        <div className="text-white">
                          {getIcon(exclusion.type)}
                        </div>
                      </div>
                      
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 mb-1">
                          <span className="font-mono text-sm font-semibold text-white truncate">
                            {exclusion.value}
                          </span>
                          <span className={`flex-shrink-0 px-2.5 py-0.5 bg-gradient-to-r ${getTypeColor(exclusion.type)} rounded-full text-white text-xs font-bold uppercase tracking-wide shadow-lg`}>
                            {exclusion.type}
                          </span>
                        </div>
                        {exclusion.reason && (
                          <p className="text-xs text-gray-400 italic truncate">
                            "{exclusion.reason}"
                          </p>
                        )}
                        <p className="text-xs text-gray-500 mt-1">
                          Added {new Date(exclusion.created_at).toLocaleDateString()}
                        </p>
                      </div>
                    </div>
                    
                    {/* Delete Button - PREMIUM & GUARANTEED WORKING */}
                    <button
                      onClick={() => handleDelete(exclusion.id)}
                      disabled={loading}
                      className="flex-shrink-0 p-2.5 text-red-400 hover:text-red-300 hover:bg-red-500/10 border-2 border-transparent hover:border-red-500/30 rounded-lg transition-all duration-300 transform hover:scale-110 active:scale-95 disabled:opacity-50 disabled:cursor-not-allowed cursor-pointer"
                      style={{ position: 'relative', zIndex: 10 }}
                      title="Remove exclusion"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}