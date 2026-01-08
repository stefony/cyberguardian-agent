'use client'

import { useState, useEffect } from 'react'
import { api } from '@/lib/api'
import { Shield, Zap, AlertTriangle, CheckCircle2 } from 'lucide-react'

type Profile = {
  name: string
  description: string
  threshold: number
  color: string
}

export default function SensitivityProfiles() {
  const [profiles, setProfiles] = useState<Record<string, Profile>>({})
  const [activeProfile, setActiveProfile] = useState<string>('medium')
  const [loading, setLoading] = useState(false)
  const [message, setMessage] = useState<{ type: 'success' | 'error', text: string } | null>(null)

  useEffect(() => {
    loadProfiles()
    detectActiveProfile()
  }, [])

  const loadProfiles = async () => {
    try {
      const response = await api.profiles.getProfiles()
      if (response.success && response.data) {
        setProfiles(response.data.profiles)
      }
    } catch (error) {
      console.error('Failed to load profiles:', error)
    }
  }

  const detectActiveProfile = async () => {
    try {
      const response = await api.protection.getStatus()
      if (response.success && response.data) {
        const threshold = response.data.threat_threshold || response.data.threatThreshold || 75
        
        // Detect which profile matches the threshold
        if (threshold >= 90) setActiveProfile('low')
        else if (threshold >= 70) setActiveProfile('medium')
        else setActiveProfile('high')
      }
    } catch (error) {
      console.error('Failed to detect active profile:', error)
    }
  }

  const handleSetProfile = async (profileName: string) => {
    if (loading || profileName === activeProfile) return
    
    setLoading(true)
    setMessage(null)
    
    try {
      const response = await api.profiles.setProfile(profileName)
      
      if (response.success) {
        setActiveProfile(profileName)
        setMessage({ 
          type: 'success', 
          text: response.data?.message || 'Profile updated successfully!' 
        })
        setTimeout(() => setMessage(null), 3000)
      }
    } catch (error: any) {
      setMessage({ 
        type: 'error', 
        text: error.message || 'Failed to update profile' 
      })
    } finally {
      setLoading(false)
    }
  }

  const getProfileIcon = (profileKey: string) => {
    switch (profileKey) {
      case 'low': return <Shield className="w-6 h-6" />
      case 'medium': return <Zap className="w-6 h-6" />
      case 'high': return <AlertTriangle className="w-6 h-6" />
      default: return <Shield className="w-6 h-6" />
    }
  }

  const getProfileGradient = (profileKey: string) => {
    switch (profileKey) {
      case 'low': return 'from-green-500 to-emerald-500'
      case 'medium': return 'from-yellow-500 to-orange-500'
      case 'high': return 'from-red-500 to-pink-500'
      default: return 'from-gray-500 to-gray-600'
    }
  }

  const getProfileBorderColor = (profileKey: string) => {
    switch (profileKey) {
      case 'low': return 'border-green-500/50'
      case 'medium': return 'border-yellow-500/50'
      case 'high': return 'border-red-500/50'
      default: return 'border-gray-500/50'
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
              <AlertTriangle className="w-5 h-5" />
            )}
            <span className="font-medium">{message.text}</span>
          </div>
        </div>
      )}

      {/* Profile Cards Grid */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {Object.entries(profiles).map(([key, profile]) => {
          const isActive = key === activeProfile
          
          return (
            <div
              key={key}
              className="relative group"
            >
              {/* Glow Effect */}
              <div className={`absolute -inset-0.5 bg-gradient-to-r ${getProfileGradient(key)} rounded-xl opacity-0 ${
                isActive ? 'opacity-30' : 'group-hover:opacity-20'
              } blur transition duration-300`} />
              
              {/* Card */}
              <div className={`relative p-6 bg-dark-card/90 backdrop-blur-xl border-2 ${
                isActive ? getProfileBorderColor(key) : 'border-dark-border/50 hover:border-dark-border'
              } rounded-xl shadow-2xl transition-all duration-300 ${
                isActive ? 'ring-2 ring-offset-2 ring-offset-dark-bg' : ''
              }`}
              
              >
                {/* Active Badge */}
                {isActive && (
                  <div className="absolute -top-3 -right-3">
                    <div className={`px-3 py-1 bg-gradient-to-r ${getProfileGradient(key)} rounded-full shadow-lg`}>
                      <span className="text-xs font-bold text-white uppercase tracking-wide">Active</span>
                    </div>
                  </div>
                )}

                {/* Icon */}
                <div className={`inline-flex p-3 bg-gradient-to-br ${getProfileGradient(key)} rounded-xl mb-4 shadow-lg`}>
                  <div className="text-white">
                    {getProfileIcon(key)}
                  </div>
                </div>

                {/* Title */}
                <h3 className="text-xl font-bold mb-2 bg-gradient-to-r from-white to-gray-300 bg-clip-text text-transparent">
                  {profile.name}
                </h3>

                {/* Description */}
                <p className="text-sm text-gray-400 mb-4 min-h-[3rem]">
                  {profile.description}
                </p>

                {/* Threshold */}
                <div className="flex items-center justify-between mb-4 p-3 bg-dark-bg/50 rounded-lg border border-dark-border/50">
                  <span className="text-xs font-semibold text-gray-400 uppercase tracking-wide">
                    Threshold
                  </span>
                  <span className={`text-2xl font-bold bg-gradient-to-r ${getProfileGradient(key)} bg-clip-text text-transparent`}>
                    {profile.threshold}
                  </span>
                </div>

                {/* Select Button */}
                <button
                  onClick={() => handleSetProfile(key)}
                  disabled={loading || isActive}
                  className={`group/btn relative w-full px-4 py-3 rounded-xl font-bold text-white shadow-lg transition-all duration-300 transform overflow-hidden ${
                    isActive
                      ? `bg-gradient-to-r ${getProfileGradient(key)} cursor-default`
                      : `bg-gradient-to-r ${getProfileGradient(key)} hover:scale-[1.02] active:scale-[0.98] cursor-pointer`
                  } ${loading ? 'opacity-50 cursor-not-allowed' : ''}`}
                  style={{ position: 'relative', zIndex: 10 }}
                >
                  {/* Shine Effect */}
                  {!isActive && (
                    <div className="absolute inset-0 bg-gradient-to-r from-transparent via-white/20 to-transparent translate-x-[-200%] group-hover/btn:translate-x-[200%] transition-transform duration-1000" />
                  )}
                  
                  <div className="relative flex items-center justify-center gap-2">
                    {isActive ? (
                      <>
                        <CheckCircle2 className="w-5 h-5" />
                        Active Profile
                      </>
                    ) : (
                      <>
                        <Shield className="w-5 h-5" />
                        {loading ? 'Activating...' : 'Activate'}
                      </>
                    )}
                  </div>
                </button>
              </div>
            </div>
          )
        })}
      </div>

      {/* Info Box */}
      <div className="p-6 bg-blue-500/10 border-2 border-blue-500/30 rounded-xl backdrop-blur-sm">
        <div className="flex items-start gap-3">
          <div className="p-2 bg-blue-500/20 rounded-lg flex-shrink-0">
            <Zap className="w-5 h-5 text-blue-400" />
          </div>
          <div className="flex-1">
            <h4 className="font-semibold text-blue-400 mb-1">How Sensitivity Works</h4>
            <p className="text-sm text-gray-400">
              Files with threat scores <span className="font-bold text-blue-400">above the threshold</span> will be flagged or quarantined. 
              Lower thresholds = more sensitive = more alerts. Higher thresholds = less sensitive = fewer false positives.
            </p>
          </div>
        </div>
      </div>
    </div>
  )
}