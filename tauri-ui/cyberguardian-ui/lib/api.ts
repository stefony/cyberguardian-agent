/**
 * CyberGuardian Dashboard - API Client
 * Communicates with Python backend (Detection, Response, Deception, AI engines)
 */

import type {
  Threat,
  ThreatResponse,
  Alert,
  DetectionResult,
  DetectionStats,
  Honeypot,
  HoneypotResponse,  // ADD THIS LINE HERE
  AttackerSession,
  Prediction,
  RiskForecast,
  NLPAnalysis,
  SystemStatus,
  DashboardStats,
  HealthData,
  ResponseAction,
  ApiResponse,
} from './types'

// ============================================
// CONFIGURATION
// ============================================

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';


 /**
 * WS URL builder:
 * 1) If NEXT_PUBLIC_WS_URL is set → use it (full URL)
 * 2) Otherwise build it from API_BASE_URL + /api/ws/connect
 *    using wss:// when API is https, otherwise ws://
 */
const buildWsUrl = () => {
  if (process.env.NEXT_PUBLIC_WS_URL) {
    return process.env.NEXT_PUBLIC_WS_URL;
  }
  const api = API_BASE_URL;
  const wsScheme = api.startsWith('https://') ? 'wss://' : 'ws://';
  const host = api.replace(/^https?:\/\//, '');
  return `${wsScheme}${host}/api/ws/connect`;
};

const WS_BASE_URL = buildWsUrl();




// ============================================
// HTTP CLIENT
// ============================================

class ApiClient {
  private baseUrl: string

  constructor(baseUrl: string) {
    this.baseUrl = baseUrl
  }

  // REPLACE THE ENTIRE fetch METHOD IN ApiClient CLASS (around line 70-100)
// This adds Authorization header to all requests

/**
 * Generic fetch wrapper with error handling and JWT authentication
 */
// REPLACE THE ENTIRE fetch METHOD IN ApiClient CLASS (around line 70-100)
// This adds Authorization header to all requests

/**
 * Generic fetch wrapper with error handling and JWT authentication
 */
private async fetch<T>(
  endpoint: string,
  options?: RequestInit
): Promise<ApiResponse<T>> {
  // 🔎 DEBUG (временен): ако е към quarantine, логни реалния URL
  if (endpoint.startsWith("/api/quarantine")) {
    console.log("QUAR FETCH →", this.baseUrl, endpoint);
  }

  try {
   // Get JWT token from localStorage
    const token = typeof window !== 'undefined' ? localStorage.getItem('access_token') : null;
    
    // Build headers with JWT token
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
    };

    // Add Authorization header if token exists
    console.log('🔑 Token check:', token ? 'EXISTS' : 'NULL');
    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }

    // Merge with provided headers
    if (options?.headers) {
      Object.entries(options.headers).forEach(([key, value]) => {
        if (typeof value === 'string') {
          headers[key] = value;
        }
      });
    }

   // 🔍 DEBUG: Log headers before fetch
    console.log('🔍 FETCH:', endpoint, 'Token:', token ? 'EXISTS' : 'NULL', 'Headers:', headers);
    
    const response = await fetch(`${this.baseUrl}${endpoint}`, {
      ...options,
      headers,
    });

    if (!response.ok) {
      // Handle 401 Unauthorized - redirect to login
      if (response.status === 401) {
        console.warn("401 Unauthorized - redirecting to login");
        if (typeof window !== 'undefined') {
          localStorage.removeItem('access_token');
          localStorage.removeItem('user');
          window.location.href = '/auth/login';
        }
        return {
          success: false,
          error: "Unauthorized - please login again",
        };
      }

      console.warn("FETCH ERROR →", `${this.baseUrl}${endpoint}`, response.status);
      const error = await response.json().catch(() => ({ message: "Unknown error" }));
      return {
        success: false,
        error: error.message || error.detail || `HTTP ${response.status}`,
      };
    }

    const data = await response.json();
    return {
      success: true,
      data,
    };
  } catch (error) {
    console.error("NETWORK ERROR →", `${this.baseUrl}${endpoint}`, error);
    return {
      success: false,
      error: error instanceof Error ? error.message : "Network error",
    };
  }
}


  /**
   * GET request
   */
  async get<T>(endpoint: string): Promise<ApiResponse<T>> {
    return this.fetch<T>(endpoint, { method: 'GET' })
  }

  /**
   * POST request
   */
  async post<T>(endpoint: string, body?: any): Promise<ApiResponse<T>> {
    return this.fetch<T>(endpoint, {
      method: 'POST',
      body: body ? JSON.stringify(body) : undefined,
    })
  }

  /**
   * PUT request
   */
  async put<T>(endpoint: string, body?: any): Promise<ApiResponse<T>> {
    return this.fetch<T>(endpoint, {
      method: 'PUT',
      body: body ? JSON.stringify(body) : undefined,
    })
  }

  /**
   * PATCH request
   */
  async patch<T>(endpoint: string, body?: any): Promise<ApiResponse<T>> {
    return this.fetch<T>(endpoint, {
      method: 'PATCH',
      body: body ? JSON.stringify(body) : undefined,
    })
  }

  /**
   * DELETE request
   */
  async delete<T>(endpoint: string): Promise<ApiResponse<T>> {
    return this.fetch<T>(endpoint, { method: 'DELETE' })
  }
}

const client = new ApiClient(API_BASE_URL)

// ============================================
// DASHBOARD API
// ============================================

export const dashboardApi = {
  getStats: async (): Promise<ApiResponse<DashboardStats>> => {
    return client.get<DashboardStats>('/api/dashboard/stats')
  },

  getSystemStatus: async (): Promise<ApiResponse<SystemStatus>> => {
    return client.get<SystemStatus>('/api/dashboard/status')
  },

  // ADD THIS NEW FUNCTION:
  getHealth: async (): Promise<ApiResponse<HealthData>> => {
    return client.get<HealthData>('/api/health')
  },
}

// ============================================
// THREATS & ALERTS API
// ============================================

export const threatsApi = {
  getThreats: async (params?: {
    severity?: string;
    status?: string;
    type?: string;
    limit?: number;
  }): Promise<ApiResponse<ThreatResponse[]>> => {
    const query = new URLSearchParams(params as any).toString();
    console.log("➡️ FETCH_THREATS URL:", `/api/threats${query ? `?${query}` : ''}`);
    return client.get<ThreatResponse[]>(
      `/api/threats${query ? `?${query}` : ''}`
    );
  },

  getThreatById: async (id: string): Promise<ApiResponse<Threat>> => {
    return client.get<Threat>(`/api/threats/${id}`)
  },

  getAlerts: async (): Promise<ApiResponse<Alert[]>> => {
    return client.get<Alert[]>('/api/alerts')
  },

  dismissAlert: async (id: string): Promise<ApiResponse<void>> => {
    return client.post<void>(`/api/alerts/${id}/dismiss`)
  },

  /**
   * Get threat statistics
   */
  getStats: async (): Promise<ApiResponse<any>> => {
    return client.get<any>('/api/threats/stats')
  },

  /**
   * Block a threat
   */
  blockThreat: async (threatId: number): Promise<ApiResponse<any>> => {
    return client.post<any>('/api/threats/block', { 
      threat_id: threatId, 
      action: 'block' 
    })
  },

  /**
   * Dismiss a threat
   */
  dismissThreat: async (threatId: number): Promise<ApiResponse<any>> => {
    return client.post<any>('/api/threats/dismiss', { 
      threat_id: threatId, 
      action: 'dismiss' 
    })
  },

  /**
   * Batch action on multiple threats
   */
  batchAction: async (data: {
    threat_ids: number[];
    action: 'block' | 'dismiss' | 'delete';
    reason?: string;
  }): Promise<ApiResponse<any>> => {
    return client.post<any>('/api/threats/batch', data);
  },
}

// ============================================
// DETECTION ENGINE API
// ============================================

export const detectionApi = {
  /**
   * Get detection results
   */
  getDetections: async (params?: {
    type?: string
    limit?: number
  }): Promise<ApiResponse<DetectionResult[]>> => {
    const query = new URLSearchParams(params as any).toString()
    return client.get<DetectionResult[]>(
      `/api/detection/results${query ? `?${query}` : ''}`
    )
  },

  /**
   * Get detection statistics
   */
  getStats: async (): Promise<ApiResponse<DetectionStats>> => {
    return client.get<DetectionStats>('/api/detection/stats')
  },

  /**
   * Trigger manual scan
   */
  triggerScan: async (target: {
    type: 'file' | 'directory' | 'process' | 'full_system'
    path?: string
  }): Promise<ApiResponse<{ scan_id: string }>> => {
    return client.post<{ scan_id: string }>('/api/detection/scan', target)
  },

  // ADD THESE 3 NEW FUNCTIONS BELOW:

  /**
   * Get detection engine status
   */
  getStatus: async (): Promise<ApiResponse<any>> => {
    return client.get<any>('/api/detection/status')
  },

  /**
   * Get recent scans
   */
  getScans: async (limit?: number): Promise<ApiResponse<any[]>> => {
    return client.get<any[]>(`/api/detection/scans${limit ? `?limit=${limit}` : ''}`)
  },

/**
 * Upload file for scanning
 */
uploadFile: async (file: File): Promise<ApiResponse<any>> => {
  try {
    const formData = new FormData()
    formData.append('file', file)
    
    const token = localStorage.getItem('access_token')
    
    // ✅ USE V2 ENDPOINT
    const response = await fetch(`${API_BASE_URL}/api/detection/scan/v2`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token}`,
      },
      body: formData,
    })

    if (!response.ok) {
      const error = await response.json().catch(() => ({ message: 'Upload failed' }))
      return {
        success: false,
        error: error.message || error.detail || `HTTP ${response.status}`,
      }
    }

    const data = await response.json()
    return {
      success: true,
      data,
    }
  } catch (error) {
    return {
      success: false,
      error: error instanceof Error ? error.message : 'Network error',
    }
  }
},
}

// ============================================
// RESPONSE ENGINE API
// ============================================

export const responseApi = {
  /**
   * Block IP address
   */
  blockIp: async (ip: string, reason: string): Promise<ApiResponse<ResponseAction>> => {
    return client.post<ResponseAction>('/api/response/block-ip', { ip, reason })
  },

  /**
   * Kill process
   */
  killProcess: async (pid: number, reason: string): Promise<ApiResponse<ResponseAction>> => {
    return client.post<ResponseAction>('/api/response/kill-process', { pid, reason })
  },

  /**
   * Quarantine file
   */
  quarantineFile: async (
    path: string,
    reason: string
  ): Promise<ApiResponse<ResponseAction>> => {
    return client.post<ResponseAction>('/api/response/quarantine', { path, reason })
  },

  /**
   * Isolate network
   */
  isolateNetwork: async (reason: string): Promise<ApiResponse<ResponseAction>> => {
    return client.post<ResponseAction>('/api/response/isolate-network', { reason })
  },

  /**
   * Restore network
   */
  restoreNetwork: async (): Promise<ApiResponse<ResponseAction>> => {
    return client.post<ResponseAction>('/api/response/restore-network')
  },

  /**
   * Get response history
   */
  getHistory: async (limit?: number): Promise<ApiResponse<ResponseAction[]>> => {
    return client.get<ResponseAction[]>(
      `/api/response/history${limit ? `?limit=${limit}` : ''}`
    )
  },
}

// ============================================
// DECEPTION LAYER API
// ============================================

export const deceptionApi = {
  /**
   * Get all honeypots
   */
 getHoneypots: async (): Promise<ApiResponse<HoneypotResponse[]>> => {
  return client.get<HoneypotResponse[]>('/api/deception/honeypots')
},

  /**
   * Create new honeypot
   */
  createHoneypot: async (honeypot: {
    name: string
    type: string
    path: string
  }): Promise<ApiResponse<Honeypot>> => {
    return client.post<Honeypot>('/api/deception/honeypots', honeypot)
  },

  /**
   * Get attacker sessions
   */
  getAttackerSessions: async (): Promise<ApiResponse<AttackerSession[]>> => {
    return client.get<AttackerSession[]>('/api/deception/sessions')
  },

  /**
   * Get session details
   */
  getSessionById: async (id: string): Promise<ApiResponse<AttackerSession>> => {
    return client.get<AttackerSession>(`/api/deception/sessions/${id}`)
  },

  /**
   * Generate honeypots automatically
   */
  generateHoneypots: async (count: number): Promise<ApiResponse<Honeypot[]>> => {
    return client.post<Honeypot[]>('/api/deception/generate', { count })
  },

  // ADD THESE 3 NEW FUNCTIONS BELOW:

  /**
   * Get deception layer status
   */
  getStatus: async (): Promise<ApiResponse<any>> => {
    return client.get<any>('/api/deception/status')
  },

  /**
   * Get honeypot interaction logs
   */
  getLogs: async (limit?: number): Promise<ApiResponse<any[]>> => {
    return client.get<any[]>(`/api/deception/logs${limit ? `?limit=${limit}` : ''}`)
  },

  /**
   * Toggle honeypot status (activate/deactivate)
   */
  toggleHoneypot: async (honeypotId: number, action: 'activate' | 'deactivate'): Promise<ApiResponse<any>> => {
    const status = action === 'activate' ? 'active' : 'inactive'
    return client.post<any>(`/api/deception/honeypots/${action}`, { 
      honeypot_id: honeypotId, 
      status 
    })
  },
}

// ============================================
// AI ENGINES API
// ============================================

export const aiApi = {
  /**
   * Predict attack
   */
  predictAttack: async (indicators: any): Promise<ApiResponse<Prediction>> => {
    return client.post<Prediction>('/api/ai/predict', indicators)
  },

  /**
   * Get risk forecast
   */
  getRiskForecast: async (days: number = 7): Promise<ApiResponse<RiskForecast>> => {
    return client.get<RiskForecast>(`/api/ai/forecast?days=${days}`)
  },

  /**
   * Analyze text with NLP
   */
  analyzeText: async (text: string): Promise<ApiResponse<NLPAnalysis>> => {
    return client.post<NLPAnalysis>('/api/ai/nlp/analyze', { text })
  },

  /**
   * Check for adversarial attack
   */
  checkAdversarial: async (data: {
    input: any
    prediction: any
    confidence: number
  }): Promise<ApiResponse<{ attack_detected: boolean; details: any }>> => {
    return client.post('/api/ai/adversarial/check', data)
  },

  // ADD THESE 4 NEW FUNCTIONS:

  /**
   * Get AI engine status
   */
  getStatus: async (): Promise<ApiResponse<any>> => {
    return client.get<any>('/api/ai/status')
  },

  /**
   * Get threat predictions
   */
  getPredictions: async (): Promise<ApiResponse<any[]>> => {
    return client.get<any[]>('/api/ai/predictions')
  },

  /**
   * Get risk score
   */
  getRiskScore: async (): Promise<ApiResponse<any>> => {
    return client.get<any>('/api/ai/risk-score')
  },

  /**
   * Get AI recommendations
   */
  getRecommendations: async (): Promise<ApiResponse<any[]>> => {
    return client.get<any[]>('/api/ai/recommendations')
  },
}

// ============================================
// WEBSOCKET CLIENT
// ============================================

export class WebSocketClient {
  private ws: WebSocket | null = null
  private reconnectAttempts = 0
  private maxReconnectAttempts = 5
  private reconnectDelay = 3000

  /**
   * Connect to WebSocket for real-time updates
   */
  connect(onMessage: (data: any) => void, onError?: (error: Event) => void) {
    try {
      this.ws = new WebSocket(WS_BASE_URL as string)


      this.ws.onopen = () => {
        console.log('✅ WebSocket connected')
        this.reconnectAttempts = 0
      }

      this.ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data)
          onMessage(data)
        } catch (error) {
          console.error('Failed to parse WebSocket message:', error)
        }
      }

      this.ws.onerror = (error) => {
        console.error('❌ WebSocket error:', error)
        if (onError) onError(error)
      }

      this.ws.onclose = () => {
        console.log('🔌 WebSocket disconnected')
        this.attemptReconnect(onMessage, onError)
      }
    } catch (error) {
      console.error('Failed to create WebSocket:', error)
      if (onError) onError(error as Event)
    }
  }

  /**
   * Attempt to reconnect
   */
  private attemptReconnect(
    onMessage: (data: any) => void,
    onError?: (error: Event) => void
  ) {
    if (this.reconnectAttempts < this.maxReconnectAttempts) {
      this.reconnectAttempts++
      console.log(
        `Reconnecting... (${this.reconnectAttempts}/${this.maxReconnectAttempts})`
      )
      setTimeout(() => {
        this.connect(onMessage, onError)
      }, this.reconnectDelay)
    } else {
      console.error('Max reconnection attempts reached')
    }
  }

  /**
   * Send message through WebSocket
   */
  send(data: any) {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify(data))
    } else {
      console.warn('WebSocket not connected')
    }
  }

  /**
   * Close WebSocket connection
   */
  disconnect() {
    if (this.ws) {
      this.ws.close()
      this.ws = null
    }
  }
}

// ============================================
// HONEYPOTS API
// ============================================

export const honeypotApi = {
  /**
   * Get honeypot status
   */
  getStatus: async (): Promise<ApiResponse<any[]>> => {
    return client.get<any[]>('/api/honeypots/status')
  },

  /**
   * Get recent attacks
   */
  getAttacks: async (limit?: number): Promise<ApiResponse<any[]>> => {
    return client.get<any[]>(`/api/honeypots/attacks${limit ? `?limit=${limit}` : ''}`)
  },

  /**
   * Get statistics
   */
  getStatistics: async (): Promise<ApiResponse<any>> => {
    return client.get<any>('/api/honeypots/statistics')
  },

  /**
   * Start honeypot
   */
  start: async (type: string): Promise<ApiResponse<any>> => {
    return client.post<any>(`/api/honeypots/start/${type}`)
  },

  /**
   * Stop honeypot
   */
  stop: async (type: string): Promise<ApiResponse<any>> => {
    return client.post<any>(`/api/honeypots/stop/${type}`)
  },

  /**
   * Start all honeypots
   */
  startAll: async (): Promise<ApiResponse<any>> => {
    return client.post<any>('/api/honeypots/start-all')
  },

  /**
   * Stop all honeypots
   */
  stopAll: async (): Promise<ApiResponse<any>> => {
    return client.post<any>('/api/honeypots/stop-all')
  },
}
// ============================================
// ML MODELS API
// ============================================

export const mlApi = {
  /**
   * Get ML model status
   */
  getStatus: async (): Promise<ApiResponse<any>> => {
    return client.get<any>('/api/ml/status')
  },

  /**
   * Train ML models
   * - pass { sync: true } ако искаш да върне реалните метрики в отговора
   */
  train: async (params: {
    n_clusters?: number
    contamination?: number
    sync?: boolean
  }): Promise<ApiResponse<any>> => {
    const { sync, ...body } = params || {}
    const suffix = sync ? '?sync=1' : ''
    return client.post<any>(`/api/ml/train${suffix}`, body)
  },

  /**
   * Persist current trained models to disk
   */
  save: async (): Promise<ApiResponse<{ ok: boolean; saved_as: string }>> => {
    return client.post<{ ok: boolean; saved_as: string }>('/api/ml/save')
  },

  /**
   * Load latest persisted models (LATEST)
   */
  load: async (): Promise<ApiResponse<{
    ok: boolean
    model_trained: boolean
    training_date: string
    samples: number
    n_clusters: number
  }>> => {
    return client.post('/api/ml/load')
  },

  /**
   * Get live metrics (silhouette, mean anomaly, labeled_count, etc.)
   */
  getMetrics: async (): Promise<ApiResponse<any>> => {
    return client.get<any>('/api/ml/metrics')
  },

  /**
   * ✅ Get anomaly threshold
   */
  getThresholds: async (): Promise<ApiResponse<{ anomaly_threshold: number }>> => {
  return client.get<{ anomaly_threshold: number }>('/api/ml/thresholds')
},

  /**
   * ✅ Set anomaly threshold
   */
 setThresholds: async (
  data: { anomaly_threshold: number }
): Promise<ApiResponse<{ anomaly_threshold: number }>> => {
  return client.post<{ anomaly_threshold: number }>('/api/ml/thresholds', data)
},


  /**
   * Predict: anomaly only
   */
  predictAnomaly: async (log: any): Promise<ApiResponse<any>> => {
    return client.post<any>('/api/ml/predict/anomaly', log)
  },

  /**
   * Analyze behavior (cluster label)
   */
  analyzeBehavior: async (log: any): Promise<ApiResponse<any>> => {
    return client.post<any>('/api/ml/analyze/behavior', log)
  },

  /**
   * Hybrid threat score
   */
  getThreatScore: async (log: any): Promise<ApiResponse<any>> => {
    return client.post<any>('/api/ml/threat-score', log)
  },

  /**
   * Batch threat scores
   */
  batchThreatScores: async (
    logs: any[]
  ): Promise<ApiResponse<{ total: number; scores: any[] }>> => {
    return client.post<{ total: number; scores: any[] }>(
      '/api/ml/batch/threat-scores',
      logs
    )
  },
}


// ============================================
// ANALYTICS API
// ============================================

export const analyticsApi = {
  /**
   * Get overview statistics
   */
  getOverview: async (): Promise<ApiResponse<any>> => {
    return client.get<any>('/api/analytics/overview')
  },

  /**
   * Get threats timeline
   */
  getThreatsTimeline: async (days?: number): Promise<ApiResponse<any[]>> => {
    return client.get<any[]>(`/api/analytics/threats-timeline${days ? `?days=${days}` : ''}`)
  },

  /**
   * Get detection statistics breakdown
   */
  getDetectionStats: async (): Promise<ApiResponse<any[]>> => {
    return client.get<any[]>('/api/analytics/detection-stats')
  },

  /**
   * Get honeypot activity
   */
  getHoneypotActivity: async (days?: number): Promise<ApiResponse<any[]>> => {
    return client.get<any[]>(`/api/analytics/honeypot-activity${days ? `?days=${days}` : ''}`)
  },

  /**
   * Get top threats
   */
  getTopThreats: async (limit?: number): Promise<ApiResponse<any[]>> => {
    return client.get<any[]>(`/api/analytics/top-threats${limit ? `?limit=${limit}` : ''}`)
  },

  /**
   * Get security posture score
   */
  getSecurityPosture: async (): Promise<ApiResponse<any>> => {
    return client.get<any>('/api/analytics/security-posture')
  },

  /**
   * Get recent security incidents
   */
  getRecentIncidents: async (limit?: number): Promise<ApiResponse<any[]>> => {
    return client.get<any[]>(`/api/analytics/recent-incidents${limit ? `?limit=${limit}` : ''}`)
  },
}

// REPLACE THE ENTIRE emailsApi SECTION IN lib/api.ts WITH THIS:

// ============================================
// EMAILS API
// ============================================

export const emailsApi = {
  /**
   * Get email scanner status
   */
  getStatus: async (): Promise<ApiResponse<any>> => {
    return client.get<any>('/api/emails/status')
  },

  /**
   * Scan emails for phishing
   */
  scan: async (params: {
    account_id: number
    folder?: string
    limit?: number
  }): Promise<ApiResponse<any[]>> => {
    return client.post<any[]>('/api/emails/scan', params)
  },

  /**
   * Get email statistics
   */
  getStats: async (): Promise<ApiResponse<any>> => {
    return client.get<any>('/api/emails/stats')
  },

  // ========== EMAIL ACCOUNTS MANAGEMENT ==========

  /**
   * Get all email accounts for current user
   */
  getAccounts: async (): Promise<ApiResponse<any[]>> => {
    return client.get<any[]>('/api/emails/accounts')
  },

  /**
   * Add new email account
   */
  addAccount: async (data: {
    email_address: string
    provider: string
    imap_host: string
    imap_port: number
    password: string
    auto_scan_enabled?: boolean
    scan_interval_hours?: number
    folders_to_scan?: string
  }): Promise<ApiResponse<any>> => {
    return client.post<any>('/api/emails/accounts', data)  // ✅ FIXED - removed /add
  },

  /**
   * Update email account settings
   */
  updateAccount: async (
    accountId: number,
    data: {
      auto_scan_enabled?: boolean
      scan_interval_hours?: number
      folders_to_scan?: string
    }
  ): Promise<ApiResponse<any>> => {
    return client.put<any>(`/api/emails/accounts/${accountId}`, data)
  },

  /**
   * Delete email account
   */
  deleteAccount: async (accountId: number): Promise<ApiResponse<any>> => {
    return client.delete<any>(`/api/emails/accounts/${accountId}`)
  },

  /**
   * Get scan history for account
   */
  getHistory: async (accountId: number, limit?: number): Promise<ApiResponse<any>> => {
    return client.get<any>(
      `/api/emails/history?account_id=${accountId}${limit ? `&limit=${limit}` : ''}`
    )
  },

  /**
   * Get scanned emails results
   */
  getResults: async (accountId: number, limit?: number): Promise<ApiResponse<any>> => {
    return client.get<any>(
      `/api/emails/results?account_id=${accountId}${limit ? `&limit=${limit}` : ''}`
    )
  },
}

// ============================================
// SETTINGS API
// ============================================

export const settingsApi = {
  /**
   * Get application settings
   */
  getSettings: async (): Promise<ApiResponse<any>> => {
    return client.get<any>('/api/settings')
  },

  /**
   * Save application settings
   */
  saveSettings: async (settings: any): Promise<ApiResponse<any>> => {
    return client.post<any>('/api/settings', settings)
  },

  /**
   * Reset settings to default
   */
  resetSettings: async (): Promise<ApiResponse<any>> => {
    return client.post<any>('/api/settings/reset')
  },

  /**
   * Get system information
   */
  getSystemInfo: async (): Promise<ApiResponse<any>> => {
    return client.get<any>('/api/settings/system-info')
  },

  /**
   * Get license information
   */
  getLicense: async (): Promise<ApiResponse<any>> => {
    return client.get<any>('/api/settings/license')
  },

  // ========== EXPORT/IMPORT CONFIG ==========

  /**
   * Export complete system configuration
   */
  exportConfig: async (): Promise<ApiResponse<{
    version: string
    exported_at: string
    settings: any
    exclusions: any[]
    scan_schedules: any[]
    auto_purge_policy: any
    filename: string
  }>> => {
    return client.get<any>('/api/settings/export')
  },

  /**
   * Import system configuration
   */
  importConfig: async (config: any): Promise<ApiResponse<{
    success: boolean
    imported: string[]
    failed: string[]
    warnings: string[]
    message: string
  }>> => {
    return client.post<any>('/api/settings/import', config)
  },
}


/// ============================================
// PROTECTION API
// ============================================

export const protectionApi = {
  /**
   * Get protection status
   */
  getStatus: async (): Promise<ApiResponse<any>> => {
    return client.get<any>('/api/protection/status')
  },

  /**
   * Toggle protection
   */
  toggle: async (
    enabled: boolean,
    paths: string[],
    autoQuarantine?: boolean,
    threatThreshold?: number
  ): Promise<ApiResponse<any>> => {
    return client.post<any>('/api/protection/toggle', {
      enabled,
      paths,
      auto_quarantine: autoQuarantine,
      threat_threshold: threatThreshold,
    })
  },

  /**
   * Update protection settings (without toggling)
   */
  updateSettings: async (
    autoQuarantine?: boolean,
    threatThreshold?: number
  ): Promise<ApiResponse<any>> => {
    return client.post<any>('/api/protection/settings', {
      auto_quarantine: autoQuarantine,
      threat_threshold: threatThreshold,
    })
  },

  /**
   * Get file system events
   */
  getEvents: async (limit?: number): Promise<ApiResponse<any[]>> => {
    return client.get<any[]>(
      `/api/protection/events${limit ? `?limit=${limit}` : ''}`
    )
  },

  /**
   * Get protection statistics
   */
  getStats: async (): Promise<ApiResponse<any>> => {
    return client.get<any>('/api/protection/stats')
  },
}

// ============================================
// SCANS API
// ============================================

export const scansApi = {
  /**
   * Get all scan schedules
   */
  getSchedules: async (): Promise<ApiResponse<any[]>> => {
    return client.get<any[]>('/api/scans/schedules')
  },

  /**
   * Get single schedule
   */
  getSchedule: async (id: number): Promise<ApiResponse<any>> => {
    return client.get<any>(`/api/scans/schedules/${id}`)
  },

  /**
   * Create scan schedule
   */
  createSchedule: async (data: {
    name: string
    scan_type: string
    target_path: string
    schedule_type: string
    interval_days?: number
    enabled?: boolean
  }): Promise<ApiResponse<any>> => {
    return client.post<any>('/api/scans/schedules', data)
  },

  /**
   * Update scan schedule
   */
  updateSchedule: async (
    id: number,
    data: { name?: string; enabled?: boolean }
  ): Promise<ApiResponse<any>> => {
    return client.patch<any>(`/api/scans/schedules/${id}`, data)
  },

  /**
   * Delete scan schedule
   */
  deleteSchedule: async (id: number): Promise<ApiResponse<any>> => {
    return client.delete<any>(`/api/scans/schedules/${id}`)
  },

  /**
   * Get scan history
   */
  getHistory: async (limit?: number): Promise<ApiResponse<any[]>> => {
    return client.get<any[]>(
      `/api/scans/history${limit ? `?limit=${limit}` : ''}`
    )
  },

  /**
   * Run manual scan
   */
  runScan: async (data: {
    scan_type: string
    target_path: string
  }): Promise<ApiResponse<any>> => {
    return client.post<any>('/api/scans/run', data)
  },

  /**
   * Get available scan profiles
   */
  getScanProfiles: async (): Promise<ApiResponse<{
    profiles: Record<string, {
      name: string
      description: string
      scan_type: string
      threads: number
      max_files: number
      extensions: string[]
      skip_archives: boolean
      recursive: boolean
      duration_estimate: string
      icon: string
      color: string
    }>
  }>> => {
    return client.get<any>('/api/scans/profiles')
  },

  /**
   * Start scan with profile
   */
  startScanWithProfile: async (profileName: string): Promise<ApiResponse<{
    success: boolean
    scan_id: number
    profile: string
    message: string
  }>> => {
    return client.post<any>(`/api/scans/start-profile/${profileName}`, {})
  },
}
// ============================================
// QUARANTINE API
// ============================================

export const quarantineApi = {
  /**
   * Get all quarantined files
   */
  getFiles: async (): Promise<ApiResponse<any[]>> => {
    return client.get<any[]>('/api/quarantine')
  },

  /**
   * Get quarantine statistics
   */
  getStats: async (): Promise<ApiResponse<any>> => {
    return client.get<any>('/api/quarantine/stats')
  },

  /**
   * Get single quarantined file
   */
  getFile: async (id: string): Promise<ApiResponse<any>> => {
    return client.get<any>(`/api/quarantine/${id}`)
  },

  /**
   * Quarantine a file
   */
  quarantineFile: async (data: {
    file_path: string
    reason?: string
    threat_score?: number
    threat_level?: string
    detection_method?: string
  }): Promise<ApiResponse<any>> => {
    return client.post<any>('/api/quarantine', data)
  },

  /**
   * Restore file from quarantine
   */
  restoreFile: async (id: string): Promise<ApiResponse<any>> => {
    return client.post<any>(`/api/quarantine/${id}/restore`, {})
  },

  /**
   * Permanently delete quarantined file
   */
  deleteFile: async (id: string): Promise<ApiResponse<any>> => {
    return client.delete<any>(`/api/quarantine/${id}`)
  },

  // ========== AUTO-PURGE POLICY ==========

  /**
   * Get auto-purge settings
   */
  getAutoPurgeSettings: async (): Promise<ApiResponse<{
    enabled: boolean
    days_threshold: number
    auto_purge_critical: boolean
    auto_purge_high: boolean
    auto_purge_medium: boolean
    auto_purge_low: boolean
  }>> => {
    return client.get<any>('/api/quarantine/auto-purge/settings')
  },

  /**
   * Update auto-purge settings
   */
  updateAutoPurgeSettings: async (settings: {
    enabled: boolean
    days_threshold: number
    auto_purge_critical: boolean
    auto_purge_high: boolean
    auto_purge_medium: boolean
    auto_purge_low: boolean
  }): Promise<ApiResponse<any>> => {
    return client.post<any>('/api/quarantine/auto-purge/settings', settings)
  },

  /**
   * Preview auto-purge (which files will be deleted)
   */
  previewAutoPurge: async (): Promise<ApiResponse<{
    files_to_delete: Array<{
      id: string
      name: string
      threat_level: string
      age_days: number
      size: number
    }>
    total_count: number
    total_size_bytes: number
  }>> => {
    return client.post<any>('/api/quarantine/auto-purge/preview', {})
  },

  /**
   * Execute auto-purge
   */
  executeAutoPurge: async (): Promise<ApiResponse<{
    deleted_count: number
    deleted_size_bytes: number
  }>> => {
    return client.post<any>('/api/quarantine/auto-purge/execute', {})
  },
}

// ============================================
// HONEYPOT GEO ATTACKS API
// ============================================

export const geoAttacksApi = {
  /**
   * Get honeypot attacks with geolocation data
   */
  getGeoAttacks: async (limit: number = 100): Promise<ApiResponse<{
    success: boolean
    total: number
    attacks: Array<{
      id: number
      timestamp: string
      source_ip: string
      action: string
      country: string
      city: string
      latitude: number
      longitude: number
      honeypot_id: number
    }>
  }>> => {
    return client.get<any>(`/api/honeypots/geo-attacks?limit=${limit}`)
  },
}

// ============================================
// WHAT-IF SIMULATOR API
// ============================================

export const whatIfApi = {
  /**
   * Simulate threat scenario
   */
  simulate: async (scenario: {
    threats_per_hour: number
    attack_types: string[]
    duration_hours: number
    current_defenses: Record<string, boolean>
  }): Promise<ApiResponse<{
    scenario: string
    threat_volume: number
    estimated_blocks: number
    estimated_breaches: number
    cpu_usage_percent: number
    memory_usage_percent: number
    disk_io_mbps: number
    network_bandwidth_mbps: number
    recommendations: string[]
    risk_level: string
    confidence: number
  }>> => {
    return client.post<any>('/api/ai/what-if', scenario)
  },
}
// ============================================
// EXCLUSIONS API
// ============================================

export const exclusionsApi = {
  /**
   * Get all exclusions
   */
  getExclusions: async (type?: string): Promise<ApiResponse<Array<{
    id: number
    type: string
    value: string
    reason: string | null
    created_at: string
    created_by: string | null
  }>>> => {
    const url = type ? `/api/exclusions?type=${type}` : '/api/exclusions'
    return client.get<any>(url)
  },

  /**
   * Add new exclusion
   */
  addExclusion: async (data: {
    type: string
    value: string
    reason?: string
  }): Promise<ApiResponse<{ success: boolean; id: number; message: string }>> => {
    return client.post<any>('/api/exclusions', data)
  },

  /**
   * Delete exclusion
   */
  deleteExclusion: async (id: number): Promise<ApiResponse<{ success: boolean; message: string }>> => {
    return client.delete<any>(`/api/exclusions/${id}`)
  },

  /**
   * Check if value is excluded
   */
  checkExclusion: async (type: string, value: string): Promise<ApiResponse<{
    excluded: boolean
    type: string
    value: string
  }>> => {
    return client.get<any>(`/api/exclusions/check/${type}/${value}`)
  },
}

// ============================================
// SENSITIVITY PROFILES API
// ============================================

export const profilesApi = {
  /**
   * Get available sensitivity profiles
   */
  getProfiles: async (): Promise<ApiResponse<{
    profiles: Record<string, {
      name: string
      description: string
      threshold: number
      color: string
    }>
  }>> => {
    return client.get<any>('/api/protection/profiles')
  },

  /**
   * Set active sensitivity profile
   */
  setProfile: async (profileName: string): Promise<ApiResponse<{
    success: boolean
    profile: string
    threshold: number
    message: string
  }>> => {
    return client.post<any>(`/api/protection/profile/${profileName}`, {})
  },
}

// ============================================
// REMEDIATION API
// ============================================

export const remediationApi = {
  /**
   * Scan Windows registry for suspicious entries
   */
  scanRegistry: async (): Promise<ApiResponse<{
    entries: Array<{
      id: string
      hive: string
      key_path: string
      value_name: string
      value_data: string
      value_type: string
      risk_score: number
      indicators: string[]
      scanned_at: string
    }>
    statistics: {
      total_suspicious: number
      critical_risk: number
      high_risk: number
      medium_risk: number
      low_risk: number
      by_hive: Record<string, number>
    }
    scanned_at: string
  }>> => {
    return client.get<any>('/api/remediation/registry/scan')
  },

  /**
   * Get registry scan statistics
   */
  getRegistryStats: async (): Promise<ApiResponse<{
    total_suspicious: number
    critical_risk: number
    high_risk: number
    medium_risk: number
    low_risk: number
    by_hive: Record<string, number>
  }>> => {
    return client.get<any>('/api/remediation/registry/statistics')
  },

  /**
   * Remove a registry entry (with automatic backup)
   */
  removeRegistryEntry: async (data: {
    hive: string
    key_path: string
    value_name: string
  }): Promise<ApiResponse<{
    success: boolean
    message: string
    backup_file: string | null
  }>> => {
    return client.post<any>('/api/remediation/registry/remove', data)
  },

  /**
   * Restore a registry entry from backup
   */
  restoreRegistryEntry: async (data: {
    backup_file: string
  }): Promise<ApiResponse<{
    success: boolean
    message: string
  }>> => {
    return client.post<any>('/api/remediation/registry/restore', data)
  },

  /**
   * List all registry backups
   */
  listRegistryBackups: async (): Promise<ApiResponse<{
    backups: Array<{
      filename: string
      filepath: string
      hive: string
      key_path: string
      value_name: string
      backed_up_at: string
    }>
  }>> => {
    return client.get<any>('/api/remediation/registry/backups')
  },

  // ========== SERVICES CLEANUP ==========

  /**
   * Scan Windows services for suspicious entries
   */
  scanServices: async (): Promise<ApiResponse<{
    services: Array<{
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
    }>
    statistics: {
      total_suspicious: number
      critical_risk: number
      high_risk: number
      medium_risk: number
      low_risk: number
      by_status: Record<string, number>
      by_startup_type: Record<string, number>
    }
    scanned_at: string
  }>> => {
    return client.get<any>('/api/remediation/services/scan')
  },

  /**
   * Stop a Windows service
   */
  stopService: async (data: {
    service_name: string
  }): Promise<ApiResponse<{
    success: boolean
    message: string
  }>> => {
    return client.post<any>('/api/remediation/services/stop', data)
  },

  /**
   * Remove a Windows service (with automatic backup)
   */
  removeService: async (data: {
    service_name: string
  }): Promise<ApiResponse<{
    success: boolean
    message: string
    backup_file: string | null
  }>> => {
    return client.post<any>('/api/remediation/services/remove', data)
  },

  /**
   * List all service backups
   */
  listServiceBackups: async (): Promise<ApiResponse<{
    backups: Array<{
      filename: string
      filepath: string
      service_name: string
      binary_path: string
      startup_type: string
      backed_up_at: string
    }>
  }>> => {
    return client.get<any>('/api/remediation/services/backups')
  },

  // ========== SCHEDULED TASKS CLEANUP ==========

  /**
   * Scan Windows scheduled tasks for suspicious entries
   */
  scanTasks: async (): Promise<ApiResponse<{
    tasks: Array<{
      id: string
      task_name: string
      path: string
      status: string
      enabled: boolean
      actions: Array<{
        type: string
        path: string
        arguments: string
        working_directory: string
      }>
      triggers: Array<{
        type: string
        enabled: boolean
      }>
      last_run: string
      next_run: string
      author: string
      risk_score: number
      indicators: string[]
      scanned_at: string
    }>
    statistics: {
      total_suspicious: number
      critical_risk: number
      high_risk: number
      medium_risk: number
      low_risk: number
      by_status: Record<string, number>
      enabled_count: number
      disabled_count: number
    }
    scanned_at: string
  }>> => {
    return client.get<any>('/api/remediation/tasks/scan')
  },

  /**
   * Remove a scheduled task (with automatic backup)
   */
  removeTask: async (data: {
    task_path: string
  }): Promise<ApiResponse<{
    success: boolean
    message: string
    backup_file: string | null
  }>> => {
    return client.post<any>('/api/remediation/tasks/remove', data)
  },

  /**
   * List all task backups
   */
  listTaskBackups: async (): Promise<ApiResponse<{
    backups: Array<{
      filename: string
      filepath: string
      task_path: string
      task_name: string
      author: string
      backed_up_at: string
    }>
  }>> => {
    return client.get<any>('/api/remediation/tasks/backups')
  },

  // ========== DEEP QUARANTINE ==========

  /**
   * Perform deep analysis on a target file/directory
   */
  analyzeDeep: async (data: {
    file_path: string
  }): Promise<ApiResponse<{
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
  }>> => {
    return client.post<any>('/api/remediation/deep-quarantine/analyze', data)
  },

  /**
   * Perform complete removal based on analysis
   */
  removeDeep: async (data: {
    analysis_id: string
    analysis_data: any
  }): Promise<ApiResponse<{
    success: boolean
    message: string
    backup_file: string | null
  }>> => {
    return client.post<any>('/api/remediation/deep-quarantine/remove', data)
  },

  /**
   * List all deep quarantine backups
   */
  listDeepBackups: async (): Promise<ApiResponse<{
    backups: Array<{
      filename: string
      filepath: string
      analysis_id: string
      target_path: string
      threat_level: string
      risk_score: number
      backed_up_at: string
    }>
  }>> => {
    return client.get<any>('/api/remediation/deep-quarantine/backups')
  },

  /**
   * Get remediation service health
   */
  getHealth: async (): Promise<ApiResponse<{
    status: string
    service: string
    features: Record<string, string>
  }>> => {
    return client.get<any>('/api/remediation/health')
  },
}

// ============================================
// PROCESS PROTECTION API
// ============================================

export const processProtectionApi = {
  /**
   * Get process protection status
   */
  getStatus: async (): Promise<ApiResponse<{
    platform: string
    is_protected: boolean
    service_installed: boolean
    can_protect: boolean
    is_admin: boolean
    is_root: boolean
    username: string
    recommendations: string[]
  }>> => {
    return client.get<any>('/api/process-protection/status')
  },

  /**
   * Get protection capabilities
   */
  getCapabilities: async (): Promise<ApiResponse<{
    platform: string
    is_protected: boolean
    service_installed: boolean
    can_protect: boolean
    is_admin: boolean
    is_root: boolean
    username: string
    recommendations: string[]
  }>> => {
    return client.get<any>('/api/process-protection/capabilities')
  },

  /**
   * Check current privileges
   */
  checkPrivileges: async (): Promise<ApiResponse<{
    platform: string
    is_admin: boolean
    is_root: boolean
    can_protect: boolean
    username: string
  }>> => {
    return client.get<any>('/api/process-protection/privileges')
  },

  /**
   * Enable anti-termination protection
   */
  enableAntiTermination: async (): Promise<ApiResponse<{
    success: boolean
    message: string
    privileges?: any
  }>> => {
    return client.post<any>('/api/process-protection/enable-anti-termination', {})
  },

  /**
   * Enable self-healing mechanisms
   */
  enableSelfHealing: async (): Promise<ApiResponse<{
    success: boolean
    message: string
  }>> => {
    return client.post<any>('/api/process-protection/enable-self-healing', {})
  },

  /**
   * Enable maximum protection
   */
  enableMaximumProtection: async (): Promise<ApiResponse<{
    success: boolean
    message: string
    protection: any
  }>> => {
    return client.post<any>('/api/process-protection/enable-maximum-protection', {})
  },

  /**
   * Install as system service
   */
  installService: async (serviceName?: string): Promise<ApiResponse<{
    success: boolean
    message: string
    service_name?: string
    privileges?: any
  }>> => {
    const params = serviceName ? `?service_name=${serviceName}` : ''
    return client.post<any>(`/api/process-protection/install-service${params}`, {})
  },

  /**
   * Get security recommendations
   */
  getRecommendations: async (): Promise<ApiResponse<{
    recommendations: string[]
    current_status: {
      is_protected: boolean
      service_installed: boolean
      can_protect: boolean
    }
  }>> => {
    return client.get<any>('/api/process-protection/recommendations')
  },

  /**
   * Get process protection statistics
   */
  getStatistics: async (): Promise<ApiResponse<{
    platform: string
    is_protected: boolean
    service_installed: boolean
    has_admin_rights: boolean
    has_root_rights: boolean
    can_enable_protection: boolean
    recommendations_count: number
  }>> => {
    return client.get<any>('/api/process-protection/statistics')
  },
}

// ============================================
// PROCESS MONITOR API
// ============================================

export const processMonitorApi = {
  /**
   * Get all running processes
   */
  getProcesses: async (limit?: number): Promise<ApiResponse<{
    total: number
    processes: Array<{
      pid: number
      name: string
      username: string
      cpu_percent: number
      memory_mb: number
      exe_path: string
      cmdline: string
      created_at: string
      suspicious: boolean
    }>
  }>> => {
    return client.get<any>(`/api/process-monitor/processes${limit ? `?limit=${limit}` : ''}`)
  },

  /**
   * Get detected threats
   */
  getThreats: async (params?: {
    threat_type?: string
    severity?: string
    limit?: number
  }): Promise<ApiResponse<{
    total: number
    threats: Array<{
      type: string
      pid: number
      process_name: string
      severity: string
      description: string
      details: any
      detected_at: string
    }>
  }>> => {
    const query = new URLSearchParams(params as any).toString()
    return client.get<any>(`/api/process-monitor/threats${query ? `?${query}` : ''}`)
  },

  /**
   * Get statistics
   */
  getStatistics: async (): Promise<ApiResponse<{
    total_processes: number
    suspicious_processes: number
    total_threats: number
    threats_by_type: Record<string, number>
    threats_by_severity: Record<string, number>
    monitoring_active: boolean
    platform: string
    last_scan: string
  }>> => {
    return client.get<any>('/api/process-monitor/stats')
  },

  /**
   * Trigger manual scan
   */
  triggerScan: async (): Promise<ApiResponse<{
    threats_found: number
    breakdown: {
      process_injection: number
      dll_hijacking: number
      process_hollowing: number
    }
    threats: any[]
  }>> => {
    return client.post<any>('/api/process-monitor/scan', {})
  },

  /**
   * Scan specific process memory
   */
  scanProcessMemory: async (pid: number): Promise<ApiResponse<{
    scan_result: {
      pid: number
      process_name: string
      total_memory_scanned: number
      suspicious_patterns_found: number
      threat_detected: boolean
      scan_time: string
    }
  }>> => {
    return client.get<any>(`/api/process-monitor/scan-memory/${pid}`)
  },

  /**
   * Start background monitoring
   */
  startMonitoring: async (): Promise<ApiResponse<{
    message: string
    scan_interval: number
  }>> => {
    return client.post<any>('/api/process-monitor/start', {})
  },

  /**
   * Stop background monitoring
   */
  stopMonitoring: async (): Promise<ApiResponse<{
    message: string
  }>> => {
    return client.post<any>('/api/process-monitor/stop', {})
  },

  /**
   * Get monitoring status
   */
  getMonitoringStatus: async (): Promise<ApiResponse<{
    monitoring: {
      active: boolean
      scan_interval: number
      platform: string
    }
  }>> => {
    return client.get<any>('/api/process-monitor/status')
  },

  /**
   * Clear all threats
   */
  clearThreats: async (): Promise<ApiResponse<{
    message: string
  }>> => {
    return client.delete<any>('/api/process-monitor/threats')
  },

  /**
   * Set detection mode
   */
  setDetectionMode: async (mode: 'production' | 'demo' | 'testing'): Promise<ApiResponse<{
    mode: string
    message: string
  }>> => {
    return client.post<any>(`/api/process-monitor/set-mode?mode=${mode}`, {})
  },

  /**
   * Get current detection mode
   */
  getDetectionMode: async (): Promise<ApiResponse<{
    mode: string
  }>> => {
    return client.get<any>('/api/process-monitor/get-mode')
  },
}

// ============================================
// REPORTS API
// ============================================

export const reportsApi = {
  /**
   * Get available report types
   */
  getReportTypes: async (): Promise<ApiResponse<{
    report_types: Array<{
      id: string
      name: string
      description: string
      suitable_for: string[]
    }>
  }>> => {
    return client.get<any>('/api/reports/types')
  },

  /**
   * Get reports status
   */
  getStatus: async (): Promise<ApiResponse<{
    available_reports: string[]
    description: string
  }>> => {
    return client.get<any>('/api/reports/status')
  },

  /**
   * Generate compliance report and download PDF
   */
  generateReport: async (data: {
    report_type: string
    date_from?: string | null
    date_to?: string | null
  }): Promise<Blob> => {
    try {
      const token = typeof window !== 'undefined' ? localStorage.getItem('access_token') : null
      
      const headers: Record<string, string> = {
        'Content-Type': 'application/json',
      }

      if (token) {
        headers['Authorization'] = `Bearer ${token}`
      }

      const response = await fetch(`${API_BASE_URL}/api/reports/generate`, {
        method: 'POST',
        headers,
        body: JSON.stringify(data),
      })

      if (!response.ok) {
        throw new Error(`Report generation failed: ${response.statusText}`)
      }

      // Return PDF blob for download
      return await response.blob()
    } catch (error) {
      console.error('Report generation error:', error)
      throw error
    }
  },
}

// ============================================
// EXECUTIVE DASHBOARD API
// ============================================

export const executiveApi = {
  /**
   * Get executive overview with all KPIs
   */
  getOverview: async (): Promise<ApiResponse<{
    success: boolean
    kpis: {
      security_score: number
      threats_blocked: number
      money_saved: number
      mttr_minutes: number
      mttd_minutes: number
      active_honeypots: number
      ai_accuracy: number
    }
    statistics: {
      total_threats: number
      critical_threats: number
      block_rate: number
    }
    generated_at: string
  }>> => {
    return client.get<any>('/api/executive/overview')
  },

  /**
   * Get executive trends for charts
   */
  getTrends: async (days?: number): Promise<ApiResponse<{
    success: boolean
    trends: {
      timeline: Array<{ date: string; threats: number }>
      threat_distribution: Array<{ type: string; count: number }>
      severity_distribution: Array<{ severity: string; count: number }>
    }
    period_days: number
  }>> => {
    return client.get<any>(`/api/executive/trends${days ? `?days=${days}` : ''}`)
  },

  /**
   * Get risk analysis
   */
  getRiskAnalysis: async (): Promise<ApiResponse<{
    success: boolean
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
  }>> => {
    return client.get<any>('/api/executive/risk-analysis')
  },
}

// ============================================
// EXPORTS
// ============================================
export const api = {
  dashboard: dashboardApi,
  threats: threatsApi,
  detection: detectionApi,
  response: responseApi,
  deception: deceptionApi,
  ai: aiApi,
  honeypot: honeypotApi,
  ml: mlApi,
  analytics: analyticsApi,
  emails: emailsApi,
  settings: settingsApi, 
  protection: protectionApi,
  scans: scansApi,
  quarantine: quarantineApi,
  geoAttacks: geoAttacksApi,
  whatIf: whatIfApi,
  exclusions: exclusionsApi,
  profiles: profilesApi, 
  remediation: remediationApi,
  processProtection: processProtectionApi,
  processMonitor: processMonitorApi,  
  reports: reportsApi,  
   executive: executiveApi,  
}

export default api