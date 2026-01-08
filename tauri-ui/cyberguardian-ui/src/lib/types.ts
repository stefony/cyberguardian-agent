/**
 * CyberGuardian Dashboard - Type Definitions
 * Complete TypeScript types for the entire dashboard
 */

// ============================================
// THREAT & ALERT TYPES
// ============================================

export type ThreatLevel = 'critical' | 'high' | 'medium' | 'low' | 'info'

export type ThreatType = 
  | 'malware'
  | 'ransomware'
  | 'phishing'
  | 'c2_communication'
  | 'data_exfiltration'
  | 'brute_force'
  | 'sql_injection'
  | 'xss'
  | 'privilege_escalation'
  | 'suspicious_activity'

export interface Threat {
  id: string
  type: ThreatType
  level: ThreatLevel
  title: string
  description: string
  source: string
  target?: string
  timestamp: string
  status: 'active' | 'blocked' | 'quarantined' | 'resolved'
  indicators: string[]
  mitre_technique?: string
}
// Backend API Threat Response
export interface ThreatResponse {
  id: number;
  timestamp: string;
  source_ip: string;
  threat_type: string;
  severity: string;
  description: string;
  status: string;
  details?: any;
  confidence_score?: number;  // ← ДОБАВИ ТОЗИ РЕД
  created_at: string;
  updated_at: string;
  correlation?: {
    threat_id: number;
    matched_iocs: any[];
    match_count: number;
    correlation_score: number;
  } | null;
}

// ADD THIS AFTER ThreatResponse:
export interface ThreatStats {
  total_threats: number
  severity_breakdown: Record<string, number>
  status_breakdown: Record<string, number>
  last_updated: string
}

export interface Alert {
  id: string
  threat: Threat
  actions_taken: string[]
  recommendation: string
  can_block: boolean
  can_quarantine: boolean
  can_kill: boolean
}

// ============================================
// DETECTION TYPES
// ============================================

export interface DetectionResult {
  id: string
  detection_type: 'signature' | 'behavioral' | 'heuristic' | 'ml'
  threat_name: string
  confidence: number
  severity: number
  file_path?: string
  process_name?: string
  process_id?: number
  hash?: string
  timestamp: string
}

export interface DetectionStats {
  signature_detections: number
  behavioral_detections: number
  heuristic_detections: number
  ml_detections: number
  total_scans: number
  false_positives: number
}

// ============================================
// HONEYPOT & DECEPTION TYPES
// ============================================

export interface Honeypot {
  id: string
  name: string
  type: 'file' | 'folder' | 'credential' | 'network'
  path: string
  access_count: number
  last_accessed?: string
  status: 'active' | 'triggered' | 'disabled'
}

// ADD THIS NEW TYPE:
// Backend API Honeypot Response (different from the generic Honeypot type)
export interface HoneypotResponse {
  id: number
  name: string
  type: string
  status: string
  ip_address: string
  port: number
  description: string
  interactions: number
  last_interaction?: string
  created_at: string
  updated_at: string
}

export interface AttackerSession {
  id: string
  source_ip: string
  honeypot_accessed: string[]
  actions: AttackAction[]
  skill_level: 'script_kiddie' | 'intermediate' | 'advanced' | 'expert' | 'apt'
  tools_used: string[]
  started_at: string
  ended_at?: string
  threat_score: number
}

export interface AttackAction {
  id: string
  action_type: string
  timestamp: string
  details: string
}

// ============================================
// PREDICTION & AI TYPES
// ============================================

export interface Prediction {
  id: string
  prediction_type: string
  probability: number
  threat_level: ThreatLevel
  estimated_time: string
  kill_chain_phase: string
  confidence: number
  indicators: string[]
  recommendations: string[]
  risk_score: number
  timestamp: string
}

export interface RiskForecast {
  period_start: string
  period_end: string
  overall_risk: number
  threat_breakdown: Record<string, number>
  peak_risk_times: string[]
  vulnerable_assets: string[]
}

export interface NLPAnalysis {
  threat_type: string
  confidence: number
  risk_score: number
  sentiment: string
  indicators: string[]
  recommendations: string[]
}

// ============================================
// SYSTEM STATUS TYPES
// ============================================

export interface SystemStatus {
  status: 'protected' | 'warning' | 'critical' | 'offline'
  overall_health: number
  components: ComponentStatus[]
  active_threats: number
  threats_blocked: number
  last_updated: string
}

export interface ComponentStatus {
  name: string
  status: 'operational' | 'degraded' | 'offline'
  health: number
  message?: string
}

// ============================================
// STATISTICS TYPES
// ============================================

export interface DashboardStats {
  threats_detected: number
  threats_blocked: number
  honeypots_triggered: number
  attacks_prevented: number
  system_health: number
  uptime: string
}

export interface HealthData {
  status: string
  timestamp?: string
  uptime_seconds?: number
  uptime?: string
  version?: string
  platform?: string
  cpu_usage?: number
  memory_usage?: number
  threats_blocked?: number
  system?: {
    platform: string
    cpu_percent: number
    memory_percent: number
  }
}

export interface TimeSeriesData {
  timestamp: string
  value: number
}

export interface ChartData {
  name: string
  value: number
  color?: string
}

// ============================================
// RESPONSE TYPES
// ============================================

export interface ResponseAction {
  action_type: 'block_ip' | 'kill_process' | 'quarantine_file' | 'isolate_network' | 'rollback'
  target: string
  reason: string
  timestamp: string
  success: boolean
  message?: string
}

export interface ResponseHistory {
  id: string
  action: ResponseAction
  user?: string
  automated: boolean
}

// ============================================
// SETTINGS TYPES
// ============================================

export interface UserSettings {
  theme: 'dark' | 'light'
  notifications_enabled: boolean
  sound_alerts: boolean
  auto_response: boolean
  response_mode: 'automatic' | 'interactive' | 'passive'
  defense_level: 'strict' | 'normal' | 'relaxed'
}

export interface LicenseInfo {
  tier: 'free' | 'pro' | 'business' | 'enterprise'
  expires_at?: string
  features: string[]
}

// ============================================
// API RESPONSE TYPES
// ============================================

export interface ApiResponse<T> {
  success: boolean
  data?: T
  error?: string
  message?: string
}

export interface PaginatedResponse<T> {
  data: T[]
  total: number
  page: number
  per_page: number
  total_pages: number
}

// ==== ML types ====
export interface MLStatus {
  model_trained: boolean;
  training_date: string | null;
  training_samples: number;
  anomaly_detector_available: boolean;
  behavior_clusterer_available: boolean;
  feature_count: number;
  features: string[];

  // diagnostics
  training_data_present?: boolean;
  training_data_lines?: number | null;
  training_data_size?: number | null;
  training_data_path?: string | null;
}

export interface MLTrainingResponse {
  success: boolean;
  training_samples?: number;
  n_clusters?: number;
  silhouette_score?: number | null;
  mean_anomaly_score?: number | null;
  training_date?: string | null;
  error?: string | null;
}

export interface MLThreatScore {
  threat_score: number;
  threat_level: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  is_anomaly: boolean;
  anomaly_score: number;
  behavior_cluster: string;
  confidence: number;
}

export interface MLAnomalyPrediction {
  is_anomaly: boolean;
  anomaly_score: number;
  confidence: number;
  threshold?: number;
}

export interface MLBehaviorAnalysis {
  cluster: number;
  cluster_name: string;
  n_clusters?: number;
}

export interface MLMetrics {
  trained: boolean;
  samples: number;
  n_clusters?: number | null;
  silhouette?: number | null;
  mean_anomaly?: number | null;
  labeled_count: number;
  classifier_available: boolean;
  training_date?: string | null;
}

export interface MLThresholds {
  anomaly_threshold: number;
}


// ============================================
// NOTIFICATION TYPES
// ============================================

export interface Notification {
  id: string
  type: 'success' | 'error' | 'warning' | 'info'
  title: string
  message: string
  timestamp: string
  read: boolean
  action_url?: string
}

// ============================================
// FILTER & SEARCH TYPES
// ============================================

export interface FilterOptions {
  threat_levels?: ThreatLevel[]
  threat_types?: ThreatType[]
  date_range?: {
    start: string
    end: string
  }
  search_query?: string
  status?: string[]
}

export interface SortOptions {
  field: string
  direction: 'asc' | 'desc'
}