"use client";
import { httpFetch, honeypotApi } from "@/lib/api";
import { useEffect, useState, useRef } from "react";
import { Activity, MapPin, Clock, AlertCircle, Shield, Wifi, Globe } from "lucide-react";


// Types
interface ThreatEvent {
  id: string;
  timestamp: string;
  time_ago: string;
  event_type: string;
  source: "honeypot" | "threat_detector";
  source_ip: string;
  country: string | null;
  city: string | null;
  severity: "critical" | "high" | "medium" | "low";
  icon: string;
  details: {
    honeypot_type?: string;
    port?: number;
    description?: string;
  };
}

interface LiveFeedResponse {
  success: boolean;
  total_events: number;
  events: ThreatEvent[];
  last_updated: string;
}

const fetchWithAuth = async (endpoint: string) => {
  const token = typeof window !== "undefined" ? localStorage.getItem("access_token") : null;

  const headers: Record<string, string> = {
    "Content-Type": "application/json",
  };
  if (token) headers["Authorization"] = `Bearer ${token}`;

  const response = await httpFetch(endpoint, { headers });

  if (!response.ok) {
    throw new Error(`HTTP error! status: ${response.status}`);
  }

  return response.json();
};




export default function LiveThreatFeed() {
  const [events, setEvents] = useState<ThreatEvent[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [isLive, setIsLive] = useState(true);
  const [newEventIds, setNewEventIds] = useState<Set<string>>(new Set());
  const prevEventsRef = useRef<ThreatEvent[]>([]);
  const [topCountries, setTopCountries] = useState<Record<string, number>>({});

 useEffect(() => {
    fetchLiveFeed();
    fetchTopCountries();
    const interval = setInterval(() => {
      if (isLive) {
        fetchLiveFeed();
      }
    }, 5000);
    return () => clearInterval(interval);
  }, [isLive]);

const fetchLiveFeed = async () => {
  try {
    const data: LiveFeedResponse = await fetchWithAuth('/api/ai/live-feed?limit=50');
    
    if (data.success && data.events) {
      // Detect new events
      const prevIds = new Set(prevEventsRef.current.map((e) => e.id));
      const newIds = new Set<string>();

      data.events.forEach((event) => {
        if (!prevIds.has(event.id)) {
          newIds.add(event.id);
        }
      });

      setNewEventIds(newIds);
      setEvents(data.events);
      prevEventsRef.current = data.events;

      // Clear "new" indicator after 3 seconds
      if (newIds.size > 0) {
        setTimeout(() => {
          setNewEventIds(new Set());
        }, 3000);
      }
    }
  } catch (error) {
    console.error("Failed to fetch live feed:", error);
    // No mock data fallback
  } finally {
    setIsLoading(false);
  }
};

const fetchTopCountries = async () => {
    try {
      const res = await honeypotApi.getStatistics();
      if (res.success && res.data?.top_countries) {
        setTopCountries(res.data.top_countries);
      }
    } catch (e) {
      // silent fail
    }
  };

  const getSeverityColor = (severity: string) => {
    const colors: Record<string, string> = {
      critical: "bg-red-500/20 border-red-500/50 text-red-400",
      high: "bg-orange-500/20 border-orange-500/50 text-orange-400",
      medium: "bg-yellow-500/20 border-yellow-500/50 text-yellow-400",
      low: "bg-blue-500/20 border-blue-500/50 text-blue-400",
    };
    return colors[severity] || "bg-gray-500/20 border-gray-500/50 text-gray-400";
  };

  const getSeverityDot = (severity: string) => {
    const colors: Record<string, string> = {
      critical: "bg-red-500",
      high: "bg-orange-500",
      medium: "bg-yellow-500",
      low: "bg-blue-500",
    };
    return colors[severity] || "bg-gray-500";
  };

  const getSourceIcon = (source: string) => {
    if (source === "honeypot") {
      return <Shield className="w-4 h-4" />;
    }
    return <AlertCircle className="w-4 h-4" />;
  };

  return (
    <div className="card-premium p-6 h-[800px] flex flex-col">
      {/* Header */}
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <Activity className="w-5 h-5 text-purple-500" />
          <h2 className="text-xl font-semibold">Live Threat Feed</h2>
        </div>
        
        <div className="flex items-center gap-3">
          {/* Live indicator */}
          <div className="flex items-center gap-2">
            {isLive ? (
              <>
                <div className="relative">
                  <div className="w-2 h-2 bg-green-500 rounded-full" />
                  <div className="absolute inset-0 w-2 h-2 bg-green-500 rounded-full animate-ping" />
                </div>
                <span className="text-sm text-green-500 font-medium">LIVE</span>
              </>
            ) : (
              <>
                <div className="w-2 h-2 bg-gray-500 rounded-full" />
                <span className="text-sm text-gray-500">PAUSED</span>
              </>
            )}
          </div>

          {/* Toggle button */}
          <button
            onClick={() => setIsLive(!isLive)}
            className={`px-3 py-1 rounded-lg text-sm font-medium transition-colors ${
              isLive
                ? "bg-green-500/20 text-green-400 hover:bg-green-500/30"
                : "bg-gray-500/20 text-gray-400 hover:bg-gray-500/30"
            }`}
          >
            {isLive ? "Pause" : "Resume"}
          </button>
        </div>
      </div>

     {/* Event count */}
      <div className="flex items-start gap-2 mb-4 text-sm text-muted-foreground">
        <Wifi className="w-4 h-4 mt-0.5" />
        <div className="flex-1">
          <span>{events.length} events detected</span>
          <p className="text-xs text-cyan-400 font-medium mt-0.5">
            Global threat intelligence • Not local attacks
          </p>
        </div>
      </div>

      {/* Top Attack Origins */}
      {Object.keys(topCountries).length > 0 && (
        <div className="mb-4 p-3 rounded-lg bg-card/50 border border-border">
          <div className="flex items-center gap-2 mb-2">
            <Globe className="w-4 h-4 text-blue-400" />
            <span className="text-xs font-semibold text-blue-400">Attack Origins</span>
          </div>
          <div className="space-y-1.5">
            {Object.entries(topCountries)
              .sort(([, a], [, b]) => b - a)
              .slice(0, 5)
              .map(([country, count]) => {
                const max = Math.max(...Object.values(topCountries));
                const pct = Math.round((count / max) * 100);
                return (
                  <div key={country} className="flex items-center gap-2">
                    <span className="text-xs text-muted-foreground w-24 truncate">{country}</span>
                    <div className="flex-1 h-1.5 bg-slate-700 rounded-full overflow-hidden">
                      <div
                        className="h-full bg-blue-500 rounded-full"
                        style={{ width: `${pct}%` }}
                      />
                    </div>
                    <span className="text-xs text-muted-foreground w-6 text-right">{count}</span>
                  </div>
                );
              })}
          </div>
        </div>
      )}

      {/* Events list */}
      <div 
        className="flex-1 overflow-y-auto space-y-2 pr-2" 
        style={{
          scrollbarWidth: 'thin',
          scrollbarColor: '#6366f1 #1e293b'
        }}
      >
        {isLoading ? (
          <div className="flex items-center justify-center h-full">
            <div className="text-muted-foreground">Loading events...</div>
          </div>
        ) : events.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-full text-muted-foreground">
            <Activity className="w-12 h-12 mb-2 opacity-50" />
            <p>No recent threats detected</p>
          </div>
        ) : (
          events.map((event) => (
            <div
              key={event.id}
              className={`p-3 rounded-lg border transition-all duration-300 ${
                newEventIds.has(event.id)
                  ? "animate-slide-in bg-purple-500/10 border-purple-500/50"
                  : "bg-card/50 border-border hover:bg-card"
              }`}
            >
              {/* Event header */}
<div className="flex items-start justify-between mb-2">
  <div className="flex items-center gap-2 min-w-0 flex-1">
    {/* Severity dot */}
    <div
      className={`w-2 h-2 rounded-full flex-shrink-0 ${getSeverityDot(
        event.severity
      )}`}
    />
    
    {/* Source icon */}
    <div className="text-muted-foreground flex-shrink-0">
      {getSourceIcon(event.source)}
    </div>
    
    {/* Event type */}
    <span className="text-sm font-medium truncate" title={event.event_type}>
      {event.event_type}
    </span>
  </div>

  {/* Time ago */}
  <div className="flex items-center gap-1 text-xs text-muted-foreground flex-shrink-0">
    <Clock className="w-3 h-3" />
    <span>{event.time_ago}</span>
  </div>
</div>

{/* Event details */}
<div className="space-y-1 text-xs text-muted-foreground">
  <div className="flex items-center gap-2">
    <span className="font-mono">{event.source_ip}</span>
    {event.country && (
      <>
        <span>•</span>
        <div className="flex items-center gap-1">
          <MapPin className="w-3 h-3" />
          <span>
            {event.city}, {event.country}
          </span>
        </div>
      </>
    )}
  </div>

  {/* Additional details */}
  {event.source === "honeypot" && event.details.honeypot_type && (
    <div className="flex items-center gap-1">
      <span className="badge badge--xs">
        {event.details.honeypot_type}
      </span>
      {event.details.port && (
        <span className="badge badge--xs">
          Port {event.details.port}
        </span>
      )}
    </div>
  )}

  {event.source === "threat_detector" && event.details.description && (
    <p className="text-xs italic">{event.details.description}</p>
  )}
</div>

{/* Severity badge */}
<div className="mt-2">
  <span
    className={`inline-block px-2 py-0.5 rounded text-xs font-medium ${
      event.severity === "critical"
        ? "bg-red-500/20 text-red-400"
        : event.severity === "high"
        ? "bg-orange-500/20 text-orange-400"
        : event.severity === "medium"
        ? "bg-yellow-500/20 text-yellow-400"
        : "bg-blue-500/20 text-blue-400"
    }`}
  >
    {event.severity.toUpperCase()}
  </span>
</div>
</div>
))
)}
</div>
</div>
);
}