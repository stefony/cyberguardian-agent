"use client";

import { Database, Shield, AlertTriangle, Activity } from "lucide-react";

interface IOCStatsProps {
  stats: {
    total_iocs: number;
    iocs_by_type: Record<string, number>;
    iocs_by_severity: Record<string, number>;
    total_matches: number;
    recent_high_severity: number;
  } | null;
  loading: boolean;
}

export default function IOCStats({ stats, loading }: IOCStatsProps) {
  if (loading) {
    return (
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        {[...Array(4)].map((_, i) => (
          <div
            key={i}
            className="bg-gray-800/50 border border-gray-700 rounded-xl p-6 animate-pulse"
          >
            <div className="h-4 bg-gray-700 rounded w-24 mb-2"></div>
            <div className="h-8 bg-gray-700 rounded w-16"></div>
          </div>
        ))}
      </div>
    );
  }

  if (!stats) return null;

  const statCards = [
    {
      label: "Total IOCs",
      value: stats.total_iocs.toLocaleString(),
      icon: Database,
      color: "cyan",
      bgColor: "bg-cyan-500/10",
      iconColor: "text-cyan-400",
      borderColor: "border-cyan-500/20",
      shadowColor: "hover:shadow-cyan-500/30",
    },
    {
      label: "Threat Matches",
      value: stats.total_matches.toLocaleString(),
      icon: Shield,
      color: "blue",
      bgColor: "bg-blue-500/10",
      iconColor: "text-blue-400",
      borderColor: "border-blue-500/20",
      shadowColor: "hover:shadow-blue-500/30",
    },
    {
      label: "High Severity",
      value: stats.recent_high_severity.toLocaleString(),
      icon: AlertTriangle,
      color: "red",
      bgColor: "bg-red-500/10",
      iconColor: "text-red-400",
      borderColor: "border-red-500/20",
      shadowColor: "hover:shadow-red-500/30",
    },
    {
      label: "Active Sources",
      value: Object.keys(stats.iocs_by_type || {}).length.toString(),
      icon: Activity,
      color: "green",
      bgColor: "bg-green-500/10",
      iconColor: "text-green-400",
      borderColor: "border-green-500/20",
      shadowColor: "hover:shadow-green-500/30",
    },
  ];

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
      {statCards.map((card, index) => {
        const Icon = card.icon;
        return (
          <div
            key={index}
            className={`
              ${card.bgColor} ${card.borderColor} border rounded-xl p-6
              transition-all duration-300 
              hover:scale-105 hover:shadow-lg ${card.shadowColor}
              group cursor-pointer
              relative overflow-hidden
            `}
          >
            {/* Corner glow effect */}
            <div className="absolute top-0 right-0 w-20 h-20 bg-gradient-to-br from-white/5 to-transparent rounded-bl-full opacity-0 group-hover:opacity-100 transition-opacity duration-300" />
            
            <div className="flex items-center justify-between mb-4">
              <div className={`p-3 ${card.bgColor} rounded-lg transition-all duration-300 group-hover:scale-110 group-hover:shadow-lg ${card.shadowColor}`}>
                <Icon className={`w-6 h-6 ${card.iconColor} transition-transform duration-300 group-hover:rotate-12`} />
              </div>
            </div>
            
            <div>
              <p className="text-gray-400 text-sm mb-1 transition-colors duration-300 group-hover:text-gray-300">
                {card.label}
              </p>
              <p className={`text-3xl font-bold ${card.iconColor} transition-all duration-300 group-hover:scale-110 origin-left`}>
                {card.value}
              </p>
            </div>

            {/* Pulse indicator for high severity */}
            {card.label === "High Severity" && stats.recent_high_severity > 0 && (
              <div className="absolute top-4 right-4 flex h-3 w-3">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-red-400 opacity-75"></span>
                <span className="relative inline-flex rounded-full h-3 w-3 bg-red-500"></span>
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}