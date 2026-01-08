"use client";

import { Shield, Target, Activity, TrendingUp } from "lucide-react";

interface MITREStatsProps {
  stats: {
    total_tactics: number;
    total_techniques: number;
    total_mappings: number;
    top_mapped_techniques: Array<{
      technique_id: string;
      name: string;
      count: number;
    }>;
  } | null;
  loading: boolean;
}

export default function MITREStats({ stats, loading }: MITREStatsProps) {
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
      label: "Total Tactics",
      value: stats.total_tactics.toString(),
      icon: Shield,
      color: "cyan",
      bgColor: "bg-cyan-500/10",
      iconColor: "text-cyan-400",
      borderColor: "border-cyan-500/20",
      shadowColor: "hover:shadow-cyan-500/30",
    },
    {
      label: "Total Techniques",
      value: stats.total_techniques.toString(),
      icon: Target,
      color: "purple",
      bgColor: "bg-purple-500/10",
      iconColor: "text-purple-400",
      borderColor: "border-purple-500/20",
      shadowColor: "hover:shadow-purple-500/30",
    },
    {
      label: "Threat Mappings",
      value: stats.total_mappings.toString(),
      icon: Activity,
      color: "orange",
      bgColor: "bg-orange-500/10",
      iconColor: "text-orange-400",
      borderColor: "border-orange-500/20",
      shadowColor: "hover:shadow-orange-500/30",
    },
    {
      label: "Top Techniques",
      value: stats.top_mapped_techniques.length.toString(),
      icon: TrendingUp,
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

            {/* Pulse indicator for threat mappings */}
            {card.label === "Threat Mappings" && stats.total_mappings > 0 && (
              <div className="absolute top-4 right-4 flex h-3 w-3">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-orange-400 opacity-75"></span>
                <span className="relative inline-flex rounded-full h-3 w-3 bg-orange-500"></span>
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}