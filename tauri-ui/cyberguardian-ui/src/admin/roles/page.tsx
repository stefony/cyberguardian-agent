

import { useState, useEffect } from 'react';
import { 
  ShieldCheckIcon,
  UserGroupIcon,
  EyeIcon,
  ChartBarIcon,
  Cog6ToothIcon,
  SparklesIcon,
  LockClosedIcon,
  CheckCircleIcon,
  XMarkIcon
} from '@heroicons/react/24/outline';
import ProtectedRoute from '@/components/ProtectedRoute';

const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

interface Role {
  id: string;
  name: string;
  display_name: string;
  description: string;
  permissions_count: number;
  users_assigned: number;
  color: string;
  icon: string;
}

export default function RolesPage() {
  const [roles, setRoles] = useState<Role[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedRole, setSelectedRole] = useState<Role | null>(null);

  useEffect(() => {
    fetchRoles();
  }, []);

  const fetchRoles = async () => {
    try {
      const response = await fetch(`${API_URL}/api/roles/`, {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('access_token')}`,
          'Content-Type': 'application/json'
        }
      });
      const data = await response.json();
      
      if (data.success) {
        setRoles(data.roles);
      }
    } catch (error) {
      console.error('Error fetching roles:', error);
    } finally {
      setLoading(false);
    }
  };

  const getRoleConfig = (name: string) => {
    const configs: any = {
      administrator: {
        gradient: 'from-red-500 via-pink-500 to-purple-500',
        bg: 'from-red-900/30 to-purple-900/30',
        border: 'border-red-500/50',
        icon: '👑',
        badge: 'bg-red-500/20 text-red-300 border-red-500/30'
      },
      security_analyst: {
        gradient: 'from-green-500 via-emerald-500 to-teal-500',
        bg: 'from-green-900/30 to-teal-900/30',
        border: 'border-green-500/50',
        icon: '🛡️',
        badge: 'bg-green-500/20 text-green-300 border-green-500/30'
      },
      manager: {
        gradient: 'from-blue-500 via-cyan-500 to-sky-500',
        bg: 'from-blue-900/30 to-cyan-900/30',
        border: 'border-blue-500/50',
        icon: '⚡',
        badge: 'bg-blue-500/20 text-blue-300 border-blue-500/30'
      },
      viewer: {
        gradient: 'from-gray-500 via-slate-500 to-zinc-500',
        bg: 'from-gray-900/30 to-slate-900/30',
        border: 'border-gray-500/50',
        icon: '👀',
        badge: 'bg-gray-500/20 text-gray-300 border-gray-500/30'
      }
    };
    return configs[name] || configs.viewer;
  };

  if (loading) {
    return (
      <ProtectedRoute>
      <div className="flex items-center justify-center h-screen bg-gradient-to-br from-slate-900 via-purple-900 to-slate-900">
        <div className="text-center">
          <div className="relative">
            <div className="animate-spin rounded-full h-32 w-32 border-b-4 border-purple-500 mx-auto"></div>
            <ShieldCheckIcon className="absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2 h-12 w-12 text-purple-400" />
          </div>
          <p className="mt-6 text-purple-300 text-lg font-semibold">Loading roles...</p>
        </div>
      </div>
        </ProtectedRoute>
    );
  }

  return (
    <ProtectedRoute>
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-purple-900 to-slate-900 p-6">
      <div className="max-w-7xl mx-auto space-y-8">
        
        {/* Animated Header */}
        <div className="relative overflow-hidden rounded-3xl bg-gradient-to-r from-pink-600 via-purple-600 to-indigo-600 p-8 shadow-2xl">
          <div className="absolute inset-0 bg-black/20"></div>
          <div className="relative z-10">
            <div className="flex items-center space-x-4 mb-4">
              <div className="p-4 bg-white/20 backdrop-blur-lg rounded-2xl">
                <ShieldCheckIcon className="h-10 w-10 text-white" />
              </div>
              <div>
                <h1 className="text-5xl font-black text-white tracking-tight">Roles & Permissions</h1>
                <p className="text-purple-100 text-lg mt-2">Manage role-based access control</p>
              </div>
            </div>
            
            <div className="flex items-center space-x-6 mt-6">
              <div className="flex items-center space-x-2 bg-white/10 backdrop-blur-lg px-4 py-2 rounded-xl">
                <UserGroupIcon className="h-5 w-5 text-white" />
                <span className="text-white font-semibold">{roles.length} Roles</span>
              </div>
              <div className="flex items-center space-x-2 bg-white/10 backdrop-blur-lg px-4 py-2 rounded-xl">
                <LockClosedIcon className="h-5 w-5 text-white" />
                <span className="text-white font-semibold">Enterprise Security</span>
              </div>
            </div>
          </div>
          
          {/* Decorative elements */}
          <div className="absolute -top-20 -right-20 w-64 h-64 bg-white/10 rounded-full blur-3xl"></div>
          <div className="absolute -bottom-20 -left-20 w-64 h-64 bg-purple-500/20 rounded-full blur-3xl"></div>
        </div>

        {/* Roles Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
          {roles.map((role, index) => {
            const config = getRoleConfig(role.name);
            return (
              <div
                key={role.id}
                onClick={() => setSelectedRole(role)}
                className="group relative bg-slate-800/80 backdrop-blur-xl rounded-3xl border-2 border-purple-500/20 hover:border-purple-500/60 shadow-xl hover:shadow-2xl transition-all duration-500 overflow-hidden cursor-pointer transform hover:-translate-y-3"
                style={{ animationDelay: `${index * 100}ms` }}
              >
                {/* Gradient overlay */}
                <div className={`absolute inset-0 bg-gradient-to-br ${config.gradient} opacity-0 group-hover:opacity-20 transition-opacity duration-500`}></div>
                
                {/* Card Content */}
                <div className="relative p-6">
                  {/* Icon */}
                  <div className="flex justify-center mb-4">
                    <div className={`w-20 h-20 rounded-2xl bg-gradient-to-br ${config.gradient} flex items-center justify-center text-4xl shadow-xl group-hover:scale-110 transition-transform duration-300`}>
                      {config.icon}
                    </div>
                  </div>

                  {/* Role Name */}
                  <h3 className="text-2xl font-bold text-white text-center mb-2 group-hover:scale-105 transition-transform">
                    {role.display_name}
                  </h3>

                  {/* Description */}
                  <p className="text-slate-400 text-sm text-center leading-relaxed mb-6 min-h-[60px]">
                    {role.description}
                  </p>

                  {/* Stats */}
                  <div className="space-y-3">
                    <div className="flex items-center justify-between bg-slate-900/50 rounded-xl px-4 py-3 border border-slate-700/50">
                      <span className="text-slate-400 text-sm font-semibold">Permissions</span>
                      <span className={`px-3 py-1 rounded-full text-sm font-bold border-2 ${config.badge}`}>
                        {role.permissions_count}
                      </span>
                    </div>

                    <div className="flex items-center justify-between bg-slate-900/50 rounded-xl px-4 py-3 border border-slate-700/50">
                      <span className="text-slate-400 text-sm font-semibold">Users</span>
                      <span className="text-white font-bold">{role.users_assigned}</span>
                    </div>
                  </div>

                  {/* View Details Button */}
                  <button className="mt-6 w-full py-3 bg-gradient-to-r from-purple-600 to-pink-600 text-white rounded-xl font-bold hover:shadow-xl transform hover:scale-105 transition-all duration-300 flex items-center justify-center space-x-2">
                    <span>View Details</span>
                    <SparklesIcon className="h-5 w-5 animate-pulse" />
                  </button>
                </div>

                {/* Decorative corner */}
                <div className={`absolute top-0 right-0 w-20 h-20 bg-gradient-to-br ${config.gradient} opacity-20 rounded-bl-full`}></div>
              </div>
            );
          })}
        </div>

        {/* Permissions Overview */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Quick Stats */}
          <div className="bg-slate-800/80 backdrop-blur-xl rounded-3xl p-6 border-2 border-green-500/20 hover:border-green-500/50 transition-all shadow-xl">
            <div className="flex items-center space-x-4 mb-4">
              <div className="p-3 bg-gradient-to-br from-green-500 to-emerald-500 rounded-xl">
                <CheckCircleIcon className="h-6 w-6 text-white" />
              </div>
              <h3 className="text-xl font-bold text-white">Access Control</h3>
            </div>
            <p className="text-slate-400 text-sm leading-relaxed">
              Fine-grained permissions ensure users only access what they need
            </p>
          </div>

          <div className="bg-slate-800/80 backdrop-blur-xl rounded-3xl p-6 border-2 border-blue-500/20 hover:border-blue-500/50 transition-all shadow-xl">
            <div className="flex items-center space-x-4 mb-4">
              <div className="p-3 bg-gradient-to-br from-blue-500 to-cyan-500 rounded-xl">
                <LockClosedIcon className="h-6 w-6 text-white" />
              </div>
              <h3 className="text-xl font-bold text-white">Zero Trust</h3>
            </div>
            <p className="text-slate-400 text-sm leading-relaxed">
              Every action requires explicit permission verification
            </p>
          </div>

          <div className="bg-slate-800/80 backdrop-blur-xl rounded-3xl p-6 border-2 border-purple-500/20 hover:border-purple-500/50 transition-all shadow-xl">
            <div className="flex items-center space-x-4 mb-4">
              <div className="p-3 bg-gradient-to-br from-purple-500 to-pink-500 rounded-xl">
                <ChartBarIcon className="h-6 w-6 text-white" />
              </div>
              <h3 className="text-xl font-bold text-white">Audit Trails</h3>
            </div>
            <p className="text-slate-400 text-sm leading-relaxed">
              Track all permission changes and role assignments
            </p>
          </div>
        </div>

        {/* Role Details Modal */}
        {selectedRole && (
          <div className="fixed inset-0 bg-black/80 backdrop-blur-sm flex items-center justify-center z-50 p-4 animate-fade-in">
            <div className="bg-slate-800 rounded-3xl shadow-2xl max-w-4xl w-full border-2 border-purple-500/30 animate-scale-in max-h-[90vh] overflow-y-auto">
              {/* Modal Header */}
              <div className={`bg-gradient-to-r ${getRoleConfig(selectedRole.name).gradient} p-6 rounded-t-3xl`}>
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-4">
                    <div className="w-16 h-16 bg-white/20 backdrop-blur-lg rounded-2xl flex items-center justify-center text-3xl">
                      {getRoleConfig(selectedRole.name).icon}
                    </div>
                    <div>
                      <h2 className="text-3xl font-bold text-white">{selectedRole.display_name}</h2>
                      <p className="text-white/80 text-sm mt-1">{selectedRole.description}</p>
                    </div>
                  </div>
                  <button
                    onClick={() => setSelectedRole(null)}
                    className="text-white/80 hover:text-white transition-colors"
                  >
                    <XMarkIcon className="h-8 w-8" />
                  </button>
                </div>
              </div>

              {/* Modal Body */}
              <div className="p-8 space-y-6">
                <div className="grid grid-cols-3 gap-4">
                  <div className="bg-slate-900/50 rounded-xl p-4 border border-slate-700/50 text-center">
                    <p className="text-slate-400 text-sm mb-2">Permissions</p>
                    <p className="text-3xl font-bold text-white">{selectedRole.permissions_count}</p>
                  </div>
                  <div className="bg-slate-900/50 rounded-xl p-4 border border-slate-700/50 text-center">
                    <p className="text-slate-400 text-sm mb-2">Users Assigned</p>
                    <p className="text-3xl font-bold text-white">{selectedRole.users_assigned}</p>
                  </div>
                  <div className="bg-slate-900/50 rounded-xl p-4 border border-slate-700/50 text-center">
                    <p className="text-slate-400 text-sm mb-2">Status</p>
                    <div className="flex items-center justify-center space-x-2">
                      <CheckCircleIcon className="h-6 w-6 text-green-400" />
                      <span className="text-white font-bold">Active</span>
                    </div>
                  </div>
                </div>

                {/* Sample Permissions */}
                <div>
                  <h3 className="text-xl font-bold text-white mb-4">Key Permissions</h3>
                  <div className="space-y-2">
                    {['View Threats', 'Run Scans', 'Manage Reports', 'Configure Settings'].map((perm, i) => (
                      <div key={i} className="flex items-center justify-between bg-slate-900/50 rounded-xl px-4 py-3 border border-slate-700/50">
                        <div className="flex items-center space-x-3">
                          <CheckCircleIcon className="h-5 w-5 text-green-400" />
                          <span className="text-white font-semibold">{perm}</span>
                        </div>
                        <span className="text-green-400 text-sm font-bold">Granted</span>
                      </div>
                    ))}
                  </div>
                </div>

                <button
                  onClick={() => setSelectedRole(null)}
                  className="w-full py-3 bg-gradient-to-r from-purple-600 to-pink-600 text-white rounded-xl font-bold hover:shadow-xl transform hover:scale-105 transition-all duration-300"
                >
                  Close
                </button>
              </div>
            </div>
          </div>
        )}

      </div>

      <style jsx>{`
        @keyframes fade-in {
          from { opacity: 0; }
          to { opacity: 1; }
        }
        @keyframes scale-in {
          from { 
            opacity: 0;
            transform: scale(0.95);
          }
          to { 
            opacity: 1;
            transform: scale(1);
          }
        }
        .animate-fade-in {
          animation: fade-in 0.2s ease-out;
        }
        .animate-scale-in {
          animation: scale-in 0.3s ease-out;
        }
      `}</style>
    </div>
    </ProtectedRoute>
  );
}