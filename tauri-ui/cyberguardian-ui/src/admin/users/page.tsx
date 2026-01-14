

import { useState, useEffect, useCallback } from 'react';
import { 
  UserGroupIcon,
  PlusIcon,
  EnvelopeIcon,
  ShieldCheckIcon,
  PencilIcon,
  TrashIcon,
  CheckCircleIcon,
  XCircleIcon,
  MagnifyingGlassIcon,
  FunnelIcon,
  SparklesIcon,
  UserCircleIcon
} from '@heroicons/react/24/outline';
import ProtectedRoute from '@/components/ProtectedRoute';

const API_URL = process.env.NEXT_PUBLIC_API_URL || 'https://cyberguardian-backend-production.up.railway.app';

interface User {
  id: string;
  username: string;
  email: string;
  full_name?: string;
  role: string;
  role_display: string;
  is_active: number;
  assigned_at: string;
}

export default function UsersPage() {
  const [users, setUsers] = useState<User[]>([]);
  const [filteredUsers, setFilteredUsers] = useState<User[]>([]);
  const [loading, setLoading] = useState(true);
  const [showInviteModal, setShowInviteModal] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [roleFilter, setRoleFilter] = useState('all');
  const [inviteData, setInviteData] = useState({
    email: '',
    role: 'viewer',
    message: ''
  });

  useEffect(() => {
    fetchUsers();
  }, []);

  const filterUsers = useCallback(() => {
    let filtered = users;

    if (searchQuery) {
      filtered = filtered.filter(user =>
        user.username.toLowerCase().includes(searchQuery.toLowerCase()) ||
        user.email.toLowerCase().includes(searchQuery.toLowerCase()) ||
        (user.full_name && user.full_name.toLowerCase().includes(searchQuery.toLowerCase()))
      );
    }

    if (roleFilter !== 'all') {
      filtered = filtered.filter(user => user.role === roleFilter);
    }

    setFilteredUsers(filtered);
  }, [users, searchQuery, roleFilter]);

  useEffect(() => {
    filterUsers();
  }, [filterUsers]);

  const fetchUsers = async () => {
    try {
      const response = await fetch(`${API_URL}/api/users/`, {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('access_token')}`,
          'Content-Type': 'application/json'
        }
      });
      const data = await response.json();
      
      if (data.success) {
        setUsers(data.users);
      }
    } catch (error) {
      console.error('Error fetching users:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleInviteUser = async (e: React.FormEvent) => {
    e.preventDefault();
    
    try {
      const response = await fetch(`${API_URL}/api/users/invite`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('access_token')}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(inviteData)
      });
      
      const data = await response.json();
      
      if (data.success) {
        setShowInviteModal(false);
        setInviteData({ email: '', role: 'viewer', message: '' });
        alert('Invitation sent successfully!');
      }
    } catch (error) {
      console.error('Error inviting user:', error);
    }
  };

  const getRoleConfig = (role: string) => {
    const configs: any = {
      admin: {
        gradient: 'from-red-500 to-pink-500',
        bg: 'bg-red-500/10',
        text: 'text-red-400',
        icon: '👑',
        border: 'border-red-500/30'
      },
      manager: {
        gradient: 'from-blue-500 to-cyan-500',
        bg: 'bg-blue-500/10',
        text: 'text-blue-400',
        icon: '⚡',
        border: 'border-blue-500/30'
      },
      analyst: {
        gradient: 'from-green-500 to-emerald-500',
        bg: 'bg-green-500/10',
        text: 'text-green-400',
        icon: '🛡️',
        border: 'border-green-500/30'
      },
      viewer: {
        gradient: 'from-gray-500 to-slate-500',
        bg: 'bg-gray-500/10',
        text: 'text-gray-400',
        icon: '👀',
        border: 'border-gray-500/30'
      }
    };
    return configs[role] || configs.viewer;
  };

  const getAvatarGradient = (username: string) => {
    const gradients = [
      'from-purple-500 to-pink-500',
      'from-blue-500 to-cyan-500',
      'from-green-500 to-emerald-500',
      'from-orange-500 to-red-500',
      'from-indigo-500 to-purple-500',
      'from-yellow-500 to-orange-500'
    ];
    const index = username.charCodeAt(0) % gradients.length;
    return gradients[index];
  };

  if (loading) {
    return (
      <ProtectedRoute>
      <div className="flex items-center justify-center h-screen bg-gradient-to-br from-slate-900 via-purple-900 to-slate-900">
        <div className="text-center">
          <div className="relative">
            <div className="animate-spin rounded-full h-32 w-32 border-b-4 border-green-500 mx-auto"></div>
            <UserGroupIcon className="absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2 h-12 w-12 text-green-400" />
          </div>
          <p className="mt-6 text-green-300 text-lg font-semibold">Loading users...</p>
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
        <div className="relative overflow-hidden rounded-3xl bg-gradient-to-r from-green-600 via-emerald-600 to-teal-600 p-8 shadow-2xl">
          <div className="absolute inset-0 bg-black/20"></div>
          <div className="relative z-10">
            <div className="flex items-center justify-between">
              <div className="space-y-4">
                <div className="flex items-center space-x-4">
                  <div className="p-4 bg-white/20 backdrop-blur-lg rounded-2xl">
                    <UserGroupIcon className="h-10 w-10 text-white" />
                  </div>
                  <div>
                    <h1 className="text-5xl font-black text-white tracking-tight">Users Management</h1>
                    <p className="text-green-100 text-lg mt-2">Manage team members and permissions</p>
                  </div>
                </div>
              </div>
              
              <button
                onClick={() => setShowInviteModal(true)}
                className="group relative px-8 py-4 bg-white text-green-600 rounded-2xl font-bold text-lg shadow-xl hover:shadow-2xl transform hover:scale-105 transition-all duration-300"
              >
                <div className="flex items-center space-x-3">
                  <EnvelopeIcon className="h-6 w-6 group-hover:rotate-12 transition-transform duration-300" />
                  <span>Invite User</span>
                  <SparklesIcon className="h-5 w-5 animate-pulse" />
                </div>
              </button>
            </div>
          </div>
          
          {/* Decorative elements */}
          <div className="absolute -top-20 -right-20 w-64 h-64 bg-white/10 rounded-full blur-3xl"></div>
          <div className="absolute -bottom-20 -left-20 w-64 h-64 bg-green-500/20 rounded-full blur-3xl"></div>
        </div>

        {/* Filters */}
        <div className="bg-slate-800/80 backdrop-blur-xl rounded-2xl shadow-xl p-6 border-2 border-purple-500/20">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Search */}
            <div className="relative">
              <MagnifyingGlassIcon className="absolute left-4 top-1/2 transform -translate-y-1/2 h-5 w-5 text-purple-400" />
              <input
                type="text"
                placeholder="Search by name, email, or username..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full pl-12 pr-4 py-3 bg-slate-900 border-2 border-slate-700 rounded-xl text-white placeholder-slate-500 focus:border-purple-500 focus:ring-4 focus:ring-purple-500/20 transition-all"
              />
            </div>

            {/* Role Filter */}
            <div className="relative">
              <FunnelIcon className="absolute left-4 top-1/2 transform -translate-y-1/2 h-5 w-5 text-purple-400" />
              <select
                value={roleFilter}
                onChange={(e) => setRoleFilter(e.target.value)}
                className="w-full pl-12 pr-4 py-3 bg-slate-900 border-2 border-slate-700 rounded-xl text-white focus:border-purple-500 focus:ring-4 focus:ring-purple-500/20 transition-all appearance-none"
              >
                <option value="all">All Roles</option>
                <option value="admin">👑 Admin</option>
                <option value="manager">⚡ Manager</option>
                <option value="analyst">🛡️ Analyst</option>
                <option value="viewer">👀 Viewer</option>
              </select>
            </div>
          </div>

          <div className="mt-4 flex items-center justify-between">
            <span className="text-slate-400 text-sm">
              Showing <span className="font-bold text-purple-400">{filteredUsers.length}</span> of <span className="font-bold text-purple-400">{users.length}</span> users
            </span>
            <div className="flex items-center space-x-2 text-green-400 text-sm">
              <CheckCircleIcon className="h-4 w-4" />
              <span className="font-semibold">All systems operational</span>
            </div>
          </div>
        </div>

        {/* Users Grid/Cards */}
        {filteredUsers.length === 0 ? (
          <div className="text-center py-20 bg-slate-800/50 backdrop-blur-xl rounded-3xl border-2 border-purple-500/20 shadow-2xl">
            <UserCircleIcon className="h-24 w-24 text-purple-400/50 mx-auto mb-6" />
            <h3 className="text-3xl font-bold text-white mb-3">No Users Found</h3>
            <p className="text-purple-300 text-lg mb-8">
              {searchQuery || roleFilter !== 'all' ? 'Try adjusting your filters' : 'Invite your first team member'}
            </p>
            <button
              onClick={() => setShowInviteModal(true)}
              className="px-8 py-4 bg-gradient-to-r from-green-600 to-emerald-600 text-white rounded-xl font-bold text-lg hover:shadow-2xl transform hover:scale-105 transition-all duration-300"
            >
              <div className="flex items-center space-x-2">
                <EnvelopeIcon className="h-6 w-6" />
                <span>Invite User</span>
              </div>
            </button>
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {filteredUsers.map((user, index) => {
              const roleConfig = getRoleConfig(user.role);
              const avatarGradient = getAvatarGradient(user.username);
              
              return (
                <div
                  key={user.id}
                  className="group bg-slate-800/80 backdrop-blur-xl rounded-3xl border-2 border-purple-500/20 hover:border-purple-500/50 shadow-xl hover:shadow-2xl transition-all duration-500 overflow-hidden transform hover:-translate-y-2"
                  style={{ animationDelay: `${index * 50}ms` }}
                >
                  {/* Card Header */}
                  <div className="relative p-6 bg-gradient-to-br from-slate-900/50 to-transparent">
                    <div className="flex items-start space-x-4">
                      {/* Avatar */}
                      <div className={`flex-shrink-0 w-16 h-16 bg-gradient-to-br ${avatarGradient} rounded-2xl flex items-center justify-center text-white text-2xl font-bold shadow-xl group-hover:scale-110 transition-transform duration-300`}>
                        {user.username.charAt(0).toUpperCase()}
                      </div>
                      
                      <div className="flex-1 min-w-0">
                        <h3 className="text-xl font-bold text-white truncate group-hover:text-purple-300 transition-colors">
                          {user.username}
                        </h3>
                        {user.full_name && (
                          <p className="text-sm text-slate-400 truncate">{user.full_name}</p>
                        )}
                        <p className="text-xs text-slate-500 mt-1 truncate">{user.email}</p>
                      </div>
                    </div>

                    {/* Role Badge */}
                    <div className={`mt-4 inline-flex items-center space-x-2 px-4 py-2 rounded-full text-sm font-bold border-2 ${roleConfig.bg} ${roleConfig.text} ${roleConfig.border}`}>
                      <span>{roleConfig.icon}</span>
                      <span>{user.role_display}</span>
                    </div>
                  </div>

                  {/* Card Body */}
                  <div className="p-6 space-y-4">
                    {/* Status */}
                    <div className="flex items-center justify-between bg-slate-900/50 rounded-xl px-4 py-3 border border-slate-700/50">
                      <span className="text-slate-400 text-sm font-semibold">Status</span>
                      {user.is_active ? (
                        <div className="flex items-center space-x-2">
                          <CheckCircleIcon className="h-5 w-5 text-green-400 animate-pulse" />
                          <span className="text-green-400 font-bold text-sm">Active</span>
                        </div>
                      ) : (
                        <div className="flex items-center space-x-2">
                          <XCircleIcon className="h-5 w-5 text-red-400" />
                          <span className="text-red-400 font-bold text-sm">Inactive</span>
                        </div>
                      )}
                    </div>

                    {/* Joined Date */}
                    <div className="flex items-center justify-between bg-slate-900/50 rounded-xl px-4 py-3 border border-slate-700/50">
                      <span className="text-slate-400 text-sm font-semibold">Joined</span>
                      <span className="text-white font-semibold text-sm">
                        {new Date(user.assigned_at).toLocaleDateString('en-US', { 
                          month: 'short', 
                          day: 'numeric',
                          year: 'numeric'
                        })}
                      </span>
                    </div>
                  </div>

                  {/* Card Actions */}
                  <div className="bg-slate-900/50 px-6 py-4 flex items-center justify-end space-x-2 border-t border-slate-700/50">
                    <button className="p-2 text-blue-400 hover:bg-blue-500/10 rounded-lg transition-all transform hover:scale-110">
                      <PencilIcon className="h-5 w-5" />
                    </button>
                    <button className="p-2 text-red-400 hover:bg-red-500/10 rounded-lg transition-all transform hover:scale-110">
                      <TrashIcon className="h-5 w-5" />
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        )}

        {/* Invite User Modal */}
        {showInviteModal && (
          <div className="fixed inset-0 bg-black/80 backdrop-blur-sm flex items-center justify-center z-50 p-4 animate-fade-in">
            <div className="bg-slate-800 rounded-3xl shadow-2xl max-w-2xl w-full border-2 border-green-500/30 animate-scale-in">
              {/* Modal Header */}
              <div className="bg-gradient-to-r from-green-600 to-emerald-600 p-6 rounded-t-3xl">
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-3">
                    <div className="p-3 bg-white/20 backdrop-blur-lg rounded-xl">
                      <EnvelopeIcon className="h-6 w-6 text-white" />
                    </div>
                    <h2 className="text-2xl font-bold text-white">Invite User</h2>
                  </div>
                  <button
                    onClick={() => setShowInviteModal(false)}
                    className="text-white/80 hover:text-white transition-colors"
                  >
                    <XCircleIcon className="h-7 w-7" />
                  </button>
                </div>
              </div>

              {/* Modal Body */}
              <form onSubmit={handleInviteUser} className="p-8 space-y-6">
                <div>
                  <label className="block text-sm font-bold text-green-300 mb-3">
                    Email Address *
                  </label>
                  <input
                    type="email"
                    required
                    value={inviteData.email}
                    onChange={(e) => setInviteData({ ...inviteData, email: e.target.value })}
                    className="w-full px-4 py-3 bg-slate-900 border-2 border-slate-700 rounded-xl text-white placeholder-slate-500 focus:border-green-500 focus:ring-4 focus:ring-green-500/20 transition-all"
                    placeholder="user@example.com"
                  />
                </div>

                <div>
                  <label className="block text-sm font-bold text-green-300 mb-3">
                    Role *
                  </label>
                  <select
                    value={inviteData.role}
                    onChange={(e) => setInviteData({ ...inviteData, role: e.target.value })}
                    className="w-full px-4 py-3 bg-slate-900 border-2 border-slate-700 rounded-xl text-white focus:border-green-500 focus:ring-4 focus:ring-green-500/20 transition-all"
                  >
                    <option value="viewer">👀 Viewer - Read-only access</option>
                    <option value="analyst">🛡️ Analyst - Can analyze and scan</option>
                    <option value="manager">⚡ Manager - Can manage threats & scans</option>
                    <option value="admin">👑 Admin - Full access</option>
                  </select>
                </div>

                <div>
                  <label className="block text-sm font-bold text-green-300 mb-3">
                    Personal Message (Optional)
                  </label>
                  <textarea
                    value={inviteData.message}
                    onChange={(e) => setInviteData({ ...inviteData, message: e.target.value })}
                    className="w-full px-4 py-3 bg-slate-900 border-2 border-slate-700 rounded-xl text-white placeholder-slate-500 focus:border-green-500 focus:ring-4 focus:ring-green-500/20 transition-all resize-none"
                    rows={3}
                    placeholder="Add a personal note to the invitation..."
                  />
                </div>

                <div className="flex items-center justify-end space-x-4 pt-6 border-t border-slate-700">
                  <button
                    type="button"
                    onClick={() => setShowInviteModal(false)}
                    className="px-6 py-3 border-2 border-slate-600 text-slate-300 rounded-xl hover:bg-slate-700 font-semibold transition-all"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    className="px-8 py-3 bg-gradient-to-r from-green-600 to-emerald-600 text-white rounded-xl font-bold hover:shadow-2xl transform hover:scale-105 transition-all duration-300"
                  >
                    Send Invitation
                  </button>
                </div>
              </form>
            </div>
          </div>
        )}

      </div>

      
    </div>
      </ProtectedRoute>
  );
}

