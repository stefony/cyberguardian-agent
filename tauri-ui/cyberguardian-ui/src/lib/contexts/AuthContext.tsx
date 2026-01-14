import React, { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';

export interface User {
  id: string;
  email: string;
  username?: string;
  is_admin?: boolean;
  is_license?: boolean;
  license_key?: string;
  plan?: string;
}

interface AuthContextType {
  user: User | null;
  loading: boolean;
  login: (token: string, userData: User) => void;
  logout: () => void;
  isAuthenticated: boolean;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();
  const location = useLocation();
  const pathname = location.pathname;

  // Desktop App Mode - No authentication required
 useEffect(() => {
  console.log('🔵 AuthProvider useEffect - checking auth...');
  
  // Check for existing token and user data
  const token = localStorage.getItem('access_token');
  const userData = localStorage.getItem('user');
  const licenseKey = localStorage.getItem('license_key');
  const licensePlan = localStorage.getItem('license_plan');
  
  if (token) {
    if (userData) {
      // User data exists
      setUser(JSON.parse(userData));
    } else if (licenseKey) {
      // License-based auth
      setUser({
        id: 'license-user',
        email: 'license@user',
        username: 'License User',
        is_admin: false,
        is_license: true,
        license_key: licenseKey,
        plan: licensePlan || undefined
      });
    }
  }
  
  setLoading(false);
}, []);
  const login = (token: string, userData: User) => {
    console.log('🔵 AuthContext.login() called with:', { 
      token: token.substring(0, 20) + '...', 
      user: userData.email 
    });
    localStorage.setItem('access_token', token);
    localStorage.setItem('user', JSON.stringify(userData));
    setUser(userData);
    console.log('✅ User state updated in AuthContext');
  };

  const logout = () => {
    console.log('🔵 AuthContext.logout() - Desktop mode, staying on dashboard');
    // For desktop app, just clear data but keep desktop user
    localStorage.clear();
    setUser({
      id: 'desktop-user',
      email: 'desktop@cyberguardian.local',
      username: 'Desktop User',
      is_admin: true,
      is_license: true,
      license_key: 'DESKTOP-MODE',
      plan: 'DESKTOP'
    });
    navigate('/dashboard');
  };

  const isAuthenticated = !!user;

  console.log('🔵 AuthProvider render:', { 
    isAuthenticated, 
    user: user?.email || 'null', 
    loading
  });

  return (
    <AuthContext.Provider value={{ user, loading, login, logout, isAuthenticated }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}