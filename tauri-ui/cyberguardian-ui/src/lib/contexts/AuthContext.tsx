import { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';

interface User {
  id: string;
  email: string;
  username: string;
  full_name?: string;
  company?: string;
  is_admin: boolean;
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

  useEffect(() => {
    console.log('🔵 AuthProvider useEffect - checking auth...');
    console.log('🔵 Current pathname:', pathname);
    
    // Check for token (priority: access_token > token)
    const token = localStorage.getItem('access_token') || localStorage.getItem('token');
    const userData = localStorage.getItem('user');
    console.log('🔵 Token from localStorage:', token ? 'EXISTS' : 'NULL');
    console.log('🔵 User from localStorage:', userData ? 'EXISTS' : 'NULL');

    if (token) {
      if (userData) {
        // Regular email/password login
        const parsedUser = JSON.parse(userData);
        console.log('✅ Setting user from userData:', parsedUser);
        setUser(parsedUser);
      } else {
        // License-based auth - create minimal user object
        const licenseKey = localStorage.getItem('license_key');
        const licensePlan = localStorage.getItem('license_plan');
        
        console.log('✅ Setting user from license-based auth');
        console.log('   License Key:', licenseKey ? licenseKey.substring(0, 10) + '...' : 'NULL');
        console.log('   License Plan:', licensePlan || 'NULL');
        
        setUser({
          id: 'license-user',
          email: 'license@user',
          username: 'License User',
          is_admin: false,
          is_license: true,
          license_key: licenseKey || undefined,
          plan: licensePlan || undefined
        });
      }
    } else {
      console.log('❌ No token found - user will remain null');
    }
    
    setLoading(false);
    console.log('🔵 Loading set to false');
  }, [pathname]);

  const login = (token: string, userData: User) => {
    console.log('🔵 AuthContext.login() called with:', { token: token.substring(0, 20) + '...', user: userData.email });
    localStorage.setItem('access_token', token);
    localStorage.setItem('user', JSON.stringify(userData));
    setUser(userData);
    console.log('✅ User state updated in AuthContext');
  };
  
  const logout = () => {
    console.log('🔵 AuthContext.logout() called');
    localStorage.removeItem('access_token');
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    localStorage.removeItem('license_key');
    localStorage.removeItem('license_plan');
    localStorage.removeItem('license_expires');
    setUser(null);
    navigate('/auth/login');
  };
  
  const isAuthenticated = !!user;
  
  console.log('🔵 AuthProvider render:', { 
    isAuthenticated, 
    user: user?.email || 'null', 
    loading,
    pathname 
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