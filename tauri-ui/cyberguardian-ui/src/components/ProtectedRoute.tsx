import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '@/lib/contexts/AuthContext';

export default function ProtectedRoute({ children }: { children: React.ReactNode }) { 
  const { isAuthenticated, loading } = useAuth();
  const navigate = useNavigate();
  const [checkedAuth, setCheckedAuth] = useState(false);

  useEffect(() => {
    // Check localStorage directly as fallback
    const checkAuth = () => {
      const token = localStorage.getItem('access_token');
      
      // If we have token in localStorage, consider authenticated
      if (token) {
        setCheckedAuth(true);
        return true;
      }
      
      // If no token and not loading, redirect
      if (!loading && !isAuthenticated && !token) {
        navigate('/auth/login');
        return false;
      }
      
      setCheckedAuth(true);
      return true;
    };
    checkAuth();
  }, [isAuthenticated, loading, navigate]);

  // Show loading state while checking
  if (loading || !checkedAuth) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-slate-900 via-purple-900 to-slate-900">
        <div className="text-white text-xl">Loading...</div>
      </div>
    );
  }

  // Check localStorage one more time before rendering
  const token = localStorage.getItem('access_token');
  
  // If we have token OR isAuthenticated, show content
  if (token || isAuthenticated) {
    return <>{children}</>;
  }

  // Otherwise, show nothing (will redirect)
  return null;
}