import { useLocation, Navigate } from 'react-router-dom';
import { useAuth } from '@/contexts/AuthContext';
import { Sidebar } from './Sidebar';

export function ConditionalLayout({ children }: { children: React.ReactNode }) {
  const location = useLocation();
  const pathname = location.pathname;
  const { isAuthenticated, loading } = useAuth();
  
  const isAuthPage = pathname?.startsWith('/auth');

  // Show loading spinner while checking auth
  if (loading) {
    return (
      <div className="flex h-screen items-center justify-center">
        <div className="text-lg">Loading...</div>
      </div>
    );
  }

  if (isAuthPage) {
    // Auth pages - no sidebar, no protection
    return <>{children}</>;
  }

  // Protected dashboard pages - check authentication
  if (!isAuthenticated) {
    console.log('❌ Not authenticated - redirecting to login');
    return <Navigate to="/auth/login" replace />;
  }

  // Authenticated - show with sidebar
  return (
    <div className="flex h-screen overflow-hidden">
      <Sidebar />
      <main className="flex-1 overflow-y-auto ml-64">
        <div className="min-h-screen">
          {children}
        </div>
      </main>
    </div>
  );
}