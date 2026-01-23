import { useLocation, Navigate } from "react-router-dom";
import { useAuth } from "@/contexts/AuthContext";
import { Sidebar } from "./Sidebar";

export function ConditionalLayout({ children }: { children: React.ReactNode }) {
  const { pathname } = useLocation();
  const { isAuthenticated, loading } = useAuth();

  // ✅ Public pages (NO sidebar)
  const isPublicPage =
    pathname.startsWith("/auth") ||
    pathname === "/pricing" ||
    pathname.startsWith("/pricing/");

  if (loading) {
    return (
      <div className="flex h-screen items-center justify-center">
        <div className="text-lg">Loading...</div>
      </div>
    );
  }

  // ✅ Public pages - render without sidebar no matter what
  if (isPublicPage) {
    return <>{children}</>;
  }

  // ✅ Everything else is protected
  if (!isAuthenticated) {
    return <Navigate to="/auth/login" replace />;
  }

  // ✅ Authenticated - show sidebar layout
  return (
    <div className="flex h-screen overflow-hidden">
      <Sidebar />
      <main className="flex-1 overflow-y-auto ml-64">
        <div className="min-h-screen">{children}</div>
      </main>
    </div>
  );
}
