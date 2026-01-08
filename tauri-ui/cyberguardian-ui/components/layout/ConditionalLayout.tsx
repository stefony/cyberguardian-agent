

import { useLocation } from 'next/navigation';
import { Sidebar } from './Sidebar';

export function ConditionalLayout({ children }: { children: React.ReactNode }) {
  const pathname = useLocation();
  const isAuthPage = pathname?.startsWith('/auth');

  if (isAuthPage) {
    // Auth pages - no sidebar, no protection
    return <>{children}</>;
  }

  // Dashboard pages - with sidebar (NO PROTECTION for now)
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