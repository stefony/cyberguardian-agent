import "./globals.css";
import "leaflet/dist/leaflet.css";
import { Outlet } from "react-router-dom";
import { ConditionalLayout } from "@/components/layout/ConditionalLayout";
import { Toaster } from "sonner";

export default function RootLayout() {
  return (
    <div className="font-sans antialiased bg-dark-bg text-dark-text">
      <ConditionalLayout>
        <Outlet />
      </ConditionalLayout>
      {/* Global toast notifications */}
      <Toaster richColors position="top-right" />
    </div>
  );
}