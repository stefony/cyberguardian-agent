import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import { AuthProvider } from "@/lib/contexts/AuthContext";
import { WebSocketProvider } from "@/lib/contexts/WebSocketContext";
import App from "./App";
import "./globals.css";
import "leaflet/dist/leaflet.css";

const savedTheme = localStorage.getItem('theme') || 'dark';
if (savedTheme === 'dark') document.documentElement.classList.add('dark');

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <BrowserRouter>
      <AuthProvider>
        <WebSocketProvider>
          <App />
        </WebSocketProvider>
      </AuthProvider>
    </BrowserRouter>
  </StrictMode>
);