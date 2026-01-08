'use client'

import { useEffect, useState } from 'react'
import dynamic from 'next/dynamic'
import { api } from '@/lib/api'

// Dynamically import Leaflet to avoid SSR issues
const MapContainer = dynamic(
  () => import('react-leaflet').then((mod) => mod.MapContainer),
  { ssr: false }
)
const TileLayer = dynamic(
  () => import('react-leaflet').then((mod) => mod.TileLayer),
  { ssr: false }
)
const CircleMarker = dynamic(
  () => import('react-leaflet').then((mod) => mod.CircleMarker),
  { ssr: false }
)
const Popup = dynamic(
  () => import('react-leaflet').then((mod) => mod.Popup),
  { ssr: false }
)

interface GeoAttack {
  id: number
  timestamp: string
  source_ip: string
  action: string
  country: string
  city: string
  latitude: number
  longitude: number
  honeypot_id: number
}

export default function HoneypotMap() {
  const [attacks, setAttacks] = useState<GeoAttack[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    loadGeoAttacks()
  }, [])

  const loadGeoAttacks = async () => {
    try {
      const response = await api.geoAttacks.getGeoAttacks(100)
      if (response.success && response.data) {
        setAttacks(response.data.attacks || [])
      }
    } catch (error) {
      console.error('Failed to load geo attacks:', error)
    } finally {
      setLoading(false)
    }
  }

  if (loading) {
    return (
      <div className="h-[600px] bg-gray-900 rounded-lg flex items-center justify-center">
        <p className="text-gray-400">Loading map...</p>
      </div>
    )
  }

  return (
    <div className="h-[600px] bg-gray-900 rounded-lg overflow-hidden">
      {typeof window !== 'undefined' && (
        <MapContainer
          center={[20, 0]}
          zoom={2}
          style={{ height: '100%', width: '100%' }}
          className="z-0"
        >
          <TileLayer
            attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a>'
            url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
          />
          
          {attacks.map((attack) => (
            <CircleMarker
              key={attack.id}
              center={[attack.latitude, attack.longitude]}
              radius={8}
              fillColor="#ef4444"
              color="#dc2626"
              weight={2}
              fillOpacity={0.7}
            >
              <Popup>
                <div className="text-sm">
                  <p className="font-bold">{attack.country}</p>
                  <p>{attack.city}</p>
                  <p className="text-gray-600">IP: {attack.source_ip}</p>
                  <p className="text-gray-600">Action: {attack.action}</p>
                  <p className="text-xs text-gray-500">
                    {new Date(attack.timestamp).toLocaleString()}
                  </p>
                </div>
              </Popup>
            </CircleMarker>
          ))}
        </MapContainer>
      )}
      
      {attacks.length === 0 && !loading && (
        <div className="absolute inset-0 flex items-center justify-center">
          <p className="text-gray-400">No attacks to display</p>
        </div>
      )}
    </div>
  )
}