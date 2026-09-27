import { NavLink, Navigate, Route, Routes } from 'react-router-dom'
import { useEffect, useState } from 'react'
import { api } from './api'
import type { HealthResponse } from './types'
import HomePage from './pages/HomePage'
import VerifyPage from './pages/VerifyPage'
import HistoryPage from './pages/HistoryPage'
import DetailPage from './pages/DetailPage'
import PolicyPage from './pages/PolicyPage'

export default function App() {
  const [health, setHealth] = useState<HealthResponse | null>(null)

  useEffect(() => {
    api.health().then(setHealth).catch(() => setHealth(null))
  }, [])

  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">
          软件供应链核验工作台
          <small>DSSE · in-toto · OPA · PostgreSQL</small>
        </div>
        <nav className="nav">
          <NavLink to="/" end>首页 / 演示</NavLink>
          <NavLink to="/verify">上传核验</NavLink>
          <NavLink to="/history">历史记录</NavLink>
          <NavLink to="/policy">信任策略</NavLink>
        </nav>
        <div className="spacer" />
        {health && <span className="store-pill">存储：{health.store === 'postgres' ? 'PostgreSQL' : '内存'}</span>}
      </header>

      <main className="container">
        <Routes>
          <Route path="/" element={<HomePage />} />
          <Route path="/verify" element={<VerifyPage />} />
          <Route path="/history" element={<HistoryPage />} />
          <Route path="/verifications/:id" element={<DetailPage />} />
          <Route path="/policy" element={<PolicyPage />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </main>
    </div>
  )
}
