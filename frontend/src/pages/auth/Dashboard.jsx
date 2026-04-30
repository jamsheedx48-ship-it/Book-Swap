import React from 'react'
import useLogout from '../../hooks/useLogout'

const Dashboard = () => {
  const logout = useLogout()

  return (
    <div style={{ minHeight: '100vh', background: '#F6F7FF', fontFamily: "'DM Sans', 'Segoe UI', sans-serif" }}>

      {/* Navbar */}
      <nav style={{
        background: '#fff',
        borderBottom: '1px solid #e8e8f4',
        padding: '0 40px',
        height: 60,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
      }}>
        <span style={{ fontWeight: 800, fontSize: 18, color: '#26187D', letterSpacing: '-0.5px' }}>
          BookSwap
        </span>

        <div>
          <button
            onClick={logout}
            style={{
              background: '#26187D',
              color: '#fff',
              border: 'none',
              borderRadius: 8,
              padding: '8px 20px',
              fontSize: 13,
              fontWeight: 600,
              cursor: 'pointer',
            }}
          >
            Logout
          </button>
        </div>
      </nav>

      {/* Body */}
      <div style={{
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        height: 'calc(100vh - 60px)',
        gap: 12,
      }}>
        <h1 style={{ fontSize: 32, fontWeight: 800, color: '#26187D', margin: 0, letterSpacing: '-1px' }}>
          Welcome back 👋
        </h1>
        <p style={{ fontSize: 15, color: '#888', margin: 0 }}>
          You're logged in. Use the navbar to get started.
        </p>
      </div>

    </div>
  )
}

export default Dashboard