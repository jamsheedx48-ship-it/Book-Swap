import React from 'react'
import useLogout from '../../hooks/useLogout'
const Dashboard = () => {
    const logout=useLogout()
  return (
    <div className="p-8">
            <h1 className="text-2xl font-bold text-persian mb-4">Dashboard</h1>
            <button
                onClick={logout}
                className="bg-persian text-white px-6 py-2 rounded-lg hover:opacity-90"
            >
                Logout
            </button>
    </div>
  )
}

export default Dashboard