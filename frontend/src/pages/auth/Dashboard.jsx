import React from 'react'
import useLogout from '../../hooks/useLogout'
import Navbar from "../../components/Navbar"
import Footer from '../../components/Footer'

const Dashboard = () => {
  const logout = useLogout()

  return (
    <div style={{ minHeight: '100vh', background: '#F6F7FF', fontFamily: "'DM Sans', 'Segoe UI', sans-serif" }}>

      <Navbar/>
       <h1>HI THI S IS DAHBOARD</h1>
      <Footer/>
    </div>
  )
}

export default Dashboard