import React from 'react'
import Navbar from '../../components/Navbar'
import Footer from '../../components/Footer'
import BookGrid from '../../components/BookGrid'
import { Link } from "react-router-dom";
const BrowseBooks = () => {

  return (
    <div style={{ minHeight: '100vh', background: '#F6F7FF', fontFamily: "'DM Sans', 'Segoe UI', sans-serif" }}>

      <Navbar/>
       <BookGrid/>
      <Footer/>
    </div>
  )
}

export default BrowseBooks;