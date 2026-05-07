import React, { useState, useEffect } from "react";
import { User, LogOut } from "lucide-react";
import { Link } from "react-router-dom";
import { getMe } from "../api/auth";
import useLogout from "../hooks/useLogout";
export default function Navbar() {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  const logout = useLogout(); // use hook

  useEffect(() => {
    const fetchUser = async () => {
      try {
        const res = await getMe();
        setUser(res.data);
      } catch (error) {
        console.log("User not logged in");
        setUser(null);
      } finally {
        setLoading(false);
      }
    };

    fetchUser();
  }, []);

  return (
    <nav className="w-full bg-white border-b border-gray-200 px-6 md:px-12 py-4 flex items-center justify-between sticky top-0 z-50">
      
      {/* Logo */}
      <div className="flex items-center gap-2">
        <div className="w-10 h-10 bg-[#5B4CF0] rounded-xl flex items-center justify-center text-white font-bold text-lg">
          B
        </div>
        <h1 className="text-xl font-bold text-black">BookSwap</h1>
      </div>

      {/* Nav Links */}
      <div className="hidden md:flex items-center gap-8 text-black font-medium">
        <Link
          to="/browse-books"
          className="hover:text-[#26187D] transition"
        >
          Browse Books
        </Link>

        <Link
          to="/my-listings"
          className="hover:text-[#26187D] transition"
        >
          My Listings
        </Link>

        <Link to="/chat" className="hover:text-[#26187D] transition">
          Messages
        </Link>
        <Link to="/exchanges" className="hover:text-[#26187D] transition">
          Exchanges
        </Link>
      </div>

      {/* Actions */}
      <div className="flex items-center gap-4">
        <Link to="/list-book">
          <button className="hidden md:flex bg-[#26187D] text-white px-5 py-2 rounded-xl hover:opacity-90 transition">
            List a Book
          </button>
        </Link>

        {/* User Section */}
        {!loading && user ? (
          <div className="flex items-center gap-3">
            
            {/* User info */}
            <div className="flex items-center gap-2 bg-[#F6F7FF] px-3 py-2 rounded-full">
              <User size={20} className="text-black" />
              <span className="text-sm font-medium text-black">
                {user.name}
              </span>
            </div>

            {/* Logout button */}
            <button
              onClick={logout}
              className="flex items-center gap-2 text-red-500 hover:text-red-600 text-sm font-medium"
            >
              <LogOut size={18} />
              Logout
            </button>
          </div>
        ) : !loading ? (
          <Link to="/login">
            <button className="text-sm font-medium text-[#26187D]">
              Login
            </button>
          </Link>
        ) : null}
      </div>
    </nav>
  );
}