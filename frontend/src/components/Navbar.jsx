import React, { useState, useEffect } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import {
  LogOut,
  PlusCircle,
  MessageSquare,
  Repeat,
  LayoutGrid,
  Sparkles
} from "lucide-react";
import { getMe } from "../api/auth";
import { getMyProfile } from "../api/profile";
import useLogout from "../hooks/useLogout";

export default function Navbar() {
  const [user, setUser] = useState(null);
  const [avatarDisplay, setAvatarDisplay] = useState(null);
  const [loading, setLoading] = useState(true);
  const [isScrolled, setIsScrolled] = useState(false);

  const location = useLocation();
  const logout = useLogout();
  const navigate = useNavigate();

  useEffect(() => {
    const handleScroll = () => setIsScrolled(window.scrollY > 10);
    window.addEventListener("scroll", handleScroll);

    const fetchUser = async () => {
      try {
        const [userRes, profileRes] = await Promise.all([
          getMe(),
          getMyProfile(),
        ]);
        setUser(userRes.data);
        setAvatarDisplay(profileRes.data.avatar_display);
      } catch (error) {
        setUser(null);
        setAvatarDisplay(null);
      } finally {
        setLoading(false);
      }
    };

    fetchUser();
    return () => window.removeEventListener("scroll", handleScroll);
  }, []);

  const isActive = (path) => location.pathname === path;

  return (
    <nav
      className={`fixed top-0 w-full z-[100] transition-all duration-300 px-6 md:px-12 font-sans ${
        isScrolled
          ? "bg-white/90 backdrop-blur-md py-3 shadow-sm border-b border-gray-100"
          : "bg-white py-5 border-b border-transparent"
      }`}
    >
      <div className="w-full max-w-[1600px] mx-auto flex items-center justify-between">

        {/* Brand */}
        <div className="flex-shrink-0">
          <Link to="/" className="flex items-center gap-2 group">
            <div className="w-10 h-10 bg-[#26187D] rounded-2xl flex items-center justify-center text-white shadow-lg shadow-indigo-100 group-hover:rotate-12 transition-transform duration-300">
              <Sparkles size={20} />
            </div>
            <h1 className="text-xl font-extrabold tracking-tight text-[#26187D]">
              BookSwap<span className="text-[#5B4CF0]">.AI</span>
            </h1>
          </Link>
        </div>

        {/* Center Navigation */}
        <div className="hidden lg:flex items-center gap-1 bg-gray-50 p-1 rounded-2xl border border-gray-100">
          <Link
            to="/browse-books"
            className={`flex items-center gap-2 px-6 py-2.5 rounded-xl text-sm font-semibold transition-all ${
              isActive("/browse-books")
                ? "bg-white text-[#26187D] shadow-sm"
                : "text-gray-400 hover:text-[#26187D]"
            }`}
          >
            <LayoutGrid size={18} />
            <span>Browse</span>
          </Link>
          <Link
            to="/chat"
            className={`flex items-center gap-2 px-6 py-2.5 rounded-xl text-sm font-semibold transition-all ${
              isActive("/chat")
                ? "bg-white text-[#26187D] shadow-sm"
                : "text-gray-400 hover:text-[#26187D]"
            }`}
          >
            <MessageSquare size={18} />
            <span>Messages</span>
          </Link>
          <Link
            to="/exchanges"
            className={`flex items-center gap-2 px-6 py-2.5 rounded-xl text-sm font-semibold transition-all ${
              isActive("/exchanges")
                ? "bg-white text-[#26187D] shadow-sm"
                : "text-gray-400 hover:text-[#26187D]"
            }`}
          >
            <Repeat size={18} />
            <span>Exchanges</span>
          </Link>
        </div>

        {/* Actions & Profile */}
        <div className="flex items-center gap-4 flex-shrink-0">
          {!loading && user ? (
            <div className="flex items-center gap-4">
              <Link
                to="/list-book"
                className="hidden sm:flex items-center gap-2 bg-[#26187D] text-white px-6 py-2.5 rounded-xl font-bold text-sm hover:opacity-90 transition-all shadow-md shadow-indigo-100"
              >
                <PlusCircle size={18} />
                <span>List a Book</span>
              </Link>

              <div className="h-6 w-px bg-gray-200 mx-2 hidden md:block" />

              <div className="flex items-center gap-3">
                <div className="flex items-center gap-3 pl-2 py-2">
                  <div className="text-right hidden md:block leading-none cursor-default">
                    <p className="text-sm font-bold text-gray-900">
                      {user.name}
                    </p>
                  </div>

                  <Link
                    to="/profile"
                    className="w-10 h-10 rounded-xl overflow-hidden border border-gray-100 hover:border-[#26187D] transition-all"
                  >
                    {avatarDisplay ? (
                      <img
                        src={avatarDisplay}
                        alt="Profile"
                        className="w-full h-full object-cover"
                      />
                    ) : (
                      <div className="w-full h-full bg-indigo-50 flex items-center justify-center text-[#26187D] font-bold text-xs">
                        {user.name?.substring(0, 2).toUpperCase()}
                      </div>
                    )}
                  </Link>
                </div>

                <button
                  onClick={logout}
                  className="p-2 text-gray-400 hover:text-red-500 transition-colors"
                  title="Logout"
                >
                  <LogOut size={20} />
                </button>
              </div>
            </div>
          ) : !loading ? (
            <div className="flex items-center gap-3">
              <Link
                to="/login"
                className="px-5 py-2 font-bold text-sm text-gray-500 hover:text-[#26187D]"
              >
                Login
              </Link>
              <Link
                to="/register"
                className="bg-[#26187D] text-white px-6 py-2.5 rounded-xl font-bold text-sm shadow-lg shadow-indigo-100 hover:bg-black transition-all"
              >
                Join Ecosystem
              </Link>
            </div>
          ) : null}
        </div>
      </div>
    </nav>
  );
}