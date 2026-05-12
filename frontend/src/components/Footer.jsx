import React from "react";
import { Link } from "react-router-dom";
import { Sparkles, MessageSquare, LayoutGrid, Repeat, Heart, Info, Mail, Globe } from "lucide-react";

export default function Footer() {
  return (
    <footer className="bg-white border-t border-gray-100 font-sans">
      <div className="w-full max-w-[1600px] mx-auto px-6 md:px-12 py-16 grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-12">
        
        {/* Brand & Ecosystem Pitch */}
        <div className="lg:col-span-2 space-y-6">
          <Link to="/" className="flex items-center gap-2 group">
            <div className="w-10 h-10 bg-[#26187D] rounded-2xl flex items-center justify-center text-white shadow-lg shadow-indigo-100 group-hover:rotate-12 transition-transform duration-300">
              <Sparkles size={20} />
            </div>
            <h1 className="text-xl font-extrabold tracking-tight text-[#26187D]">
              BookSwap<span className="text-[#5B4CF0]">.AI</span>
            </h1>
          </Link>

          <p className="text-gray-500 text-sm font-normal leading-relaxed max-w-xs tracking-tight">
            An AI-powered knowledge ecosystem designed for smart student book circulation and optimized exchange[cite: 177, 298].
          </p>
          
          <div className="flex items-center gap-4 pt-2">
            {/* <a href="#" className="w-10 h-10 bg-gray-50 rounded-xl flex items-center justify-center text-gray-400 hover:text-[#26187D] transition-colors">
              <Instagram size={18} />
            </a> */}
            <a href="#" className="w-10 h-10 bg-gray-50 rounded-xl flex items-center justify-center text-gray-400 hover:text-[#26187D] transition-colors">
              <Globe size={18} />
            </a>
            <a href="#" className="w-10 h-10 bg-gray-50 rounded-xl flex items-center justify-center text-gray-400 hover:text-[#26187D] transition-colors">
              <Mail size={18} />
            </a>
          </div>
        </div>

        {/* Discovery Links */}
        <div className="space-y-6">
          <h3 className="text-[10px] font-black text-gray-300 uppercase tracking-[0.2em]">Discovery</h3>
          <ul className="space-y-4">
            <li>
              <Link to="/browse-books" className="flex items-center gap-2 text-sm font-normal text-gray-500 hover:text-[#26187D] transition-colors">
                <LayoutGrid size={16} /> Browse Library
              </Link>
            </li>
            <li>
              <Link to="/how-it-works" className="flex items-center gap-2 text-sm font-normal text-gray-500 hover:text-[#26187D] transition-colors">
                <Info size={16} /> Smart Matching
              </Link>
            </li>
            <li>
              <Link to="/list-book" className="flex items-center gap-2 text-sm font-normal text-gray-500 hover:text-[#26187D] transition-colors">
                <Sparkles size={16} /> AI Summary
              </Link>
            </li>
          </ul>
        </div>

        {/* Community Links */}
        <div className="space-y-6">
          <h3 className="text-[10px] font-black text-gray-300 uppercase tracking-[0.2em]">Community</h3>
          <ul className="space-y-4">
            <li>
              <Link to="/chat" className="flex items-center gap-2 text-sm font-normal text-gray-500 hover:text-[#26187D] transition-colors">
                <MessageSquare size={16} /> Messaging
              </Link>
            </li>
            <li>
              <Link to="/exchanges" className="flex items-center gap-2 text-sm font-normal text-gray-500 hover:text-[#26187D] transition-colors">
                <Repeat size={16} /> Swap Chains
              </Link>
            </li>
            <li>
              <Link to="/wishlist" className="flex items-center gap-2 text-sm font-normal text-gray-500 hover:text-[#26187D] transition-colors">
                <Heart size={16} /> Wishlist
              </Link>
            </li>
          </ul>
        </div>

        {/* Status Hub */}
        <div className="space-y-6">
          <h3 className="text-[10px] font-black text-gray-300 uppercase tracking-[0.2em]">Ecosystem</h3>
          <div className="bg-gray-50 p-6 rounded-[2rem] border border-gray-100">
             <p className="text-[10px] font-black text-gray-400 uppercase tracking-widest mb-1">Status</p>
             <p className="text-sm font-extrabold text-[#26187D]">Beta v1.0.4</p>
             <div className="mt-4 flex items-center gap-2">
                <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse" />
                <span className="text-[10px] font-black text-gray-500 uppercase tracking-tighter">AI Node Active [cite: 102]</span>
             </div>
          </div>
        </div>
      </div>

      {/* Bottom Legal & Location */}
      <div className="border-t border-gray-50 py-8">
        <div className="w-full max-w-[1600px] mx-auto px-6 md:px-12 flex flex-col md:flex-row justify-between items-center gap-4 text-[10px] font-black text-gray-400 uppercase tracking-[0.2em]">
          <p>© 2026 BOOKSWAP AI — ALL RIGHTS RESERVED [cite: 171]</p>
          <div className="flex gap-8">
            <p className="hover:text-gray-900 cursor-pointer transition-colors">Privacy Protocol</p>
            <p className="hover:text-gray-900 cursor-pointer transition-colors">Trust Guidelines [cite: 226]</p>
          </div>
          <p className="text-[#26187D]">Manjeri, Kerala, India</p>
        </div>
      </div>
    </footer>
  );
}