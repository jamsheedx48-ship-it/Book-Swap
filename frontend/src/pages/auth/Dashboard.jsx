import React, { useState, useEffect } from "react";
import { Link } from "react-router-dom";
import { 
  BookOpen, 
  RefreshCcw, 
  MessageCircle, 
  Shield, 
  Sparkles, 
  Zap, 
  MapPin, 
  ArrowRight 
} from "lucide-react";

import Navbar from "../../components/Navbar";
import Footer from "../../components/Footer";

export default function LandingPage() {
  return (
    <div className="min-h-screen bg-[#F8FAFF] font-sans selection:bg-[#5B4CF0] selection:text-white">
      <Navbar />

      {/* Hero Section: The AI Ecosystem Launchpad */}
      <section className="relative pt-32 pb-20 px-6 md:px-12 overflow-hidden">
        {/* Abstract background blobs for depth */}
        <div className="absolute top-0 right-0 -translate-y-1/2 translate-x-1/4 w-[600px] h-[600px] bg-[#5B4CF0]/5 rounded-full blur-3xl pointer-events-none" />
        <div className="absolute bottom-0 left-0 translate-y-1/2 -translate-x-1/4 w-[400px] h-[400px] bg-[#26187D]/5 rounded-full blur-3xl pointer-events-none" />

        <div className="max-w-[1600px] mx-auto grid lg:grid-cols-2 gap-16 items-center">
          <div className="space-y-8 relative z-10 text-center lg:text-left">
            <div className="inline-flex items-center gap-2 bg-white border border-indigo-50 px-4 py-2 rounded-full shadow-sm">
              <Sparkles className="text-[#5B4CF0]" size={16} />
              <span className="text-[10px] font-black uppercase tracking-widest text-[#26187D]">
                AI-Powered Knowledge Circulation [cite: 177]
              </span>
            </div>

            <h1 className="text-5xl md:text-7xl font-black leading-[1.1] tracking-tighter text-slate-900">
              Don't just buy. <br />
              <span className="text-transparent bg-clip-text bg-gradient-to-r from-[#26187D] to-[#5B4CF0]">
                Smart Swap.
              </span>
            </h1>

            <p className="text-gray-500 text-lg md:text-xl leading-relaxed max-w-xl mx-auto lg:mx-0 font-medium">
              Join the student ecosystem where AI understands your interests to suggest the perfect book exchange [cite: 297-298]. Save money and keep knowledge moving.
            </p>

            <div className="flex flex-col sm:flex-row gap-4 justify-center lg:justify-start">
              <Link
                to="/register"
                className="group bg-[#26187D] text-white px-8 py-4 rounded-2xl font-black text-sm flex items-center justify-center gap-3 shadow-2xl shadow-indigo-200 hover:bg-black transition-all"
              >
                Start Swapping <Zap size={18} className="group-hover:text-yellow-400 transition-colors" />
              </Link>
              <Link
                to="/browse-books"
                className="px-8 py-4 rounded-2xl font-black text-sm border-2 border-gray-100 hover:border-indigo-100 hover:bg-white transition-all text-center flex items-center justify-center gap-2"
              >
                Explore Library <ArrowRight size={18} />
              </Link>
            </div>

            <div className="flex items-center justify-center lg:justify-start gap-6 pt-4">
               <div className="flex -space-x-3">
                  {[1,2,3,4].map(i => (
                    <div key={i} className="w-10 h-10 rounded-full border-2 border-white bg-gray-200 overflow-hidden">
                       <img src={`https://i.pravatar.cc/100?img=${i+10}`} alt="User" />
                    </div>
                  ))}
               </div>
               <p className="text-xs font-bold text-gray-400 uppercase tracking-widest">
                  Trusted by students in Manjeri
               </p>
            </div>
          </div>

          <div className="relative group">
            <div className="absolute -inset-4 bg-gradient-to-tr from-indigo-500 to-purple-500 rounded-[3rem] blur-2xl opacity-10 group-hover:opacity-20 transition-opacity" />
            <div className="relative bg-white p-4 rounded-[3rem] shadow-2xl border border-white/50">
              <img
                src="https://images.unsplash.com/photo-1521587760476-6c12a4b040da"
                alt="Book Community"
                className="rounded-[2.5rem] w-full object-cover h-[500px] md:h-[600px]"
              />
              {/* Floating AI Notification Card */}
              <div className="absolute -bottom-6 -left-6 bg-white/90 backdrop-blur-md px-6 py-5 rounded-[2rem] shadow-xl border border-indigo-50 flex items-center gap-4 animate-bounce-slow">
                <div className="bg-indigo-50 p-3 rounded-2xl">
                  <RefreshCcw className="text-[#5B4CF0]" size={20} />
                </div>
                <div>
                  <p className="text-[10px] font-black text-gray-400 uppercase tracking-widest">Smart Match found [cite: 86-89]</p>
                  <p className="text-sm font-black text-gray-900">Exchange "Atomic Habits" nearby</p>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Core AI Features: Based on Documentation [cite: 60-90] */}
      <section className="py-24 bg-white border-y border-gray-100">
        <div className="max-w-[1600px] mx-auto px-6 md:px-12">
          <div className="text-center mb-16 space-y-4">
            <h2 className="text-4xl font-black text-slate-900">Engineered for Readers</h2>
            <p className="text-gray-500 font-medium max-w-2xl mx-auto uppercase text-[10px] tracking-[0.2em]">
              Beyond a platform—A circulation optimized system [cite: 298]
            </p>
          </div>

          <div className="grid md:grid-cols-3 gap-10">
            {[
              { 
                icon: <Zap className="text-amber-500" />, 
                title: "Chain Optimization", 
                desc: "Our AI finds multi-user swap chains (A→B→C) so everyone gets what they want ." 
              },
              { 
                icon: <MapPin className="text-rose-500" />, 
                title: "Hyper-Local Matching", 
                desc: "Identify swaps within your immediate area to eliminate logistics barriers [cite: 223-225]." 
              },
              { 
                icon: <Shield className="text-[#5B4CF0]" />, 
                title: "Verified Trust", 
                desc: "Trade with confidence using our reliability scoring and verified badges [cite: 226-230]." 
              }
            ].map((feature, i) => (
              <div key={i} className="p-10 rounded-[2.5rem] bg-[#F8FAFF] border border-transparent hover:border-indigo-100 hover:bg-white hover:shadow-2xl transition-all duration-500 group">
                <div className="bg-white w-14 h-14 rounded-2xl shadow-sm flex items-center justify-center mb-8 group-hover:scale-110 transition-transform">
                  {feature.icon}
                </div>
                <h3 className="text-xl font-black mb-4 text-gray-900">{feature.title}</h3>
                <p className="text-gray-500 leading-relaxed text-sm font-medium">{feature.desc}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Modern CTA: Gamification Focus  */}
      <section className="px-6 md:px-12 py-24">
        <div className="max-w-[1600px] mx-auto bg-[#26187D] rounded-[4rem] p-12 md:p-24 text-center relative overflow-hidden shadow-2xl shadow-indigo-200">
          <div className="absolute top-0 right-0 w-96 h-96 bg-white/5 rounded-full blur-3xl -mr-48 -mt-48" />
          <div className="absolute bottom-0 left-0 w-96 h-96 bg-[#5B4CF0]/20 rounded-full blur-3xl -ml-48 -mb-48" />
          
          <div className="relative z-10 max-w-3xl mx-auto space-y-10">
            <h2 className="text-4xl md:text-6xl font-black text-white leading-tight">
              Grow your library <br /> through the power of giving.
            </h2>
            <p className="text-indigo-100 text-lg md:text-xl font-medium max-w-xl mx-auto leading-relaxed">
              Earn credits for every book you give to the community and spend them to discover your next read [cite: 246-249].
            </p>
            <Link 
              to="/register" 
              className="inline-block bg-white text-[#26187D] px-12 py-5 rounded-2xl font-black text-lg hover:bg-indigo-50 transition-all shadow-xl active:scale-95"
            >
              Create Your AI Profile
            </Link>
          </div>
        </div>
      </section>

      <Footer />
    </div>
  );
}