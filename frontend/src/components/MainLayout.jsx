import React from "react";
import Navbar from "./Navbar";
import Footer from "./Footer";

/**
 * Reusable layout wrapper for all main pages
 * Use this for dashboard, browse books, add book, chat, profile etc.
 * Skip this layout for auth pages like login/register.
 */

export default function MainLayout({ children }) {
  return (
    <div className="min-h-screen flex flex-col bg-[#F6F7FF]">
      {/* Common Navbar */}
      <Navbar />

      {/* Dynamic Page Content */}
      <main className="flex-grow w-full">
        <div className="max-w-7xl mx-auto px-6 md:px-12 py-8">
          {children}
        </div>
      </main>

      {/* Common Footer */}
      <Footer />
    </div>
  );
}
