import React from "react";
import { BookOpen, MessageCircle } from "lucide-react";

export default function Footer() {
  return (
    <footer className="bg-white border-t border-gray-200">
      <div className="max-w-7xl mx-auto px-6 md:px-12 py-12 grid grid-cols-1 md:grid-cols-4 gap-8">
        
        {/* Brand */}
        <div>
          <div className="flex items-center gap-2 mb-4">
            <div className="w-10 h-10 bg-[#26187D] rounded-xl flex items-center justify-center text-white font-bold">
              B
            </div>
            <h2 className="text-lg font-bold text-black">BookSwap</h2>
          </div>

          <p className="text-gray-600 text-sm leading-relaxed">
            Exchange books with readers around you and discover your next
            favorite read.
          </p>
        </div>

        {/* Quick Links */}
        <div>
          <h3 className="font-semibold text-black mb-3">Quick Links</h3>
          <ul className="space-y-2 text-gray-600 text-sm">
            <li>
              <a href="#" className="hover:text-[#26187D]">
                Browse Books
              </a>
            </li>
            <li>
              <a href="#" className="hover:text-[#26187D]">
                How It Works
              </a>
            </li>
            <li>
              <a href="#" className="hover:text-[#26187D]">
                List a Book
              </a>
            </li>
          </ul>
        </div>

        {/* Community */}
        <div>
          <h3 className="font-semibold text-black mb-3">Community</h3>
          <ul className="space-y-2 text-gray-600 text-sm">
            <li>
              <a href="#" className="hover:text-[#26187D]">
                Messages
              </a>
            </li>
            <li>
              <a href="#" className="hover:text-[#26187D]">
                Wishlist
              </a>
            </li>
            <li>
              <a href="#" className="hover:text-[#26187D]">
                Support
              </a>
            </li>
          </ul>
        </div>

        {/* Social */}
        <div>
          <h3 className="font-semibold text-black mb-3">Stay Connected</h3>
          <div className="flex gap-4 text-[#26187D]">
            <BookOpen className="cursor-pointer hover:opacity-80" />
            <MessageCircle className="cursor-pointer hover:opacity-80" />
          </div>
        </div>
      </div>

      {/* Bottom copyright */}
      <div className="border-t border-gray-200 py-4 text-center text-sm text-gray-500">
        © 2026 BookSwap. All rights reserved.
      </div>
    </footer>
  );
}