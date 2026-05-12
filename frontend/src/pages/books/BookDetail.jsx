import React, { useEffect, useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import Navbar from "../../components/Navbar";
import Footer from "../../components/Footer";
import { getBookDetail } from "../../api/books";
import { toast } from "react-toastify";
import { Heart, Sparkles, Calendar, BookOpen } from "lucide-react";
import BookChat from "../../components/BookChat";
import ExchangeModal from "../../components/ExchangeModal";
import { checkPendingExchange } from "../../api/exchange";
import { getMe } from "../../api/auth";
import { startConversation } from "../../api/chat";

const BookDetail = () => {
  const { id } = useParams();
  const navigate = useNavigate();

  const [book, setBook] = useState(null);
  const [loading, setLoading] = useState(true);
  const [showExchangeModal, setShowExchangeModal] = useState(false);
  const [hasPendingExchange, setHasPendingExchange] = useState(false);
  const [me, setMe] = useState(null);

  useEffect(() => {
    if (id) {
      fetchBookDetail();
      fetchPendingStatus();
      // Fetch user identity
      getMe().then((res) => setMe(res.data)).catch(() => setMe(null));
    }
  }, [id]);

  const isMyBook = me?.id === book?.user_id;

  const fetchBookDetail = async () => {
    try {
      setLoading(true);
      const res = await getBookDetail(id);
      setBook(res.data);
    } catch (error) {
      toast.error(error.response?.data?.detail || "Failed to load book details");
    } finally {
      setLoading(false);
    }
  };

  const fetchPendingStatus = async () => {
    try {
      const res = await checkPendingExchange(id);
      setHasPendingExchange(res.data.has_pending);
    } catch (error) {
      console.log(error);
    }
  };

  const handleMessage = async () => {
    try {
      const res = await startConversation(book.user_id);
      navigate(`/chat/${res.data.conversation_id}`);
    } catch (err) {
      toast.error("Could not start conversation.");
    }
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-[#F8FAFF] flex flex-col items-center justify-center font-sans">
        <div className="w-10 h-10 border-4 border-[#26187D] border-t-transparent rounded-full animate-spin mb-4"></div>
        <p className="text-[10px] font-bold text-gray-400 uppercase tracking-widest">Opening Library...</p>
      </div>
    );
  }

  if (!book) {
    return (
      <div className="min-h-screen bg-[#F8FAFF] flex items-center justify-center font-sans">
        <p className="text-gray-500 font-bold">Book not found</p>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-[#F8FAFF] font-sans">
      <Navbar />

      <main className="max-w-[1200px] mx-auto px-6 pt-32 pb-20">
        <div className="grid md:grid-cols-2 gap-12 items-start">

          {/* Left: Image */}
          <div className="bg-white p-3 rounded-[2.5rem] shadow-[0_10px_40px_rgba(0,0,0,0.03)] border border-white">
            <img
              src={book.image_detail || book.image || "https://via.placeholder.com/400x500?text=No+Image"}
              alt={book.title}
              className="w-full h-[550px] object-cover rounded-[2rem]"
            />
          </div>

          {/* Right: Content */}
          <div className="py-4">
            <div className="flex items-center gap-2 mb-4">
              <Sparkles className="text-[#5B4CF0]" size={16} />
              <span className="text-[10px] font-bold uppercase tracking-[0.2em] text-[#26187D]">
                Knowledge Exchange
              </span>
            </div>

            <h1 className="text-5xl font-bold text-slate-900 tracking-tight leading-tight mb-2">
              {book.title}
            </h1>
            <p className="text-xl font-medium text-gray-400 mb-8 uppercase tracking-tight">
              by {book.author}
            </p>

            <div className="flex flex-wrap gap-2 mb-10">
              {book.category_detail?.name && (
                <span className="px-5 py-2 bg-white border border-gray-100 rounded-xl text-xs font-bold text-[#26187D] shadow-sm">
                  {book.category_detail.name}
                </span>
              )}
            </div>

            <div className="space-y-4 mb-10">
              <h2 className="text-lg font-bold text-slate-900 flex items-center gap-2">
                <BookOpen size={18} className="text-gray-300" /> Synopsis
              </h2>
              <p className="text-gray-500 leading-relaxed font-medium">
                {book.description || "No description available"}
              </p>
            </div>

            <div className="grid grid-cols-2 gap-4 mb-10">
              <div className="bg-white rounded-2xl p-5 border border-gray-100 shadow-sm">
                <p className="text-[10px] font-bold text-gray-300 uppercase tracking-widest mb-1">Condition</p>
                <p className="font-bold text-green-600 capitalize">{book.condition}</p>
              </div>
              <div className="bg-white rounded-2xl p-5 border border-gray-100 shadow-sm">
                <p className="text-[10px] font-bold text-gray-300 uppercase tracking-widest mb-1 flex items-center gap-1.5">
                  <Calendar size={10} /> Listed On
                </p>
                <p className="font-bold text-slate-700">
                  {new Date(book.created_at).toLocaleDateString()}
                </p>
              </div>
            </div>

            <div className="flex gap-4">
              {isMyBook ? (
                <button disabled className="flex-1 bg-gray-50 text-gray-400 border border-gray-100 py-4 rounded-2xl font-bold text-sm cursor-not-allowed">
                  Your Listing
                </button>
              ) : hasPendingExchange ? (
                <>
                  <button disabled className="flex-1 bg-amber-50 text-amber-600 border border-amber-100 py-4 rounded-2xl font-bold text-sm cursor-not-allowed">
                    Pending Request
                  </button>
                  <button onClick={handleMessage} className="px-8 bg-[#26187D] text-white py-4 rounded-2xl font-bold text-sm hover:bg-black transition active:scale-95">
                    Message
                  </button>
                </>
              ) : (
                <>
                  <button onClick={() => setShowExchangeModal(true)} className="flex-1 bg-[#26187D] text-white py-4 rounded-2xl font-bold text-sm shadow-xl shadow-indigo-100 hover:bg-black transition-all active:scale-95">
                    Request Swap
                  </button>
                  <button onClick={handleMessage} className="px-8 bg-white border border-gray-100 py-4 rounded-2xl font-bold text-sm text-[#26187D] hover:bg-gray-50 transition shadow-sm active:scale-95">
                    Message
                  </button>
                </>
              )}
              <button className="px-8 bg-white border border-gray-100 py-4 rounded-2xl font-bold text-sm text-gray-500 flex items-center justify-center gap-2 hover:bg-gray-50 transition shadow-sm active:scale-95">
                <Heart size={18} />
              </button>
            </div>
          </div>
        </div>
      </main>

      <Footer />

      <ExchangeModal
        book={book}
        isOpen={showExchangeModal}
        onClose={() => {
          setShowExchangeModal(false);
          fetchPendingStatus();
        }}
      />

      {/* --- CRITICAL FIX START --- */}
      {/* We only render the chat if the user (me) and book are both loaded */}
      {book && me?.id && (
        <BookChat 
          bookId={Number(book.id)} 
          bookTitle={book.title} 
          userId={String(me.id)} 
        />
      )}
      {/* --- CRITICAL FIX END --- */}
    </div>
  );
};

export default BookDetail;