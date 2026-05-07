import React, { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import Navbar from "../../components/Navbar";
import Footer from "../../components/Footer";
import { getBookDetail } from "../../api/books";
import { toast } from "react-toastify";
import { Heart, Repeat } from "lucide-react";
import BookChat from "../../components/BookChat";
import ExchangeModal from "../../components/ExchangeModal";
import { checkPendingExchange } from "../../api/exchange";
import { getMe } from "../../api/auth";

const BookDetail = () => {
  const { id } = useParams();

  const [book, setBook] = useState(null);
  const [loading, setLoading] = useState(true);
  const [showExchangeModal, setShowExchangeModal] = useState(false);
  const [hasPendingExchange, setHasPendingExchange] = useState(false);
  const [me, setMe] = useState(null);

  useEffect(() => {
    if (id) {
      fetchBookDetail();
      fetchPendingStatus();
      getMe().then((res) => setMe(res.data));
    }
  }, [id]);

  //for hiding swap btn for my books
  const isMyBook = me?.id === book?.user_id;

  const fetchBookDetail = async () => {
    try {
      setLoading(true);
      const res = await getBookDetail(id);
      setBook(res.data);
    } catch (error) {
      const status = error.response?.status;

      if (status === 429) {
        toast.error("Too many requests. Please wait a moment.");
      } else {
        toast.error(
          error.response?.data?.detail || "Failed to load book details",
        );
      }
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

  if (loading) {
    return (
      <div className="min-h-screen flex justify-center items-center">
        Loading...
      </div>
    );
  }

  if (!book) {
    return (
      <div className="min-h-screen flex justify-center items-center">
        Book not found
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-[#F6F7FF]">
      <Navbar />

      <div className="max-w-6xl mx-auto px-6 py-12">
        <div className="grid md:grid-cols-2 gap-10">
          {/* Left Image */}
          <div>
            <img
              src={
                book.image_detail
                  ? book.image_detail
                  : book.image
                    ? book.image
                    : "https://via.placeholder.com/400x500?text=No+Image"
              }
              alt={book.title}
              className="w-full h-[500px] object-cover rounded-2xl shadow-md"
            />
          </div>

          {/* Right Content */}
          <div>
            {/* Title */}
            <h1 className="text-5xl font-bold text-black mb-3">{book.title}</h1>

            {/* Author */}
            <p className="text-xl text-gray-600 mb-4">{book.author}</p>

            {/* Categories */}
            <div className="flex flex-wrap gap-2 mb-6">
              {book.category_detail?.name && (
                <span className="px-3 py-1 bg-gray-200 rounded-full text-sm">
                  {book.category_detail.name}
                </span>
              )}
            </div>

            {/* Synopsis */}
            <h2 className="text-2xl font-semibold mb-3">Synopsis</h2>

            <p className="text-gray-600 leading-relaxed mb-8">
              {book.description || "No description available"}
            </p>

            {/* Info Box */}
            <div className="grid grid-cols-3 gap-4 bg-white rounded-2xl p-6 shadow-sm border border-gray-100 mb-8">
              <div>
                <p className="text-xs text-gray-400 uppercase">Condition</p>
                <p className="font-semibold text-green-600">{book.condition}</p>
              </div>

              <div>
                <p className="text-xs text-gray-400 uppercase">
                  Owner Location
                </p>
                <p className="font-semibold">
                  {book.owner_location || "Not available"}
                </p>
              </div>

              <div>
                <p className="text-xs text-gray-400 uppercase">Listed On</p>
                <p className="font-semibold">
                  {new Date(book.created_at).toLocaleDateString()}
                </p>
              </div>
            </div>

            {/* Action Buttons */}
            <div className="flex gap-4">
              {isMyBook ? (
                <button
                  disabled
                  className="flex-1 bg-[#F6F7FF] text-[#26187D] border border-[#26187D] py-4 rounded-2xl font-semibold"
                >
                  Your Listing
                </button>
              ) : hasPendingExchange ? (
                <button
                  disabled
                  className="flex-1 bg-yellow-500 text-white py-4 rounded-2xl font-semibold"
                >
                  Pending Request
                </button>
              ) : (
                <button
                  onClick={() => setShowExchangeModal(true)}
                  className="flex-1 bg-[#26187D] text-white py-4 rounded-2xl font-semibold"
                >
                  Request Swap
                </button>
              )}

              <button className="flex-1 bg-white border border-gray-200 py-4 rounded-2xl font-semibold flex items-center justify-center gap-2 hover:bg-gray-50 transition">
                <Heart size={18} />
                Wishlist
              </button>
            </div>
          </div>
        </div>
      </div>
      <Footer />

      <ExchangeModal
        book={book}
        isOpen={showExchangeModal}
        onClose={() => {
          setShowExchangeModal(false);
          fetchPendingStatus();
        }}
      />
      <BookChat bookId={book.id} bookTitle={book.title} />
    </div>
  );
};

export default BookDetail;
