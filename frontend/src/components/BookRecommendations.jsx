import { useState, useEffect } from "react";
import { getRecommendations } from "../api/books";
import { Link } from "react-router-dom";

export default function BookRecommendations() {
  const [platformBooks, setPlatformBooks] = useState([]);
  const [globalBooks, setGlobalBooks] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const fetchRecommendations = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await getRecommendations();
      setPlatformBooks(res.data.platform_books || []);
      setGlobalBooks(res.data.global_books || []);
    } catch {
      setError("Couldn't load recommendations.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchRecommendations();
  }, []);

  return (
    <div className="bg-white rounded-[2rem] border border-gray-100 p-6 shadow-sm">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <div
            className="w-9 h-9 rounded-xl flex items-center justify-center text-white text-base"
            style={{ background: "#26187D" }}
          >
            ✦
          </div>
          <div>
            <p className="text-sm font-black text-gray-900">For You</p>
            <p className="text-[10px] text-gray-400 uppercase tracking-widest font-bold">
              AI Picks
            </p>
          </div>
        </div>
        <button
          onClick={fetchRecommendations}
          disabled={loading}
          className="text-[10px] uppercase tracking-widest font-black text-[#26187D] hover:opacity-60 transition-opacity disabled:opacity-30"
        >
          Refresh
        </button>
      </div>

      {loading ? (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          {[...Array(4)].map((_, i) => (
            <div key={i} className="h-40 rounded-2xl bg-gray-50 animate-pulse" />
          ))}
        </div>
      ) : error ? (
        <p className="text-xs text-red-400 font-bold text-center py-6">{error}</p>
      ) : (
        <div className="space-y-6">

          {/* Platform books — real listings */}
          {platformBooks.length > 0 && (
            <div>
              <p className="text-[10px] uppercase tracking-widest font-black text-[#26187D] mb-3">
                Available on BookSwap
              </p>
              <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
                {platformBooks.map((book) => (
                  <Link
                    to={`/books/${book.id}`}
                    key={book.id}
                    className="flex flex-col p-3 rounded-2xl border border-gray-100 hover:border-[#26187D]/30 hover:shadow-md transition-all group"
                    style={{ borderTop: "3px solid #26187D" }}
                  >
                    {book.cover ? (
                      <img
                        src={book.cover}
                        alt={book.title}
                        className="w-full h-28 object-cover rounded-xl mb-2"
                      />
                    ) : (
                      <div
                        className="w-full h-28 rounded-xl mb-2 flex items-center justify-center text-3xl"
                        style={{ background: "#EAE8F8" }}
                      >
                        📚
                      </div>
                    )}
                    <p className="text-xs font-black text-gray-900 line-clamp-2 group-hover:text-[#26187D] transition-colors">
                      {book.title}
                    </p>
                    <p className="text-[11px] text-gray-400 font-bold uppercase mt-0.5 line-clamp-1">
                      {book.author}
                    </p>
                    <span
                      className="inline-block mt-1.5 text-[10px] font-black px-2 py-0.5 rounded-full uppercase w-fit"
                      style={{ background: "#EAE8F8", color: "#26187D" }}
                    >
                      {book.genre}
                    </span>
                  </Link>
                ))}
              </div>
            </div>
          )}

          {/* Global AI suggestions */}
          {globalBooks.length > 0 && (
            <div>
              <p className="text-[10px] uppercase tracking-widest font-black text-gray-400 mb-3">
                AI Suggestions
              </p>
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                {globalBooks.map((book, i) => (
                  <div
                    key={i}
                    className="flex flex-col p-3 rounded-2xl border border-gray-100 hover:border-gray-200 transition-all"
                  >
                    <span className="text-2xl mb-2">{book.cover_emoji}</span>
                    <p className="text-xs font-black text-gray-900 line-clamp-2">
                      {book.title}
                    </p>
                    <p className="text-[11px] text-gray-400 font-bold uppercase mt-0.5 line-clamp-1">
                      {book.author}
                    </p>
                    <span
                      className="inline-block mt-1.5 text-[10px] font-black px-2 py-0.5 rounded-full uppercase w-fit"
                      style={{ background: "#F1F4F9", color: "#888" }}
                    >
                      {book.genre}
                    </span>
                    <p className="text-[11px] text-gray-400 mt-1.5 leading-relaxed line-clamp-2">
                      {book.reason}
                    </p>
                  </div>
                ))}
              </div>
            </div>
          )}

        </div>
      )}
    </div>
  );
}