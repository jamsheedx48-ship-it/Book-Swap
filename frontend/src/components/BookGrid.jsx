import React, { useEffect, useState } from "react";
import { useSearchParams, Link } from "react-router-dom";
import { getBooks, getCategories } from "../api/books";
import { toast } from "react-toastify";
import BookRecommendations from "./BookRecommendations";

export default function BookGrid() {
  const [books, setBooks] = useState([]);
  const [categories, setCategories] = useState([]);
  const [loading, setLoading] = useState(true);
  const [nextPage, setNextPage] = useState(null);
  const [prevPage, setPrevPage] = useState(null);
  const [searchParams, setSearchParams] = useSearchParams();

  const currentPage = Math.max(1, Number(searchParams.get("page")) || 1);
  const [search, setSearch] = useState(searchParams.get("search") || "");
  const [category, setCategory] = useState(searchParams.get("category") || "");
  const [condition, setCondition] = useState(
    searchParams.get("condition") || "",
  );

  useEffect(() => {
    fetchBooks();
  }, [currentPage, searchParams]);
  useEffect(() => {
    fetchCategories();
  }, []);
  useEffect(() => {
    // If the search input is cleared, update the URL params automatically
    if (search === "" && searchParams.get("search")) {
      setSearchParams({
        page: 1,
        search: "",
        category,
        condition,
      });
    }
  }, [search, setSearchParams, category, condition, searchParams]);

  const fetchBooks = async () => {
    try {
      setLoading(true);
      const res = await getBooks({
        page: currentPage,
        search: searchParams.get("search") || "",
        category: searchParams.get("category") || "",
        condition: searchParams.get("condition") || "",
      });
      setBooks(res.data.results);
      setNextPage(res.data.next);
      setPrevPage(res.data.previous);
    } catch (error) {
      const message = error.response?.data?.detail || "Failed to load books";
      if (message.toLowerCase().includes("invalid page")) {
        setSearchParams({ page: 1, search, category, condition });
        return;
      }
      toast.error(message);
    } finally {
      setLoading(false);
    }
  };

  const fetchCategories = async () => {
    try {
      const res = await getCategories();
      setCategories(res.data);
    } catch {
      toast.error("Failed to load categories");
    }
  };

  const handleSearch = () => {
    setSearchParams({ page: 1, search, category, condition });
  };

  return (
    <section className="min-h-screen pt-28 pb-12 px-6 md:px-10 bg-gradient-to-br from-[#F1F4F9] via-[#F8FAFF] to-[#FFFFFF] font-sans">
      {/* Expansive container for wide screens */}
      <div className="w-full max-w-[1600px] mx-auto">
        {/* Modern Search Island */}
        <div className="mb-12">
          <div className="flex flex-col lg:flex-row items-center justify-between gap-6 bg-white p-4 rounded-[2rem] shadow-[0_10px_40px_rgba(0,0,0,0.03)] border border-white/50 backdrop-blur-sm">
            {/* Search Input Group */}
            <div className="relative w-full lg:flex-1 group">
              <span className="absolute inset-y-0 left-5 flex items-center text-indigo-300 group-focus-within:text-[#5B4CF0] transition-colors">
                <svg
                  xmlns="http://www.w3.org/2000/svg"
                  className="h-5 w-5"
                  fill="none"
                  viewBox="0 0 24 24"
                  stroke="currentColor"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2.5}
                    d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"
                  />
                </svg>
              </span>
              <input
                type="text"
                placeholder="Search by title, author, or genre..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && handleSearch()}
                className="w-full pl-14 pr-6 py-4 bg-gray-50/50 border-none rounded-2xl focus:ring-2 focus:ring-[#5B4CF0]/10 transition-all text-gray-700 outline-none font-bold text-sm placeholder-gray-400"
              />
            </div>

            {/* Filter Group */}
            <div className="flex flex-wrap items-center gap-3 w-full lg:w-auto">
              <select
                value={category}
                onChange={(e) => {
                  const val = e.target.value;
                  setCategory(val);
                  setSearchParams({
                    page: 1,
                    search,
                    category: val,
                    condition,
                  });
                }}
                className="flex-1 lg:flex-none bg-gray-50/50 px-6 py-4 rounded-2xl border-none text-sm font-bold text-gray-500 outline-none focus:ring-2 focus:ring-[#5B4CF0]/10 cursor-pointer appearance-none"
              >
                <option value="">All Categories</option>
                {categories.map((cat) => (
                  <option key={cat.id} value={cat.id}>
                    {cat.name}
                  </option>
                ))}
              </select>

              <select
                value={condition}
                onChange={(e) => {
                  const val = e.target.value;
                  setCondition(val);
                  setSearchParams({
                    page: 1,
                    search,
                    category,
                    condition: val,
                  });
                }}
                className="flex-1 lg:flex-none bg-gray-50/50 px-6 py-4 rounded-2xl border-none text-sm font-bold text-gray-500 outline-none focus:ring-2 focus:ring-[#5B4CF0]/10 cursor-pointer appearance-none"
              >
                <option value="">Condition</option>
                <option value="new">New</option>
                <option value="like_new">Like New</option>
                <option value="good">Good</option>
                <option value="fair">Fair</option>
              </select>

              <button
                onClick={handleSearch}
                className="w-full lg:w-auto bg-[#26187D] text-white px-10 py-4 rounded-2xl font-black shadow-xl shadow-indigo-100 hover:bg-black transition-all active:scale-95 text-sm"
              >
                Find Books
              </button>
            </div>
          </div>
        </div>

        {/* AI Recommendations */}
        <div className="mb-10">
          <BookRecommendations />
        </div>

        {/* Dynamic Content Area */}

        {/* Dynamic Content Area */}
        {loading ? (
          <div className="flex flex-col items-center justify-center py-32">
            <div className="w-10 h-10 border-4 border-[#5B4CF0] border-t-transparent rounded-full animate-spin"></div>
            <p className="mt-6 text-gray-400 font-black uppercase tracking-widest text-[10px]">
              Updating Library...
            </p>
          </div>
        ) : books.length === 0 ? (
          <div className="text-center py-32 bg-white/40 rounded-[3rem] border border-white/60">
            <div className="text-6xl mb-6 opacity-40">📚</div>
            <h3 className="text-2xl font-black text-gray-900">
              No books found
            </h3>
            <p className="text-gray-400 font-bold mt-2">
              Try adjusting your AI filters or keywords.
            </p>
          </div>
        ) : (
          <>
            {/* Optimized Book Grid */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-10">
              {books.map((book) => (
                <div
                  key={book.id}
                  className="group bg-white rounded-[2.5rem] p-3 border border-white shadow-sm hover:shadow-[0_30px_60px_rgba(0,0,0,0.04)] transition-all duration-700"
                >
                  <Link
                    to={`/books/${book.id}`}
                    className="block relative overflow-hidden rounded-[2rem]"
                  >
                    {/* Floating Category Badge */}
                    <div className="absolute top-5 left-5 z-10 bg-white/90 backdrop-blur-md px-4 py-1.5 rounded-full shadow-sm">
                      <p className="text-[10px] uppercase tracking-widest font-black text-[#5B4CF0]">
                        {book.category_detail?.name || "General"}
                      </p>
                    </div>

                    {/* Image with subtle hover zoom */}
                    <div className="aspect-[3/4] overflow-hidden bg-gray-50">
                      <img
                        src={
                          book.image_thumbnail ||
                          book.image ||
                          "https://via.placeholder.com/300x400?text=No+Image"
                        }
                        alt={book.title}
                        className="w-full h-full object-cover transform group-hover:scale-105 transition-transform duration-1000"
                      />
                    </div>

                    {/* Interactive Overlay */}
                    <div className="absolute inset-0 bg-gradient-to-t from-[#26187D]/40 via-transparent to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-500 flex items-end p-8">
                      <span className="text-white text-xs font-black uppercase tracking-widest">
                        View details →
                      </span>
                    </div>
                  </Link>

                  <div className="px-4 py-6">
                    <h2 className="text-xl font-black text-gray-900 line-clamp-1 group-hover:text-[#5B4CF0] transition-colors leading-tight">
                      {book.title}
                    </h2>
                    <p className="text-gray-400 text-sm mb-5 font-bold mt-1 uppercase tracking-tight">
                      {book.author}
                    </p>

                    <div className="flex items-center justify-between border-t border-gray-50 pt-5">
                      <div className="space-y-0.5">
                        <p className="text-[10px] text-gray-300 uppercase font-black tracking-[0.15em]">
                          Condition
                        </p>
                        <p className="text-xs font-black text-gray-800 capitalize">
                          {book.condition.replace("_", " ")}
                        </p>
                      </div>
                      <Link
                        to={`/books/${book.id}`}
                        className="bg-[#26187D] w-12 h-12 rounded-2xl text-white flex items-center justify-center hover:bg-black transition-all shadow-lg shadow-indigo-100 active:scale-90"
                      >
                        <svg
                          xmlns="http://www.w3.org/2000/svg"
                          className="h-5 w-5"
                          viewBox="0 0 20 20"
                          fill="currentColor"
                        >
                          <path
                            fillRule="evenodd"
                            d="M10.293 3.293a1 1 0 011.414 0l6 6a1 1 0 010 1.414l-6 6a1 1 0 01-1.414-1.414L14.586 11H3a1 1 0 110-2h11.586l-4.293-4.293a1 1 0 010-1.414z"
                            clipRule="evenodd"
                          />
                        </svg>
                      </Link>
                    </div>
                  </div>
                </div>
              ))}
            </div>

            {/* Pagination Hub */}
            <div className="flex justify-center items-center gap-3 mt-20">
              <div className="bg-white p-2 rounded-[1.5rem] shadow-sm border border-gray-100 flex items-center gap-2">
                <button
                  onClick={() =>
                    setSearchParams({
                      ...Object.fromEntries(searchParams),
                      page: currentPage - 1,
                    })
                  }
                  disabled={!prevPage}
                  className="w-12 h-12 flex items-center justify-center text-gray-400 hover:text-[#5B4CF0] hover:bg-gray-50 rounded-xl disabled:opacity-20 disabled:hover:bg-transparent transition-all"
                >
                  <svg
                    xmlns="http://www.w3.org/2000/svg"
                    className="h-6 w-6"
                    fill="none"
                    viewBox="0 0 24 24"
                    stroke="currentColor"
                  >
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth={2.5}
                      d="M15 19l-7-7 7-7"
                    />
                  </svg>
                </button>

                <div className="px-6 border-x border-gray-100">
                  <span className="text-sm font-black text-[#26187D] uppercase tracking-tighter">
                    Page {currentPage}
                  </span>
                </div>

                <button
                  onClick={() =>
                    setSearchParams({
                      ...Object.fromEntries(searchParams),
                      page: currentPage + 1,
                    })
                  }
                  disabled={!nextPage}
                  className="w-12 h-12 flex items-center justify-center text-gray-400 hover:text-[#5B4CF0] hover:bg-gray-50 rounded-xl disabled:opacity-20 disabled:hover:bg-transparent transition-all"
                >
                  <svg
                    xmlns="http://www.w3.org/2000/svg"
                    className="h-6 w-6"
                    fill="none"
                    viewBox="0 0 24 24"
                    stroke="currentColor"
                  >
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth={2.5}
                      d="M9 5l7 7-7 7"
                    />
                  </svg>
                </button>
              </div>
            </div>
          </>
        )}
      </div>
    </section>
  );
}
