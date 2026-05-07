import React, { useEffect, useState } from "react";
import { useSearchParams, Link } from "react-router-dom";
import { getBooks, getCategories } from "../api/books";
import { toast } from "react-toastify";

export default function BookGrid() {
  const [books, setBooks] = useState([]);
  const [categories, setCategories] = useState([]);
  const [loading, setLoading] = useState(true);

  // Pagination
  const [nextPage, setNextPage] = useState(null);
  const [prevPage, setPrevPage] = useState(null);

  const [searchParams, setSearchParams] = useSearchParams();

  const currentPage = Math.max(1, Number(searchParams.get("page")) || 1);

  // Filters
  const [search, setSearch] = useState(searchParams.get("search") || "");
  const [category, setCategory] = useState(searchParams.get("category") || "");
  const [condition, setCondition] = useState(
    searchParams.get("condition") || "",
  );

  // Fetch books when filters/page changes
  useEffect(() => {
    fetchBooks();
  }, [currentPage, searchParams]);

  // Fetch categories once
  useEffect(() => {
    fetchCategories();
  }, []);

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
      const message =
        error.response?.data?.detail ||
        error.response?.data?.error ||
        "Failed to load books";

      if (message.toLowerCase().includes("invalid page")) {
        setSearchParams({
          page: 1,
          search,
          category,
          condition,
        });
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
    } catch (error) {
      toast.error("Failed to load categories");
    }
  };

  const handleSearch = () => {
    setSearchParams({
      page: 1,
      search,
      category,
      condition,
    });
  };

  if (loading) {
    return (
      <div className="text-center py-20 text-lg font-medium">
        Loading books...
      </div>
    );
  }

  return (
    <section className="bg-[#F6F7FF] min-h-screen py-10 px-6">
      {/* Filters */}
      <div className="flex flex-col lg:flex-row gap-4 mb-10 justify-center items-center">
        {/* Search Bar */}
        <div className="flex items-center bg-white shadow-md rounded-2xl px-4 py-3 w-full max-w-2xl border border-gray-100">
          <input
            type="text"
            placeholder="Search by title, author, or category..."
            value={search}
            onChange={(e) => {
              const value = e.target.value;
              setSearch(value);

              // Auto reset books when search becomes empty
              if (value.trim() === "") {
                setSearchParams({
                  page: 1,
                  search: "",
                  category,
                  condition,
                });
              }
            }}
            onKeyDown={(e) => {
              if (e.key === "Enter") {
                handleSearch();
              }
            }}
            className="flex-1 outline-none text-sm text-gray-700 placeholder-gray-400"
          />

          <button
            onClick={handleSearch}
            className="bg-[#5B4CF0] hover:bg-[#4b3ee0] text-white px-6 py-2 rounded-xl font-medium transition"
          >
            Search
          </button>
        </div>

        {/* Category Filter */}
        <select
          value={category}
          onChange={(e) => {
            const value = e.target.value;
            setCategory(value);

            setSearchParams({
              page: 1,
              search,
              category: value,
              condition,
            });
          }}
          className="bg-white shadow-md rounded-2xl px-5 py-3 border border-gray-100 outline-none text-gray-700 min-w-[200px]"
        >
          <option value="">All Categories</option>

          {categories.map((cat) => (
            <option key={cat.id} value={cat.id}>
              {cat.name}
            </option>
          ))}
        </select>

        {/* Condition Filter */}
        <select
          value={condition}
          onChange={(e) => {
            const value = e.target.value;
            setCondition(value);

            setSearchParams({
              page: 1,
              search,
              category,
              condition: value,
            });
          }}
          className="bg-white shadow-md rounded-2xl px-5 py-3 border border-gray-100 outline-none text-gray-700 min-w-[200px]"
        >
          <option value="">All Conditions</option>
          <option value="new">New</option>
          <option value="like_new">Like New</option>
          <option value="good">Good</option>
          <option value="fair">Fair</option>
        </select>
      </div>

      {/* Empty State */}
      {books.length === 0 ? (
        <div className="text-center text-gray-500 text-lg">No books found</div>
      ) : (
        <>
          {/* Book Grid */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-8">
            {books.map((book) => (
              <div
                key={book.id}
                className="bg-white rounded-2xl overflow-hidden border border-gray-100 shadow-sm hover:shadow-xl hover:-translate-y-1 transition duration-300"
              >
                {/* Clickable Card */}
                <Link to={`/books/${book.id}`}>
                  <div className="relative">
                    <span className="absolute top-4 left-4 bg-white/90 backdrop-blur-sm text-gray-700 text-xs font-semibold px-3 py-1 rounded-full shadow-sm">
                      {book.category_detail?.name || "No Category"}
                    </span>

                    <img
                      src={
                        book.image_thumbnail
                          ? book.image_thumbnail
                          : book.image
                            ? book.image
                            : "https://via.placeholder.com/300x400?text=No+Image"
                      }
                      alt={book.title}
                      className="w-full h-80 object-cover"
                    />
                  </div>

                  <div className="p-5">
                    <h2 className="text-xl font-semibold text-black mb-2 line-clamp-1">
                      {book.title}
                    </h2>

                    <p className="text-gray-500 text-sm mb-3">{book.author}</p>

                    <p className="text-sm text-gray-600 capitalize">
                      Condition: {book.condition}
                    </p>
                  </div>
                

                {/* Request Swap Button */}
                <div className="p-5 pt-0">
                  <button
                    onClick={() => {
                      console.log("Request swap clicked");
                    }}
                    className="w-full bg-[#26187D] text-white py-3 rounded-xl font-medium hover:bg-[#1d1360] transition"
                  >
                    View Details
                  </button>
                </div>
                </Link>
              </div>
            ))}
          </div>

          {/* Pagination */}
          <div className="flex justify-center items-center gap-4 mt-10">
            <button
              onClick={() =>
                setSearchParams({
                  page: currentPage - 1,
                  search: searchParams.get("search") || "",
                  category: searchParams.get("category") || "",
                  condition: searchParams.get("condition") || "",
                })
              }
              disabled={!prevPage}
              className="px-4 py-2 bg-gray-200 rounded-lg disabled:opacity-50"
            >
              Previous
            </button>

            <span className="px-4 py-2 font-medium text-[#26187D]">
              Page {currentPage}
            </span>

            <button
              onClick={() =>
                setSearchParams({
                  page: currentPage + 1,
                  search: searchParams.get("search") || "",
                  category: searchParams.get("category") || "",
                  condition: searchParams.get("condition") || "",
                })
              }
              disabled={!nextPage}
              className="px-4 py-2 bg-[#26187D] text-white rounded-lg disabled:opacity-50"
            >
              Next
            </button>
          </div>
        </>
      )}
    </section>
  );
}
