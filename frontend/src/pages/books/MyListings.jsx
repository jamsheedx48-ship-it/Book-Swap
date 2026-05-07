import { useEffect, useState } from "react";
import { getMyBooks } from "../../api/books";

export default function MyListings() {
  const [books, setBooks] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    fetchBooks();
  }, []);

  const fetchBooks = async () => {
    try {
      setLoading(true);
      setError("");

      const res = await getMyBooks();
      setBooks(res.data);
    } catch (err) {
      console.error(err);
      setError("Failed to load your listings.");
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-[#F6F7FF] flex items-center justify-center">
        <div className="text-center">
          <div className="w-12 h-12 border-4 border-[#26187D] border-t-transparent rounded-full animate-spin mx-auto mb-4"></div>
          <p className="text-[#26187D] text-lg font-medium">
            Loading your listings...
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-[#F6F7FF] px-6 md:px-10 py-10">
      <div className="max-w-6xl mx-auto">

        {/* Header */}
        <div className="mb-8">
          <h1 className="text-4xl font-bold text-[#26187D]">
            My Listings
          </h1>
          <p className="text-gray-500 mt-2 text-lg">
            Manage all books you listed for exchange
          </p>
        </div>

        {/* Error */}
        {error && (
          <div className="bg-red-50 border border-red-200 text-red-600 px-5 py-4 rounded-2xl mb-6">
            {error}
          </div>
        )}

        {/* Empty State */}
        {books.length === 0 ? (
          <div className="bg-white rounded-2xl p-14 text-center shadow-sm">
            <div className="text-6xl mb-4">📚</div>

            <h2 className="text-2xl font-semibold text-gray-700 mb-2">
              No listings yet
            </h2>

            <p className="text-gray-500 text-lg">
              Start listing books for exchange.
            </p>
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-6">
            {books.map((book) => (
              <div
                key={book.id}
                className="bg-white rounded-2xl shadow-sm border border-gray-100 overflow-hidden"
              >
                {/* Book Image */}
                <div className="h-64 bg-gray-100">
                  <img
                    src={
                    book.image_thumbnail 
                    ? book.image_thumbnail
                    : book.image
                    }
                    alt={book.title}
                    className="w-full h-full object-cover"
                  />
                </div>

                {/* Book Details */}
                <div className="p-5">
                  <h3 className="text-xl font-semibold text-black mb-2">
                    {book.title}
                  </h3>

                  <p className="text-gray-500 mb-2">
                    by {book.author}
                  </p>

                  <p className="text-sm text-gray-500 mb-2">
                    Condition:{" "}
                    <span className="font-medium text-black">
                      {book.condition}
                    </span>
                  </p>

                  {/* Availability Badge
                  <div className="mb-4">
                    <span
                      className={`px-3 py-1 rounded-full text-sm font-medium ${
                        book.is_available
                          ? "bg-green-100 text-green-700"
                          : "bg-red-100 text-red-700"
                      }`}
                    >
                      {book.is_available
                        ? "Available"
                        : "Unavailable"}
                    </span>
                  </div> */}

                  {/* Action Buttons */}
                  <div className="flex gap-3">
                    <button className="flex-1 bg-[#26187D] hover:bg-[#1c125e] text-white py-3 rounded-xl font-medium">
                      Edit
                    </button>

                    <button className="flex-1 bg-red-500 hover:bg-red-600 text-white py-3 rounded-xl font-medium">
                      Delete
                    </button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}