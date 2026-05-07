import React, { useEffect, useState } from "react";
import { toast } from "react-toastify";
import { createExchangeRequest } from "../api/exchange";
import { getMyBooks } from "../api/books";

const ExchangeModal = ({ book, isOpen, onClose }) => {
  const [myBooks, setMyBooks] = useState([]);
  const [selectedBook, setSelectedBook] = useState("");
  const [message, setMessage] = useState("");
  const [loadingBooks, setLoadingBooks] = useState(false);
  const [sendingRequest, setSendingRequest] = useState(false);

  useEffect(() => {
    if (isOpen) {
      fetchMyBooks();
    }
  }, [isOpen]);

  const fetchMyBooks = async () => {
    try {
      setLoadingBooks(true);
      const res = await getMyBooks();
      setMyBooks(res.data.results || res.data);
    } catch (error) {
      toast.error("Failed to load your books");
    } finally {
      setLoadingBooks(false);
    }
  };

  const handleSubmit = async () => {
    if (!selectedBook) {
      toast.error("Please select a book");
      return;
    }

    try {
      setSendingRequest(true);

      await createExchangeRequest({
        offered_book: selectedBook,
        requested_book: book.id,
        message,
      });

      toast.success("Exchange request sent");

      setSelectedBook("");
      setMessage("");
      onClose();
    } catch (error) {
      toast.error(
        error.response?.data?.detail ||
          error.response?.data?.non_field_errors?.[0] ||
          "Failed to send request"
      );
    } finally {
      setSendingRequest(false);
    }
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
      <div className="bg-white w-full max-w-md rounded-2xl p-6 shadow-xl">
        <h2 className="text-xl font-bold mb-4">Request Book Swap</h2>

        {loadingBooks ? (
          <p>Loading your books...</p>
        ) : (
          <select
            value={selectedBook}
            onChange={(e) => setSelectedBook(e.target.value)}
            className="w-full border border-gray-200 rounded-xl p-3 mb-4"
          >
            <option value="">Select your book</option>

            {myBooks.map((myBook) => (
              <option key={myBook.id} value={myBook.id}>
                {myBook.title}
              </option>
            ))}
          </select>
        )}

        <textarea
          value={message}
          onChange={(e) => setMessage(e.target.value)}
          placeholder="Optional message..."
          rows="3"
          className="w-full border border-gray-200 rounded-xl p-3 mb-4"
        />

        <div className="flex gap-3">
          <button
            onClick={onClose}
            className="flex-1 border border-gray-200 py-3 rounded-xl"
          >
            Cancel
          </button>

          <button
            onClick={handleSubmit}
            disabled={sendingRequest}
            className="flex-1 bg-[#26187D] text-white py-3 rounded-xl disabled:opacity-50"
          >
            {sendingRequest ? "Sending..." : "Send Request"}
          </button>
        </div>
      </div>
    </div>
  );
};

export default ExchangeModal;