import { useEffect, useState } from "react";
import { Trash2, RotateCcw, Sparkles, Trash } from "lucide-react";
import { toast } from "react-toastify";

import {
  getTrashBooks,
  restoreBook,
  permanentlyDeleteBook,
} from "../../api/books";

import ConfirmationModal from "../../components/ConfirmationModal";

export default function TrashBooks() {
  const [books, setBooks] = useState([]);
  const [loading, setLoading] = useState(true);

  const [restoreId, setRestoreId] = useState(null);
  const [deleteId, setDeleteId] = useState(null);

  useEffect(() => {
    fetchTrashBooks();
  }, []);

  const fetchTrashBooks = async () => {
    try {
      const res = await getTrashBooks();
      setBooks(res.data);
    } catch (error) {
      toast.error("Failed to load trash");
    } finally {
      setLoading(false);
    }
  };

  const handleRestore = async () => {
    try {
      await restoreBook(restoreId);
      toast.success("Book restored successfully");
      setRestoreId(null);
      fetchTrashBooks();
    } catch (error) {
      toast.error("Failed to restore book");
    }
  };

  const handlePermanentDelete = async () => {
    try {
      await permanentlyDeleteBook(deleteId);
      toast.success("Book permanently deleted");
      setDeleteId(null);
      fetchTrashBooks();
    } catch (error) {
      toast.error("Failed to delete permanently");
    }
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-[#F1F4F9] flex flex-col items-center justify-center">
        <div className="w-10 h-10 border-4 border-[#26187D] border-t-transparent rounded-full animate-spin mb-4"></div>
        <p className="text-[10px] font-bold text-gray-400 uppercase tracking-widest">Cleaning up...</p>
      </div>
    );
  }

  return (
    <div className="min-h-screen pt-28 pb-12 px-6 md:px-10 bg-gradient-to-br from-[#F1F4F9] via-[#F8FAFF] to-white font-sans">
      <div className="max-w-[1600px] mx-auto">
        
        {/* Header Section */}
        <div className="mb-12 flex items-end justify-between">
          <div>
            <div className="flex items-center gap-2 mb-2">
              <Trash className="text-gray-400" size={18} />
              <span className="text-[10px] font-bold uppercase tracking-[0.2em] text-gray-400">
                Temporary Storage
              </span>
            </div>
            <h1 className="text-4xl font-bold text-slate-900 tracking-tight">Trash</h1>
            <p className="text-gray-500 mt-1 font-medium">Books here are removed from the exchange ecosystem but can be restored.</p>
          </div>
        </div>

        {/* Content Section */}
        {books.length === 0 ? (
          <div className="bg-white/60 backdrop-blur-sm rounded-[3rem] p-20 text-center border border-white shadow-sm">
            <div className="bg-gray-50 w-20 h-20 rounded-full flex items-center justify-center mx-auto mb-6">
               <Sparkles className="text-gray-200" size={40} />
            </div>
            <h2 className="text-xl font-bold text-slate-900 mb-2">Trash is empty</h2>
            <p className="text-gray-400 font-medium max-w-sm mx-auto">
              You haven't deleted any books. Your library is clean and active.
            </p>
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-8">
            {books.map((book) => (
              <div
                key={book.id}
                className="group bg-white rounded-[2.5rem] p-3 border border-white shadow-sm hover:shadow-[0_20px_50px_rgba(0,0,0,0.05)] transition-all duration-500"
              >
                <div className="relative aspect-[3/4] overflow-hidden rounded-[2rem] bg-gray-50 grayscale hover:grayscale-0 transition-all duration-500">
                  <img
                    src={book.image_thumbnail || book.image}
                    alt={book.title}
                    className="w-full h-full object-cover"
                  />
                  <div className="absolute inset-0 bg-black/20 group-hover:bg-transparent transition-colors" />
                </div>

                <div className="px-3 py-5">
                  <h3 className="text-lg font-bold text-slate-900 line-clamp-1 mb-1">
                    {book.title}
                  </h3>
                  <p className="text-gray-400 text-xs font-bold uppercase tracking-tight mb-5">by {book.author}</p>

                  <div className="flex gap-2">
                    <button
                      onClick={() => setRestoreId(book.id)}
                      className="flex-1 flex items-center justify-center gap-2 bg-gray-50 hover:bg-[#26187D] hover:text-white text-gray-600 py-3 rounded-xl font-bold text-xs transition-all shadow-sm"
                    >
                      <RotateCcw size={14} />
                      Restore
                    </button>

                    <button
                      onClick={() => setDeleteId(book.id)}
                      className="w-12 h-12 flex items-center justify-center bg-gray-50 hover:bg-rose-50 text-gray-400 hover:text-rose-500 rounded-xl transition-all"
                    >
                      <Trash2 size={16} />
                    </button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}

        {/* Modals */}
        <ConfirmationModal
          isOpen={!!restoreId}
          onClose={() => setRestoreId(null)}
          onConfirm={handleRestore}
          title="Restore Listing"
          message="This book will be re-added to your public listings and the exchange ecosystem."
          confirmText="Restore"
          confirmColor="bg-[#26187D]"
        />

        <ConfirmationModal
          isOpen={!!deleteId}
          onClose={() => setDeleteId(null)}
          onConfirm={handlePermanentDelete}
          title="Permanent Delete"
          message="This action is final. The book will be removed from the database and cannot be recovered."
          confirmText="Delete Forever"
        />
      </div>
    </div>
  );
}