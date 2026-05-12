import { useEffect, useState } from "react";
import { BookOpen, Pencil, Trash2, PackageOpen, X, Sparkles, LayoutGrid, Trash } from "lucide-react";
import { toast } from "react-toastify";
import { Link } from "react-router-dom";

import ConfirmationModal from "../../components/ConfirmationModal";
import { getMyBooks, updateBook, deleteBook } from "../../api/books";

export default function MyListings() {
  const [books, setBooks] = useState([]);
  const [loading, setLoading] = useState(true);
  const [editingBook, setEditingBook] = useState(null);
  const [deleteBookId, setDeleteBookId] = useState(null);

  const [formData, setFormData] = useState({
    title: "",
    author: "",
    condition: "",
    description: "",
  });

  useEffect(() => {
    fetchBooks();
  }, []);

  const fetchBooks = async () => {
    try {
      const res = await getMyBooks();
      setBooks(res.data);
    } catch (error) {
      toast.error("Failed to load listings");
    } finally {
      setLoading(false);
    }
  };

  const handleEditClick = (book) => {
    setEditingBook(book);
    setFormData({
      title: book.title || "",
      author: book.author || "",
      condition: book.condition || "",
      description: book.description || "",
    });
  };

  const handleUpdateBook = async () => {
    try {
      await updateBook(editingBook.id, formData);
      toast.success("Book updated successfully");
      setEditingBook(null);
      fetchBooks();
    } catch (error) {
      toast.error(error.response?.data?.detail || "Failed to update book");
    }
  };

  const handleDeleteBook = async () => {
    try {
      await deleteBook(deleteBookId);
      toast.success("Book moved to trash");
      setDeleteBookId(null);
      fetchBooks();
    } catch (error) {
      toast.error(error.response?.data?.detail || "Failed to delete book");
    }
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-[#F1F4F9] flex flex-col items-center justify-center">
        <div className="w-10 h-10 border-4 border-[#26187D] border-t-transparent rounded-full animate-spin mb-4"></div>
        <p className="text-[10px] font-bold text-gray-400 uppercase tracking-widest">Accessing Ecosystem...</p>
      </div>
    );
  }

  return (
    <div className="min-h-screen pt-28 pb-12 px-6 md:px-10 bg-gradient-to-br from-[#F1F4F9] via-[#F8FAFF] to-white font-sans">
      <div className="max-w-[1600px] mx-auto">
        
        {/* Header Section */}
        <div className="mb-12 flex flex-col lg:flex-row lg:items-end justify-between gap-6">
          <div>
            <div className="flex items-center gap-2 mb-2">
              <Sparkles className="text-[#5B4CF0]" size={18} />
              <span className="text-[10px] font-bold uppercase tracking-[0.2em] text-[#26187D]">
                Personal Library 
              </span>
            </div>
            <h1 className="text-4xl font-bold text-slate-900 tracking-tight">My Listings</h1>
            <p className="text-gray-500 mt-1 font-medium">Manage and circulate your knowledge exchange books.</p>
          </div>

          <div className="flex items-center gap-4">
            <Link
              to="/trash-books"
              className="flex items-center gap-2 bg-white px-6 py-3 rounded-2xl text-gray-500 font-bold text-sm border border-gray-100 hover:bg-gray-50 transition-all shadow-sm"
            >
              <Trash size={16} />
              View Trash
            </Link>
            <Link
              to="/list-book"
              className="flex items-center gap-2 bg-[#26187D] px-6 py-3 rounded-2xl text-white font-bold text-sm shadow-xl shadow-indigo-100 hover:bg-black transition-all"
            >
              <LayoutGrid size={16} />
              Add New
            </Link>
          </div>
        </div>

        {/* Listings Grid */}
        {books.length === 0 ? (
          <div className="bg-white/60 backdrop-blur-sm rounded-[3rem] p-20 text-center border border-white shadow-sm">
            <PackageOpen className="mx-auto text-gray-200 mb-6" size={80} />
            <h2 className="text-xl font-bold text-slate-900 mb-2">No active listings</h2>
            <p className="text-gray-400 font-medium mb-8">Start your first swap by listing a book.</p>
            <Link to="/list-book" className="text-[#5B4CF0] font-bold text-sm hover:underline tracking-tight">
              List a Book Now →
            </Link>
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-8">
            {books.map((book) => (
              <div
                key={book.id}
                className="group bg-white rounded-[2.5rem] p-3 border border-white shadow-sm hover:shadow-[0_20px_50px_rgba(0,0,0,0.05)] transition-all duration-500"
              >
                <div className="relative aspect-[3/4] overflow-hidden rounded-[2rem] bg-gray-50">
                  <img
                    src={book.image_thumbnail || book.image || "/placeholder-book.jpg"}
                    alt={book.title}
                    className="w-full h-full object-cover transition-transform duration-700 group-hover:scale-105"
                  />
                  <div className="absolute top-4 left-4 bg-white/90 backdrop-blur-md px-3 py-1 rounded-full shadow-sm">
                    <span className="text-[10px] font-bold uppercase tracking-wider text-[#5B4CF0]">
                      {book.condition}
                    </span>
                  </div>
                </div>

                <div className="px-3 py-5">
                  <h3 className="text-lg font-bold text-slate-900 line-clamp-1 mb-1 leading-tight group-hover:text-[#26187D] transition-colors">
                    {book.title}
                  </h3>
                  <p className="text-gray-400 text-sm font-bold uppercase tracking-tight mb-4">{book.author}</p>

                  <div className="flex gap-2">
                    <button
                      onClick={() => handleEditClick(book)}
                      className="flex-1 bg-gray-50 hover:bg-indigo-50 text-gray-600 hover:text-[#26187D] py-3 rounded-xl font-bold text-xs transition-all flex items-center justify-center gap-2"
                    >
                      <Pencil size={14} />
                      Edit
                    </button>
                    <button
                      onClick={() => setDeleteBookId(book.id)}
                      className="w-12 h-12 bg-gray-50 hover:bg-rose-50 text-gray-400 hover:text-rose-500 rounded-xl transition-all flex items-center justify-center"
                    >
                      <Trash2 size={16} />
                    </button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}

        {/* Edit Modal - Ecosystem Glass Style */}
        {editingBook && (
          <div className="fixed inset-0 bg-slate-900/40 backdrop-blur-sm flex items-center justify-center z-[110] px-4">
            <div className="bg-white w-full max-w-xl rounded-[3rem] p-8 shadow-2xl border border-white overflow-hidden relative">
              <div className="flex justify-between items-center mb-8">
                <h2 className="text-2xl font-bold text-slate-900 tracking-tight">Edit Listing</h2>
                <button onClick={() => setEditingBook(null)} className="p-2 hover:bg-gray-100 rounded-xl transition-colors">
                  <X size={20} className="text-gray-400" />
                </button>
              </div>

              <div className="space-y-4">
                <div className="space-y-1">
                    <label className="text-[10px] font-bold text-gray-400 uppercase tracking-widest ml-2">Book Title</label>
                    <input
                    type="text"
                    value={formData.title}
                    onChange={(e) => setFormData({ ...formData, title: e.target.value })}
                    className="w-full bg-gray-50 border-none rounded-2xl px-5 py-3 text-sm font-medium focus:ring-2 focus:ring-indigo-100 outline-none transition-all"
                    />
                </div>

                <div className="grid grid-cols-2 gap-4">
                    <div className="space-y-1">
                        <label className="text-[10px] font-bold text-gray-400 uppercase tracking-widest ml-2">Author</label>
                        <input
                        type="text"
                        value={formData.author}
                        onChange={(e) => setFormData({ ...formData, author: e.target.value })}
                        className="w-full bg-gray-50 border-none rounded-2xl px-5 py-3 text-sm font-medium focus:ring-2 focus:ring-indigo-100 outline-none"
                        />
                    </div>
                    <div className="space-y-1">
                        <label className="text-[10px] font-bold text-gray-400 uppercase tracking-widest ml-2">Condition</label>
                        <select
                        value={formData.condition}
                        onChange={(e) => setFormData({ ...formData, condition: e.target.value })}
                        className="w-full bg-gray-50 border-none rounded-2xl px-5 py-3 text-sm font-medium focus:ring-2 focus:ring-indigo-100 outline-none appearance-none"
                        >
                            <option value="new">New</option>
                            <option value="like_new">Like New</option>
                            <option value="good">Good</option>
                            <option value="fair">Fair</option>
                        </select>
                    </div>
                </div>

                <div className="space-y-1">
                    <label className="text-[10px] font-bold text-gray-400 uppercase tracking-widest ml-2">AI Optimized Description [cite: 69-72]</label>
                    <textarea
                    value={formData.description}
                    onChange={(e) => setFormData({ ...formData, description: e.target.value })}
                    className="w-full bg-gray-50 border-none rounded-2xl px-5 py-3 text-sm font-medium focus:ring-2 focus:ring-indigo-100 outline-none h-32 resize-none"
                    />
                </div>

                <button
                  onClick={handleUpdateBook}
                  className="w-full bg-[#26187D] hover:bg-black text-white py-4 rounded-2xl font-bold transition-all shadow-xl shadow-indigo-100 mt-4"
                >
                  Save Changes
                </button>
              </div>
            </div>
          </div>
        )}
      </div>

      <ConfirmationModal
        isOpen={!!deleteBookId}
        onClose={() => setDeleteBookId(null)}
        onConfirm={handleDeleteBook}
        title="Move to Trash"
        message="This will remove the book from the active exchange ecosystem. You can restore it later from your trash."
        confirmText="Move to Trash"
      />
    </div>
  );
}