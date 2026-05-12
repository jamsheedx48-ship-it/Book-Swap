import React, { useState, useEffect } from "react";
import { UploadCloud, ChevronRight, X } from "lucide-react";
import { toast } from "react-toastify";
import MainLayout from "../../components/MainLayout";
import { createBook, getCategories } from "../../api/books";

export default function AddBookForm() {
  const [image, setImage] = useState(null);
  const [imageFile, setImageFile] = useState(null);
  const [loading, setLoading] = useState(false);
  const [categories, setCategories] = useState([]);

  const [formData, setFormData] = useState({
    title: "",
    author: "",
    genre: "",
    condition: "",
    description: "",
  });

  useEffect(() => {
    fetchCategories();
  }, []);

  useEffect(() => {
    return () => {
      if (image) URL.revokeObjectURL(image);
    };
  }, [image]);

  const fetchCategories = async () => {
    try {
      const response = await getCategories();
      setCategories(response.data);
    } catch (error) {
      toast.error("Failed to load categories");
    }
  };

  const validateForm = () => {
    if (!formData.title.trim()) { toast.error("Title is required"); return false; }
    if (!formData.author.trim()) { toast.error("Author is required"); return false; }
    if (!formData.genre) { toast.error("Please select a category"); return false; }
    if (!formData.condition) { toast.error("Please select book condition"); return false; }
    if (!formData.description.trim()) { toast.error("Description is required"); return false; }
    if (!imageFile) { toast.error("Book image is required"); return false; }
    return true;
  };

  const handleImageChange = (e) => {
    const file = e.target.files[0];
    if (file) {
      setImage(URL.createObjectURL(file));
      setImageFile(file);
    }
  };

  const handleChange = (e) => {
    setFormData({ ...formData, [e.target.name]: e.target.value });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!validateForm()) return;
    setLoading(true);

    try {
      const submitData = new FormData();
      submitData.append("title", formData.title);
      submitData.append("author", formData.author);
      submitData.append("category", formData.genre);
      submitData.append("condition", formData.condition);
      submitData.append("description", formData.description);
      if (imageFile) submitData.append("image", imageFile);

      await createBook(submitData);
      toast.success("Book listed successfully!");
      setFormData({ title: "", author: "", genre: "", condition: "", description: "" });
      setImage(null);
      setImageFile(null);
    } catch (error) {
      toast.error("Something went wrong");
    } finally {
      setLoading(false);
    }
  };

  return (
    <MainLayout>
      {/* Clean, solid light background */}
      <div className="min-h-screen pt-32 pb-16 px-6 bg-[#F8FAFF] font-sans">
        <div className="max-w-[1000px] mx-auto">
          
          {/* Header */}
          <div className="mb-10 text-center md:text-left">
            <h1 className="text-3xl font-bold text-slate-900">List a New Book</h1>
            <p className="text-gray-500 mt-2 font-medium">Fill in the details to add your book to the collection.</p>
          </div>

          {/* Form Card */}
          <div className="bg-white rounded-[2rem] p-8 md:p-12 shadow-sm border border-gray-100">
            <form onSubmit={handleSubmit} className="space-y-10">
              
              {/* Cover Upload */}
              <div className="space-y-3">
                <label className="text-[11px] font-bold text-gray-400 uppercase tracking-widest ml-1">Book Cover</label>
                <label className="relative group border-2 border-dashed border-gray-100 rounded-3xl h-64 flex flex-col items-center justify-center cursor-pointer hover:bg-gray-50 transition-all overflow-hidden">
                  {image ? (
                    <div className="relative w-full h-full">
                      <img src={image} alt="Preview" className="h-full w-full object-cover" />
                      <button 
                        type="button"
                        onClick={(e) => { e.preventDefault(); setImage(null); setImageFile(null); }}
                        className="absolute top-4 right-4 bg-black/60 text-white p-2 rounded-full hover:bg-rose-500 transition-colors"
                      >
                        <X size={16} />
                      </button>
                    </div>
                  ) : (
                    <div className="text-center">
                      <UploadCloud className="w-10 h-10 text-gray-300 mx-auto mb-3" />
                      <p className="text-sm font-bold text-gray-600">Select book cover</p>
                      <p className="text-[10px] text-gray-400 font-bold uppercase mt-1">JPG, PNG or WEBP (Max 5MB)</p>
                    </div>
                  )}
                  <input type="file" accept="image/*" className="hidden" onChange={handleImageChange} />
                </label>
              </div>

              {/* Form Grid */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
                <div className="space-y-2">
                  <label className="text-[11px] font-bold text-gray-400 uppercase tracking-widest ml-1">Book Title</label>
                  <input
                    name="title"
                    value={formData.title}
                    onChange={handleChange}
                    placeholder="e.g. The Psychology of Money"
                    className="w-full bg-gray-50 border border-transparent rounded-2xl px-6 py-4 text-sm font-bold text-slate-800 placeholder-gray-300 focus:bg-white focus:border-indigo-100 outline-none transition-all"
                  />
                </div>
                <div className="space-y-2">
                  <label className="text-[11px] font-bold text-gray-400 uppercase tracking-widest ml-1">Author</label>
                  <input
                    name="author"
                    value={formData.author}
                    onChange={handleChange}
                    placeholder="Morgan Housel"
                    className="w-full bg-gray-50 border border-transparent rounded-2xl px-6 py-4 text-sm font-bold text-slate-800 placeholder-gray-300 focus:bg-white focus:border-indigo-100 outline-none transition-all"
                  />
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
                <div className="space-y-2">
                  <label className="text-[11px] font-bold text-gray-400 uppercase tracking-widest ml-1">Genre</label>
                  <select
                    name="genre"
                    value={formData.genre}
                    onChange={handleChange}
                    className="w-full bg-gray-50 border border-transparent rounded-2xl px-6 py-4 text-sm font-bold text-gray-600 appearance-none focus:bg-white focus:border-indigo-100 outline-none cursor-pointer"
                  >
                    <option value="">Select Category</option>
                    {categories.map((cat) => (
                      <option key={cat.id} value={cat.id}>{cat.name}</option>
                    ))}
                  </select>
                </div>
                <div className="space-y-2">
                  <label className="text-[11px] font-bold text-gray-400 uppercase tracking-widest ml-1">Condition</label>
                  <select
                    name="condition"
                    value={formData.condition}
                    onChange={handleChange}
                    className="w-full bg-gray-50 border border-transparent rounded-2xl px-6 py-4 text-sm font-bold text-gray-600 appearance-none focus:bg-white focus:border-indigo-100 outline-none cursor-pointer"
                  >
                    <option value="">Book Condition</option>
                    <option value="new">New</option>
                    <option value="good">Good</option>
                    <option value="fair">Fair</option>
                  </select>
                </div>
              </div>

              <div className="space-y-2">
                <label className="text-[11px] font-bold text-gray-400 uppercase tracking-widest ml-1">Description</label>
                <textarea
                  rows="4"
                  name="description"
                  value={formData.description}
                  onChange={handleChange}
                  placeholder="Tell others about the book..."
                  className="w-full bg-gray-50 border border-transparent rounded-2xl px-6 py-4 text-sm font-bold text-slate-800 placeholder-gray-300 resize-none focus:bg-white focus:border-indigo-100 outline-none transition-all"
                />
              </div>

              {/* Action */}
              <div className="pt-6 flex justify-end">
                <button
                  type="submit"
                  disabled={loading}
                  className="w-full md:w-auto bg-[#26187D] text-white px-12 py-4 rounded-2xl font-bold text-sm shadow-lg shadow-indigo-100 hover:bg-black transition-all flex items-center justify-center gap-2 active:scale-95 disabled:opacity-50"
                >
                  {loading ? "Listing..." : "List Book"} <ChevronRight size={18} />
                </button>
              </div>
            </form>
          </div>
        </div>
      </div>
    </MainLayout>
  );
}