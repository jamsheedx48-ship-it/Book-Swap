import React, { useState,useEffect } from "react";
import { UploadCloud } from "lucide-react";
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

  // run fn on mount
  useEffect(() => {
    fetchCategories();
  }, []);

  // cleanup preview URL
  useEffect(() => {
    return () => {
      if (image) {
        URL.revokeObjectURL(image);
      }
    };
  }, [image]);

  // fetch all categories
  const fetchCategories = async () => {
    try {
      const response = await getCategories();
      setCategories(response.data);
    } catch (error) {
      toast.error("Failed to load categories");
    }
  };

  // frontend validation
  const validateForm = () => {
    if (!formData.title.trim()) {
      toast.error("Title is required");
      return false;
    }

    if (!formData.author.trim()) {
      toast.error("Author is required");
      return false;
    }

    if (!formData.genre) {
      toast.error("Please select a category");
      return false;
    }

    if (!formData.condition) {
      toast.error("Please select book condition");
      return false;
    }

    if (!formData.description.trim()) {
      toast.error("Description is required");
      return false;
    }

    if (!imageFile) {
      toast.error("Book image is required");
      return false;
    }

    return true;
  };

  // image upload
  const handleImageChange = (e) => {
    const file = e.target.files[0];
    if (file) {
      setImage(URL.createObjectURL(file)); // preview
      setImageFile(file); // actual backend upload
    }
  };

  // form input changes
  const handleChange = (e) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value,
    });
  };

  // submit form
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

      if (imageFile) {
        submitData.append("image", imageFile);
      }

      const response = await createBook(submitData);

      toast.success("Book listed successfully!");

      // reset form
      setFormData({
        title: "",
        author: "",
        genre: "",
        condition: "",
        description: "",
      });

      setImage(null);
      setImageFile(null);
    } catch (error) {
      const backendErrors = error.response?.data;

      if (backendErrors) {
        Object.entries(backendErrors).forEach(([field, messages]) => {
          if (Array.isArray(messages)) {
            messages.forEach((msg) => toast.error(msg));
          } else {
            toast.error(messages);
          }
        });
      } else {
        toast.error("Something went wrong");
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <MainLayout>
      <div className="flex justify-center">
        <div className="w-full max-w-3xl bg-white rounded-2xl shadow-sm p-8">
          {/* Header */}
          <h1 className="text-2xl font-bold text-black">List a New Book</h1>

          <p className="text-sm text-gray-600 mt-1 mb-6">
            Share your collection with the community and discover your next
            read.
          </p>

          <form onSubmit={handleSubmit} className="space-y-5">
            {/* Upload */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Book Cover
              </label>

              <label className="border-2 border-dashed border-gray-200 rounded-xl h-48 flex flex-col items-center justify-center cursor-pointer hover:border-[#26187D] transition">
                {image ? (
                  <img
                    src={image}
                    alt="Preview"
                    className="h-full w-full object-cover rounded-xl"
                  />
                ) : (
                  <>
                    <UploadCloud className="w-10 h-10 text-[#26187D] mb-2" />
                    <p className="text-sm font-medium text-gray-700">
                      Click to upload or drag and drop
                    </p>
                    <p className="text-xs text-gray-400">
                      PNG, JPG or WEBP (Max: 5MB)
                    </p>
                  </>
                )}

                <input
                  type="file"
                  accept="image/*"
                  className="hidden"
                  onChange={handleImageChange}
                />
              </label>
            </div>

            {/* Title */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Book Title
              </label>
              <input
                type="text"
                name="title"
                value={formData.title}
                onChange={handleChange}
                placeholder="e.g. The Great Gatsby"
                className="w-full border border-gray-200 rounded-lg px-4 py-3 focus:outline-none focus:ring-2 focus:ring-[#26187D]"
              />
            </div>

            {/* Author */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Author
              </label>
              <input
                type="text"
                name="author"
                value={formData.author}
                onChange={handleChange}
                placeholder="e.g. F. Scott Fitzgerald"
                className="w-full border border-gray-200 rounded-lg px-4 py-3 focus:outline-none focus:ring-2 focus:ring-[#26187D]"
              />
            </div>

            {/* Genre + Condition */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Genre
                </label>
                <select
                  name="genre"
                  value={formData.genre}
                  onChange={handleChange}
                  className="w-full border border-gray-200 rounded-lg px-4 py-3 focus:outline-none focus:ring-2 focus:ring-[#26187D]"
                >
                  <option value="">Select genre</option>
                  {categories.map((category) => (
                    <option key={category.id} value={category.id}>
                      {category.name}
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Condition
                </label>
                <select
                  name="condition"
                  value={formData.condition}
                  onChange={handleChange}
                  className="w-full border border-gray-200 rounded-lg px-4 py-3 focus:outline-none focus:ring-2 focus:ring-[#26187D]"
                >
                  <option value="">Select condition</option>
                  <option value="new">New</option>
                  <option value="good">Good</option>
                  <option value="fair">Fair</option>
                </select>
              </div>
            </div>

            {/* Description */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Description
              </label>
              <textarea
                rows="4"
                name="description"
                value={formData.description}
                onChange={handleChange}
                placeholder="Tell others about your book"
                className="w-full border border-gray-200 rounded-lg px-4 py-3 focus:outline-none focus:ring-2 focus:ring-[#26187D]"
              />
            </div>

            {/* Buttons */}
            <div className="flex justify-end gap-3 pt-4">
              <button
                type="button"
                className="px-5 py-2 rounded-lg border border-gray-200 text-gray-700 hover:bg-[#F6F7FF]"
              >
                Cancel
              </button>

              <button
                type="submit"
                disabled={loading}
                className="px-6 py-2 rounded-lg bg-[#26187D] text-white hover:opacity-90 disabled:opacity-50"
              >
                {loading ? "Listing..." : "List Your Book"}
              </button>
            </div>
          </form>
        </div>
      </div>
    </MainLayout>
  );
}
