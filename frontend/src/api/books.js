import api from "./axiosInstance";

// Create book
export const createBook = (formData) => {
  return api.post("books/", formData, {
    headers: { "Content-Type": "multipart/form-data" },
  });
};

// Get categories
export const getCategories = () => api.get("books/categories/");

// Get all books with filters
export const getBooks = ({ page = 1, search = "", category = "", condition = "" }) => {
  let query = `books/?page=${page}`;
  if (search) query += `&search=${search}`;
  if (category) query += `&category=${category}`;
  if (condition) query += `&condition=${condition}`;
  return api.get(query);
};

// Get single book details
export const getBookDetail = (id) => api.get(`books/${id}/`);

// Get all my books only
export const getMyBooks = () => api.get("books/my-books/");

export const updateBook = (id, data) => api.put(`books/${id}/`, data);

export const deleteBook = (id) => api.delete(`books/${id}/`);

export const getTrashBooks = () => api.get("books/trash/");

export const restoreBook = (id) => api.post(`books/trash/${id}/restore/`);

export const permanentlyDeleteBook = (id) => api.delete(`books/trash/${id}/delete/`);