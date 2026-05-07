import axios from "axios";

const API = axios.create({
  baseURL: "http://localhost/api/books",
  withCredentials: true,
});

// Create book
export const createBook = (formData) => {
  return API.post("/", formData, {
    headers: {
      "Content-Type": "multipart/form-data",
    },
  });
};

// Get categories
export const getCategories = () => {
  return API.get("/categories/");
};

// Get all books with filters
export const getBooks = ({
  page = 1,
  search = "",
  category = "",
  condition = "",
}) => {
  let query = `/?page=${page}`;

  if (search) {
    query += `&search=${search}`;
  }

  if (category) {
    query += `&category=${category}`;
  }

  if (condition) {
    query += `&condition=${condition}`;
  }

  return API.get(query);
};

// Get single book details
export const getBookDetail = (id) => {
  return API.get(`/${id}/`);
};

//get all my books only
export const getMyBooks=()=>{
  return API.get("/my-books/")
}