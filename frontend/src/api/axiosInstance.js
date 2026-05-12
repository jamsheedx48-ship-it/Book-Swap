import axios from "axios";
import { Navigate } from "react-router-dom";
const api = axios.create({
  baseURL: "http://localhost/api/",
  withCredentials: true,
});

api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;

    if (error.response?.status === 401 && !originalRequest._retry) {
      if (originalRequest.url.includes("logout")) {
        return Promise.reject(error);
      }

      originalRequest._retry = true;

      try {
        await axios.post(
          "http://localhost/api/users/token/refresh/",
          {},
          { withCredentials: true }
        );
        return api(originalRequest);
      } catch (refreshError) {
        return Promise.reject(refreshError);
      }
    }

    return Promise.reject(error);
  }
);

export default api;