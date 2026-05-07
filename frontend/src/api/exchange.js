import axios from "axios";

const API = axios.create({
  baseURL: "http://localhost/api/exchanges",
  withCredentials: true,
});

export const createExchangeRequest = (data) => {
  return API.post("/request/", data);
};

export const getMyExchanges = () => {
  return API.get("");
};

export const exchangeAction = (id, action) => {
  return API.post(`/${id}/${action}/`);
};

// check book has penidng req
export const checkPendingExchange = (bookId) => {
  return API.get(`/check-pending/${bookId}/`)
}