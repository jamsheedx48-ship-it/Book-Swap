import api from "./axiosInstance";

export const createExchangeRequest = (data) => api.post("exchanges/request/", data);

export const getMyExchanges = () => api.get("exchanges/");

export const exchangeAction = (id, action) => api.post(`exchanges/${id}/${action}/`);

export const checkPendingExchange = (bookId) => api.get(`exchanges/check-pending/${bookId}/`);