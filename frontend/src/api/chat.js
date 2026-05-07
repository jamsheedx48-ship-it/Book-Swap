import axios from "axios";

const API = axios.create({
    baseURL: "http://localhost/api/chat",
    withCredentials: true,
});

export const getConversations = () => API.get("/conversations/");
export const startConversation = (userId) => API.post("conversations/start/", { user_id: userId });
export const getMessages = (conversationId) => API.get(`/conversations/${conversationId}/messages/`);