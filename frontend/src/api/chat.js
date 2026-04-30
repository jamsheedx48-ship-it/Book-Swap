import axios from "axios";

const API = axios.create({
    baseURL: "http://localhost/api",
    withCredentials: true,
});

export const getConversations = () => API.get("/chat/conversations/");
export const startConversation = (userId) => API.post("/chat/conversations/start/", { user_id: userId });
export const getMessages = (conversationId) => API.get(`/chat/conversations/${conversationId}/messages/`);