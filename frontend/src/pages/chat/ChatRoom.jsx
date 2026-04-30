import React from "react";
import { useEffect, useState, useRef, useCallback } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { getMessages } from "../../api/chat";
import { getMe } from "../../api/auth";
import useWebSocket from "../../hooks/useWebSocket";

const ChatRoom = () => {
    const { conversationId } = useParams();
    const [messages, setMessages] = useState([]);
    const [input, setInput] = useState("");
    const [error, setError] = useState(null);
    const [loading, setLoading] = useState(true);
    const [currentUserId, setCurrentUserId] = useState(null);
    const bottomRef = useRef(null);
    const navigate = useNavigate();
    
    useEffect(() => {
        getMe().then((res) => setCurrentUserId(res.data.id));
    }, []);
    
    // load old messages
    useEffect(() => {
        getMessages(conversationId)
            .then((res) => setMessages(res.data))
            .catch((err) => setError(err.response?.data?.detail || "Failed to load messages."))
            .finally(() => setLoading(false));
    }, [conversationId]);

    // scroll to bottom on new message
    useEffect(() => {
        bottomRef.current?.scrollIntoView({ behavior: "smooth" });
    }, [messages]);
    // new msgs added to list
    const onMessage = useCallback((data) => {
        setMessages((prev) => [...prev, data]);
    }, []);

    const { sendMessage } = useWebSocket(conversationId, onMessage);

    const handleSend = () => {
        if (!input.trim()) return; 
        sendMessage(input.trim());
        setInput("");
    };

    const handleKeyDown = (e) => {
        if (e.key === "Enter") handleSend();
    };
    return (
        <div style={{ backgroundColor: "#F6F7FF", minHeight: "100vh", display: "flex", flexDirection: "column" }}>
            {/* Header */}
            <div style={{ backgroundColor: "#26187D", padding: "16px 24px", display: "flex", alignItems: "center", gap: "12px" }}>
                <span onClick={() => navigate("/chat")} style={{ color: "#fff", cursor: "pointer", fontSize: "20px" }}>‹</span>
                <h2 style={{ color: "#fff", margin: 0, fontSize: "18px", fontWeight: "600" }}>Chat</h2>
            </div>

            {/* Messages */}
            <div style={{ flex: 1, overflowY: "auto", padding: "24px", display: "flex", flexDirection: "column", gap: "12px" }}>
                {loading && <p style={{ textAlign: "center", color: "#888" }}>Loading...</p>}
                {error && <p style={{ textAlign: "center", color: "red", fontSize: "14px" }}>{error}</p>}
                {messages.map((msg, index) => {
                     const isMine = msg.sender === currentUserId || msg.sender_id === currentUserId;
                    return (
                        <div
                            key={index}
                            style={{
                                display: "flex",
                                justifyContent: isMine ? "flex-end" : "flex-start",
                            }}
                        >
                            <div
                                style={{
                                    backgroundColor: isMine ? "#26187D" : "#fff",
                                    color: isMine ? "#fff" : "#1a1a2e",
                                    padding: "10px 16px",
                                    borderRadius: isMine ? "18px 18px 4px 18px" : "18px 18px 18px 4px",
                                    maxWidth: "70%",
                                    boxShadow: "0 1px 4px rgba(0,0,0,0.08)",
                                    fontSize: "14px",
                                }}
                            >
                                {!isMine && (
                                    <p style={{ margin: "0 0 4px", fontSize: "11px", fontWeight: "600", color: "#26187D" }}>
                                        {msg.sender_name}
                                    </p>
                                )}
                                <p style={{ margin: 0 }}>{msg.message}</p>
                                <p style={{ margin: "4px 0 0", fontSize: "10px", opacity: 0.6, textAlign: "right" }}>
                                    {new Date(msg.timestamp).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}
                                </p>
                            </div>
                        </div>
                    );
                })}
                <div ref={bottomRef} />
            </div>

            {/* Input */}
            <div style={{ padding: "16px 24px", backgroundColor: "#fff", borderTop: "1px solid #ebebf0", display: "flex", gap: "12px" }}>
                <input
                    value={input}
                    onChange={(e) => setInput(e.target.value)}
                    onKeyDown={handleKeyDown}
                    placeholder="Type a message..."
                    style={{
                        flex: 1,
                        padding: "12px 16px",
                        borderRadius: "24px",
                        border: "1px solid #ddd",
                        fontSize: "14px",
                        outline: "none",
                        backgroundColor: "#F6F7FF",
                    }}
                />
                <button
                    onClick={handleSend}
                    style={{
                        backgroundColor: "#26187D",
                        color: "#fff",
                        border: "none",
                        borderRadius: "50%",
                        width: "46px",
                        height: "46px",
                        cursor: "pointer",
                        fontSize: "20px",
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "center",
                    }}
                >
                    ›
                </button>
            </div>
        </div>
    );
};

export default ChatRoom;