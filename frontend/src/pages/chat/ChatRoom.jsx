import React, { useEffect, useState, useRef, useCallback } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { getMessages } from "../../api/chat";
import { getMe } from "../../api/auth";
import useWebSocket from "../../hooks/useWebSocket";
import { ChevronLeft, Send, MoreVertical, User } from "lucide-react";

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
    
    useEffect(() => {
        getMessages(conversationId)
            .then((res) => setMessages(res.data))
            .catch((err) => setError(err.response?.data?.detail || "Failed to load messages."))
            .finally(() => setLoading(false));
    }, [conversationId]);

    useEffect(() => {
        bottomRef.current?.scrollIntoView({ behavior: "smooth" });
    }, [messages]);

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
        <div className="flex flex-col h-screen bg-[#F1F4F9] font-sans">
            {/* Modern Header */}
            <header className="fixed top-0 w-full z-50 bg-white/80 backdrop-blur-md border-b border-gray-100 px-6 py-4 flex items-center justify-between shadow-sm">
                <div className="flex items-center gap-4">
                    <button 
                        onClick={() => navigate("/chat")}
                        className="p-2 hover:bg-gray-100 rounded-xl transition-colors text-gray-500"
                    >
                        <ChevronLeft size={24} />
                    </button>
                    <div className="flex items-center gap-3">
                        <div className="w-10 h-10 bg-[#26187D] rounded-full flex items-center justify-center text-white font-bold">
                            <User size={20} />
                        </div>
                        <div>
                            <h2 className="text-sm font-bold text-gray-900 leading-none">
                                {messages.find(m => m.sender_id !== currentUserId)?.sender_name || "Chat"}
                            </h2>
                            <p className="text-[10px] font-bold text-green-500 uppercase tracking-tighter mt-1">
                                Online
                            </p>
                        </div>
                    </div>
                </div>
                <button className="p-2 text-gray-400 hover:text-gray-600">
                    <MoreVertical size={20} />
                </button>
            </header>

            {/* Messages Area */}
            <div className="flex-1 overflow-y-auto pt-24 pb-32 px-6 flex flex-col gap-4">
                {loading && (
                    <div className="flex justify-center py-10">
                        <div className="w-8 h-8 border-4 border-[#5B4CF0] border-t-transparent rounded-full animate-spin"></div>
                    </div>
                )}
                
                {error && (
                    <div className="text-center p-4 bg-rose-50 text-rose-600 rounded-2xl text-xs font-bold uppercase tracking-widest border border-rose-100 mx-auto">
                        {error}
                    </div>
                )}

                {messages.map((msg, index) => {
                    const isMine = msg.sender === currentUserId || msg.sender_id === currentUserId;
                    return (
                        <div
                            key={index}
                            className={`flex w-full ${isMine ? "justify-end" : "justify-start"}`}
                        >
                            <div className={`max-w-[75%] md:max-w-[60%] flex flex-col ${isMine ? "items-end" : "items-start"}`}>
                                <div
                                    className={`relative px-5 py-3 shadow-sm transition-all ${
                                        isMine 
                                            ? "bg-[#26187D] text-white rounded-[1.5rem] rounded-tr-none shadow-indigo-100" 
                                            : "bg-white text-gray-800 rounded-[1.5rem] rounded-tl-none border border-gray-100"
                                    }`}
                                >
                                    {!isMine && (
                                        <span className="block text-[10px] font-black uppercase text-[#5B4CF0] mb-1 tracking-wider">
                                            {msg.sender_name}
                                        </span>
                                    )}
                                    <p className="text-sm leading-relaxed font-medium">
                                        {msg.message}
                                    </p>
                                    <div className={`mt-1 flex items-center gap-1 ${isMine ? "justify-end" : "justify-start"}`}>
                                        <span className={`text-[9px] font-bold uppercase opacity-50 ${isMine ? "text-indigo-200" : "text-gray-400"}`}>
                                            {new Date(msg.timestamp).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}
                                        </span>
                                    </div>
                                </div>
                            </div>
                        </div>
                    );
                })}
                <div ref={bottomRef} />
            </div>

            {/* Input Floating Dock */}
            <div className="fixed bottom-6 left-0 w-full px-6 pointer-events-none">
                <div className="max-w-[800px] mx-auto bg-white p-3 rounded-[2rem] shadow-[0_10px_40px_rgba(0,0,0,0.1)] border border-gray-100 flex items-center gap-3 pointer-events-auto">
                    <input
                        value={input}
                        onChange={(e) => setInput(e.target.value)}
                        onKeyDown={handleKeyDown}
                        placeholder="Type your message..."
                        className="flex-1 px-6 py-3 bg-gray-50 rounded-2xl outline-none text-sm font-medium text-gray-700 placeholder-gray-400 focus:ring-2 focus:ring-[#5B4CF0]/10 transition-all"
                    />
                    <button
                        onClick={handleSend}
                        disabled={!input.trim()}
                        className="bg-[#26187D] text-white w-12 h-12 rounded-2xl flex items-center justify-center hover:bg-black transition-all shadow-lg shadow-indigo-100 active:scale-90 disabled:opacity-30 disabled:hover:bg-[#26187D] disabled:active:scale-100"
                    >
                        <Send size={18} />
                    </button>
                </div>
            </div>
        </div>
    );
};

export default ChatRoom;