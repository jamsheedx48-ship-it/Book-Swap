import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { getConversations } from "../../api/chat";
import { MessageSquare, ChevronRight, Search } from "lucide-react";
import Navbar from "../../components/Navbar";
import Footer from "../../components/Footer";

const ChatList = () => {
    const [conversations, setConversations] = useState([]);
    const [error, setError] = useState(null);
    const [loading, setLoading] = useState(true);
    const navigate = useNavigate();

    useEffect(() => {
        getConversations()
            .then((res) => setConversations(res.data))
            .catch((err) => setError(err.response?.data?.detail || "Failed to load conversations."))
            .finally(() => setLoading(false));
    }, []);

    return (
        <>
        {/* Expanded horizontal padding and standard gradient background */}
        <Navbar/>

        <div className="min-h-screen bg-gradient-to-br from-[#F1F4F9] via-[#F8FAFF] to-white pt-28 pb-12 px-6 md:px-16 font-sans">
            
            {/* Increased max-width to 1600px to fix the collapsed center look */}
            <div className="max-w-[1600px] mx-auto">
                
                {/* Header Section */}
                <div className="flex flex-col md:flex-row md:items-center justify-between mb-10 gap-4">
                    <h2 className="text-3xl font-bold text-slate-900 tracking-tight">
                        Messages
                    </h2>

                    <div className="relative group">
                        <Search className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-400 group-focus-within:text-[#5B4CF0] transition-colors" size={16} />
                        <input 
                            type="text" 
                            placeholder="Search chats..." 
                            className="pl-12 pr-4 py-2.5 bg-white border border-slate-100 rounded-2xl text-sm focus:ring-4 focus:ring-indigo-50 outline-none w-full md:w-80 shadow-sm transition-all"
                        />
                    </div>
                </div>

                {/* Loading State */}
                {loading && (
                    <div className="flex flex-col items-center justify-center py-20">
                        <div className="w-10 h-10 border-4 border-[#5B4CF0] border-t-transparent rounded-full animate-spin"></div>
                        <p className="mt-4 text-xs font-semibold text-slate-400 uppercase tracking-widest">Loading Chats...</p>
                    </div>
                )}

                {/* Error State */}
                {error && (
                    <div className="bg-rose-50 border border-rose-100 p-4 rounded-2xl text-center max-w-2xl mx-auto">
                        <p className="text-rose-600 text-sm font-semibold">{error}</p>
                    </div>
                )}

                {/* Empty State */}
                {!loading && !error && conversations.length === 0 && (
                    <div className="bg-white/60 backdrop-blur-sm border border-white p-20 rounded-[2.5rem] text-center shadow-sm max-w-2xl mx-auto">
                        <div className="bg-gray-50 w-16 h-16 rounded-3xl flex items-center justify-center mx-auto mb-6">
                            <MessageSquare className="text-gray-300" size={32} />
                        </div>
                        <h3 className="text-lg font-bold text-slate-900">No conversations yet</h3>
                        <p className="text-gray-500 text-sm mt-1">Start a swap request to begin chatting.</p>
                    </div>
                )}

                {/* Conversation List Grid - Adjusts to take more space */}
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                    {conversations.map((conv) => (
                        <div
                            key={conv.id}
                            onClick={() => navigate(`/chat/${conv.id}`)}
                            className="group flex items-center justify-between bg-white p-6 rounded-[2rem] cursor-pointer border border-transparent hover:border-indigo-100 hover:shadow-[0_15px_40px_rgba(38,24,125,0.06)] transition-all duration-300 shadow-sm"
                        >
                            <div className="flex items-center gap-5">
                                {/* Simple Initial Avatar */}
                                <div className="w-14 h-14 bg-gray-100 rounded-2xl flex items-center justify-center text-[#26187D] font-bold shadow-sm group-hover:bg-[#26187D] group-hover:text-white transition-all">
                                    {conv.other_user?.name?.charAt(0) || "?"}
                                </div>
                                
                                <div className="space-y-1">
                                    <h3 className="font-bold text-slate-900 group-hover:text-[#26187D] transition-colors leading-none">
                                        {conv.other_user?.name || "Unknown User"}
                                    </h3>
                                    <p className="text-slate-400 text-sm font-medium line-clamp-1">
                                        {conv.last_message?.message || "No messages yet"} 
                                    </p>
                                </div>
                            </div>

                            <div className="w-10 h-10 bg-slate-50 rounded-xl flex items-center justify-center text-slate-300 group-hover:bg-[#26187D] group-hover:text-white transition-all">
                                <ChevronRight size={20} />
                            </div>
                        </div>
                    ))}
                </div>
            </div>
        </div>

        <Footer/>
    </>
    );
};

export default ChatList;