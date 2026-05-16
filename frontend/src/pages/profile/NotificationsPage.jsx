import { useNotifications } from '../../context/NotificationContext';
import { Bell, ArrowLeft, Check, CheckCircle2 } from 'lucide-react';

export default function NotificationsPage() {
    const { notifications, unreadCount, markAllRead } = useNotifications();

    const handleBack = () => {
        if (typeof window !== 'undefined') {
            window.history.length > 1 ? window.history.back() : window.location.href = '/';
        }
    };

    return (
        <div className="min-h-screen bg-[#F6F7FF] pt-28 pb-16 px-6 md:px-12">
            <div className="max-w-2xl mx-auto">
                
                {/* Header Section */}
                <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between mb-8 pb-6 border-b border-[#26187D]/10">
                    <div className="flex items-center gap-4">
                        {/* Project Themed Back Button */}
                        <button 
                            onClick={handleBack}
                            className="p-2.5 bg-white border border-[#26187D]/10 text-[#26187D] rounded-2xl hover:bg-[#26187D] hover:text-white transition-all shadow-sm group"
                            aria-label="Go back"
                        >
                            <ArrowLeft size={18} className="group-hover:-translate-x-0.5 transition-transform" />
                        </button>
                        
                        <div>
                            <div className="flex items-center gap-2.5">
                                <h1 className="text-2xl font-extrabold text-[#26187D] tracking-tight">Notifications</h1>
                                {unreadCount > 0 && (
                                    <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-bold bg-[#26187D]/10 text-[#26187D]">
                                        {unreadCount} new
                                    </span>
                                )}
                            </div>
                            {unreadCount > 0 && (
                                <p className="text-xs text-gray-400 mt-0.5">{unreadCount} unread messages remaining</p>
                            )}
                        </div>
                    </div>

                    {/* Styled Action Button */}
                    {unreadCount > 0 && (
                        <button
                            onClick={markAllRead}
                            className="flex items-center justify-center gap-1.5 px-4 py-2 text-sm font-semibold text-[#26187D] bg-[#26187D]/5 hover:bg-[#26187D]/10 rounded-xl transition-all"
                        >
                            <Check size={16} />
                            Mark all as read
                        </button>
                    )}
                </div>

                {/* Notifications List */}
                <div className="space-y-3.5">
                    {notifications.length === 0 ? (
                        /* Empty State matching your design tokens */
                        <div className="flex flex-col items-center justify-center text-center py-20 bg-white rounded-2xl border border-[#26187D]/10 shadow-sm p-6">
                            <div className="w-16 h-16 bg-[#F6F7FF] text-[#26187D] rounded-2xl flex items-center justify-center mb-4 border border-[#26187D]/5">
                                <Bell size={28} className="opacity-70" />
                            </div>
                            <h3 className="font-bold text-[#26187D] text-lg">All caught up!</h3>
                            <p className="text-sm text-gray-400 max-w-xs mt-1">
                                No new alerts at the moment. We'll let you know when something pops up.
                            </p>
                        </div>
                    ) : (
                        /* Notification Rows */
                        notifications.map((n, i) => (
                            <div
                                key={n.notification_id || i}
                                className={`group p-4 rounded-2xl border transition-all duration-200 ${
                                    !n.is_read
                                        ? 'bg-white border-[#26187D]/20 shadow-sm hover:shadow-md'
                                        : 'bg-white/60 border-gray-100 hover:bg-white'
                                }`}
                            >
                                <div className="flex items-start gap-4">
                                    {/* Icon Box with Theme colors */}
                                    <div className="relative flex-shrink-0 mt-0.5">
                                        <div className={`w-10 h-10 rounded-xl flex items-center justify-center transition-colors ${
                                            !n.is_read ? 'bg-[#26187D] text-white' : 'bg-[#26187D]/5 text-[#26187D]/60'
                                        }`}>
                                            <Bell size={18} />
                                        </div>
                                        
                                        {/* Dynamic Active Glow */}
                                        {!n.is_read && (
                                            <span className="absolute -top-1 -right-1 flex h-3 w-3">
                                                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-[#26187D] opacity-75"></span>
                                                <span className="relative inline-flex rounded-full h-3 w-3 bg-[#26187D]"></span>
                                            </span>
                                        )}
                                    </div>

                                    {/* Body Text */}
                                    <div className="flex-1 min-w-0">
                                        <p className={`text-sm leading-relaxed ${!n.is_read ? 'font-bold text-gray-900' : 'text-gray-600'}`}>
                                            {n.message}
                                        </p>
                                        
                                        <div className="text-xs text-gray-400 mt-1.5 flex items-center gap-1.5">
                                            <span>
                                                {n.created_at ? new Date(n.created_at).toLocaleString(undefined, {
                                                    month: 'short',
                                                    day: 'numeric',
                                                    hour: '2-digit',
                                                    minute: '2-digit'
                                                }) : 'Just now'}
                                            </span>
                                            
                                            {n.is_read && (
                                                <>
                                                    <span className="w-1 h-1 rounded-full bg-gray-300" />
                                                    <span className="flex items-center gap-0.5 text-gray-400 font-medium">
                                                        <CheckCircle2 size={12} className="text-[#26187D]/40" /> Read
                                                    </span>
                                                </>
                                            )}
                                        </div>
                                    </div>
                                </div>
                            </div>
                        ))
                    )}
                </div>
            </div>
        </div>
    );
}