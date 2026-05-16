import { useNavigate } from 'react-router-dom';
import { Bell } from 'lucide-react';
import { useNotifications } from '../context/NotificationContext';

export default function NotificationBell() {
    const { unreadCount } = useNotifications();
    const navigate = useNavigate();

    return (
        <button onClick={() => navigate('/notifications')} className="relative p-2">
            <Bell size={22} color="#26187D" />
            {unreadCount > 0 && (
                <span className="absolute -top-1 -right-1 bg-[#26187D] text-white text-xs rounded-full w-5 h-5 flex items-center justify-center">
                    {unreadCount > 9 ? '9+' : unreadCount}
                </span>
            )}
        </button>
    );
}