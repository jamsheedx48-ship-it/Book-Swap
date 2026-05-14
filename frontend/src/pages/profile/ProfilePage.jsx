import React, { useState, useEffect } from "react";
import { toast } from "react-toastify";
import { getMyProfile, getRecentActivity } from "../../api/profile";
import { getMyBooks } from "../../api/books";
import {
  BookOpen,
  Heart,
  History,
  Leaf,
  Rocket,
  Plus,
  Settings,
  MapPin,
  Star,
  Share2,
  CheckCircle2,
  ShieldCheck,
  Search,
  Flame,
  Ghost,
  Landmark,
  Inbox,
  PlusCircle,
  MessageSquare,
  Send,
} from "lucide-react";
import { useNavigate } from "react-router-dom";

const GENRE_ICONS = {
  science_fiction: <Rocket size={18} />,
  literary_fiction: <Leaf size={18} />,
  history: <Landmark size={18} />,
  philosophy: <ShieldCheck size={18} />,
  mystery: <Search size={18} />,
  horror: <Ghost size={18} />,
  fantasy: <Flame size={18} />,
  default: <BookOpen size={18} />,
};

const BookSwapProfile = () => {
  const [profile, setProfile] = useState(null);
  const [activities, setActivities] = useState([]);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState("library");
  const [myBooks, setMyBooks] = useState([]);

  const navigate = useNavigate();

  useEffect(() => {
    const fetchUserData = async () => {
      try {
        const response = await getMyProfile();
        setProfile(response.data);
      } catch (err) {
        const errorMessage =
          err.response?.data?.error || "Failed to load profile details";
        toast.error(errorMessage);
      } finally {
        setLoading(false);
      }
    };
    fetchUserData();
  }, []);

  useEffect(() => {
    if (activeTab === "activity") {
      const fetchActivity = async () => {
        try {
          const response = await getRecentActivity();
          setActivities(response.data);
        } catch (err) {
          toast.error("Failed to load recent activity");
        }
      };
      fetchActivity();
    }
  }, [activeTab]);

  useEffect(() => {
    if (activeTab === "library") {
      const fetchBooks = async () => {
        try {
          const res = await getMyBooks();
          setMyBooks(res.data);
        } catch (err) {
          toast.error("Failed to load books");
        }
      };
      fetchBooks();
    }
  }, [activeTab]);

  if (loading) {
    return (
      <div className="flex justify-center items-center h-screen bg-[#F8F9FD]">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-[#4F46E5]"></div>
      </div>
    );
  }

  if (!profile) return null;

  return (
    <div className="min-h-screen bg-[#F8F9FD] py-10 px-4 md:px-10 font-sans text-slate-900">
      <div className="max-w-7xl mx-auto">

        {/* HEADER */}
        <header className="flex flex-col md:flex-row md:items-center justify-between mb-10 gap-6">
          <div className="flex items-center gap-6">
            <div className="relative">
              <div className="w-24 h-24 rounded-full bg-slate-200 border-4 border-white shadow-sm overflow-hidden flex items-center justify-center">
                {profile.avatar_display ? (
                  <img
                    src={profile.avatar_display}
                    alt="Profile"
                    className="w-full h-full object-cover"
                  />
                ) : (
                  <span className="text-2xl font-bold text-[#26187D]">
                    {profile.name?.substring(0, 2).toUpperCase()}
                  </span>
                )}
              </div>
              <div className="absolute bottom-1 right-1 bg-[#10B981] border-2 border-white p-1 rounded-full">
                <CheckCircle2 size={12} className="text-white" />
              </div>
            </div>

            <div>
              <div className="flex items-center gap-3">
                <h1 className="text-3xl font-bold text-slate-800 tracking-tight">
                  {profile.name}
                </h1>
                <span className="bg-[#ECFDF5] text-[#059669] text-[11px] font-bold px-2.5 py-1 rounded-full border border-[#D1FAE5] flex items-center gap-1">
                  Verified User
                </span>
              </div>
              <div className="flex flex-wrap gap-5 mt-2.5 text-sm text-slate-500 font-medium">
                <span className="flex items-center gap-1.5">
                  <Star size={16} className="text-amber-400 fill-amber-400" />
                  {profile.average_rating !== null
                    ? `${profile.average_rating}/5 stars`
                    : "No ratings"}
                </span>
                <span className="flex items-center gap-1.5">
                  <Share2 size={16} className="text-indigo-500" />
                  {profile.total_swaps_done} successful swaps
                </span>
                <span className="flex items-center gap-1.5">
                  <MapPin size={16} className="text-slate-400" />
                  {profile.location || "Location not set"}
                </span>
              </div>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <button
              className="flex items-center gap-2 bg-[#4F46E5] hover:bg-[#4338CA] text-white px-6 py-3 rounded-xl font-bold transition-all shadow-lg shadow-indigo-100"
              onClick={() => navigate("/list-book")}
            >
              <Plus size={20} /> List a New Book
            </button>
            <button
              className="p-3 border-2 border-dashed border-slate-200 rounded-xl text-slate-400 hover:text-[#4F46E5] hover:border-[#4F46E5] transition-all"
              onClick={() => navigate("/settings")}
            >
              <Settings size={22} />
            </button>
          </div>
        </header>

        {/* STATS */}
        <section className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-12">
          <StatBox
            label="BOOKS LISTED"
            value={profile.total_books_listed}
            icon={<BookOpen size={20} />}
            color="indigo"
          />
          <StatBox
            label="SWAPS DONE"
            value={profile.total_swaps_done}
            icon={<History size={20} />}
            color="emerald"
          />
          <StatBox
            label="AVG RATING"
            value={profile.average_rating ?? "N/A"}
            icon={<Star size={20} />}
            color="amber"
          />
        </section>

        <div className="grid grid-cols-12 gap-10">

          {/* SIDEBAR */}
          <aside className="col-span-12 lg:col-span-3 space-y-10">
            <div>
              <h3 className="text-[10px] font-bold text-slate-400 uppercase tracking-[0.15em] mb-4">
                Library View
              </h3>
              <nav className="flex flex-col gap-1">
                <SideNavLink
                  icon={<BookOpen size={18} />}
                  label="My Library"
                  active={activeTab === "library"}
                  onClick={() => setActiveTab("library")}
                />
                <SideNavLink
                  icon={<Heart size={18} />}
                  label="Wishlist"
                  active={activeTab === "wishlist"}
                  onClick={() => setActiveTab("wishlist")}
                />
                <SideNavLink
                  icon={<History size={18} />}
                  label="Activity"
                  active={activeTab === "activity"}
                  onClick={() => setActiveTab("activity")}
                />
              </nav>
            </div>

            <div>
              <h3 className="text-[10px] font-bold text-slate-400 uppercase tracking-[0.15em] mb-4">
                Favourite Genres
              </h3>
              <nav className="flex flex-col gap-1">
                {profile.interests?.length > 0 ? (
                  profile.interests.map((genre) => (
                    <SideNavLink
                      key={genre.id}
                      icon={GENRE_ICONS[genre.name] || GENRE_ICONS["default"]}
                      label={genre.label}
                    />
                  ))
                ) : (
                  <p className="text-xs text-slate-400 px-4">No genres selected</p>
                )}
              </nav>
            </div>
          </aside>

          {/* MAIN CONTENT */}
          <main className="col-span-12 lg:col-span-9">

            {/* LIBRARY TAB */}
            {activeTab === "library" && (
              <>
                <div className="flex items-center justify-between mb-8">
                  <h2 className="text-xl font-bold text-slate-800">
                    Currently Listed ({myBooks.length})
                  </h2>
                  <button
                    onClick={() => navigate("/my-listings")}
                    className="text-sm font-bold text-[#4F46E5] hover:underline flex items-center gap-1"
                  >
                    View All <span className="text-lg leading-none">→</span>
                  </button>
                </div>

                {myBooks.length === 0 ? (
                  <div className="bg-white rounded-[2rem] border border-dashed border-slate-200 p-16 flex flex-col items-center text-center shadow-sm">
                    <div className="w-20 h-20 bg-slate-50 rounded-full flex items-center justify-center mb-6 text-slate-300">
                      <Inbox size={40} />
                    </div>
                    <h3 className="text-xl font-bold text-slate-800 mb-2">
                      No books listed yet
                    </h3>
                    <p className="text-slate-500 max-w-xs mb-8">
                      Your library is empty. Start by adding books you want to swap with others.
                    </p>
                    <button
                      className="flex items-center gap-2 bg-[#4F46E5] text-white px-8 py-3 rounded-xl font-bold hover:bg-[#4338CA] transition-all"
                      onClick={() => navigate("/list-book")}
                    >
                      <PlusCircle size={20} /> List Your First Book
                    </button>
                  </div>
                ) : (
                  <>
                    <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-8">
                      {myBooks.slice(0, 3).map((book) => (
                        <BookCard
                          key={book.id}
                          id={book.id}
                          title={book.title}
                          author={book.author}
                          tag={book.status}
                          type={book.condition}
                          image={book.image_thumbnail}
                        />
                      ))}
                    </div>

                    {myBooks.length > 3 && (
                      <div className="mt-8 text-center">
                        <button
                          onClick={() => navigate("/my-listings")}
                          className="bg-white border border-slate-200 text-slate-700 px-8 py-3 rounded-xl font-bold hover:border-[#4F46E5] hover:text-[#4F46E5] transition-all"
                        >
                          View All {myBooks.length} Books →
                        </button>
                      </div>
                    )}
                  </>
                )}
              </>
            )}

            {/* ACTIVITY TAB */}
            {activeTab === "activity" && (
              <>
                <h2 className="text-xl font-bold text-slate-800 mb-8">
                  Recent Activity
                </h2>
                <div className="space-y-4">
                  {activities.length > 0 ? (
                    activities.map((act, index) => (
                      <div
                        key={index}
                        className="bg-white p-6 rounded-2xl border border-slate-100 flex items-center gap-5 shadow-sm"
                      >
                        <div className="w-12 h-12 bg-indigo-50 rounded-full flex items-center justify-center text-indigo-600">
                          {act.type === "book_listed" && <Plus size={20} />}
                          {act.type === "swap_sent" && <Send size={20} />}
                          {act.type === "swap_received" && <MessageSquare size={20} />}
                          {act.type === "rating_received" && <Star size={20} />}
                        </div>
                        <div>
                          <p className="text-slate-800 font-medium">{act.message}</p>
                          <p className="text-xs text-slate-400 mt-1">
                            {new Date(act.timestamp).toLocaleDateString()}
                          </p>
                        </div>
                      </div>
                    ))
                  ) : (
                    <p className="text-center text-slate-500 py-10">
                      No recent activity.
                    </p>
                  )}
                </div>
              </>
            )}

            {/* WISHLIST TAB */}
            {activeTab === "wishlist" && (
              <div className="bg-white rounded-[2rem] border border-dashed border-slate-200 p-16 flex flex-col items-center text-center shadow-sm">
                <div className="w-20 h-20 bg-slate-50 rounded-full flex items-center justify-center mb-6 text-slate-300">
                  <Heart size={40} />
                </div>
                <h3 className="text-xl font-bold text-slate-800 mb-2">
                  Wishlist coming soon
                </h3>
                <p className="text-slate-500">
                  Books you want to read will appear here.
                </p>
              </div>
            )}

          </main>
        </div>
      </div>
    </div>
  );
};

const StatBox = ({ label, value, icon, color }) => {
  const iconColors = {
    indigo: "bg-indigo-50 text-indigo-600",
    emerald: "bg-emerald-50 text-emerald-600",
    amber: "bg-amber-50 text-amber-600",
  };
  return (
    <div className="bg-white p-8 rounded-2xl border border-slate-100 shadow-sm flex items-center gap-6 group hover:shadow-md transition-all">
      <div className={`w-14 h-14 rounded-2xl flex items-center justify-center ${iconColors[color]}`}>
        {icon}
      </div>
      <div>
        <p className="text-3xl font-extrabold text-[#26187D] tracking-tight">{value}</p>
        <p className="text-[10px] font-bold text-slate-400 uppercase tracking-widest mt-0.5">{label}</p>
      </div>
    </div>
  );
};

const SideNavLink = ({ icon, label, active = false, onClick }) => (
  <button
    onClick={onClick}
    className={`w-full flex items-center gap-3 px-4 py-3 rounded-xl text-sm font-semibold transition-all ${
      active
        ? "bg-[#EEF2FF] text-[#4F46E5] shadow-sm"
        : "text-slate-500 hover:bg-slate-50 hover:text-slate-900"
    }`}
  >
    {icon} {label}
  </button>
);

const BookCard = ({ id, title, author, tag, type, image }) => {
  const navigate = useNavigate();

  return (
    <div className="group bg-white rounded-[2rem] border border-slate-100 shadow-sm overflow-hidden hover:shadow-xl transition-all duration-300">
      <div className="h-72 bg-[#0B0D17] relative overflow-hidden">
        <div className="absolute top-4 left-4 z-10">
          <span className="bg-white/95 backdrop-blur text-[9px] font-black px-2.5 py-1 rounded-md uppercase tracking-wider text-slate-800">
            {tag}
          </span>
        </div>

        {image ? (
          <img
            src={image}
            alt={title}
            className="w-full h-full object-cover group-hover:scale-105 transition-transform duration-300"
          />
        ) : (
          <div className="w-full h-full flex flex-col items-center justify-center text-center p-4 border border-white/10 rounded-lg">
            <div className="text-white font-serif italic text-lg leading-tight mb-2 opacity-90">
              {title}
            </div>
            <div className="h-[1px] w-8 bg-white/20 mb-2"></div>
            <div className="text-white/40 text-[10px] uppercase tracking-[0.2em]">
              {author}
            </div>
          </div>
        )}
      </div>

      <div className="p-6">
        <h4 className="font-bold text-slate-900 text-base mb-1 truncate">{title}</h4>
        <p className="text-sm text-slate-500 mb-4">{author}</p>
        <div className="flex items-center justify-between pt-4 border-t border-slate-50">
          <span className="text-xs font-bold text-indigo-600 bg-indigo-50 px-2 py-1 rounded">
            {type}
          </span>
          <button
            onClick={() => navigate(`/books/${id}`)}
            className="text-xs font-bold text-slate-800 flex items-center gap-1 group-hover:text-indigo-600 transition-colors"
          >
            View Details <span className="text-lg leading-none">→</span>
          </button>
        </div>
      </div>
    </div>
  );
};

export default BookSwapProfile;