import React, { useState, useEffect, useRef } from "react";
import { toast } from "react-toastify";
import {
  User,
  Shield,
  Camera,
  Save,
  Lock,
  Smartphone,
  ArrowLeft,
  Check,
} from "lucide-react";
import {
  getMyProfile,
  updateProfile,
  getGenres,
  changePassword,
} from "../../api/profile";
import { useNavigate } from "react-router-dom";

const SettingsPage = () => {
  const [activeTab, setActiveTab] = useState("profile");
  const [profile, setProfile] = useState(null);
  const [availableGenres, setAvailableGenres] = useState([]);
  const [formData, setFormData] = useState({
    bio: "",
    location: "",
    interests: [],
  });
  const [loading, setLoading] = useState(false);
  const fileInputRef = useRef(null);
  const navigate = useNavigate();

  // Password Form State
  const [passwords, setPasswords] = useState({
    old_password: "",
    new_password: "",
    confirm_password: "",
  });

  const cartoonAvatars = [
    "https://api.dicebear.com/7.x/avataaars/svg?seed=Felix",
    "https://api.dicebear.com/7.x/avataaars/svg?seed=Aria",
    "https://api.dicebear.com/7.x/avataaars/svg?seed=Jack",
    "https://api.dicebear.com/7.x/avataaars/svg?seed=Milo",
    "https://api.dicebear.com/7.x/avataaars/svg?seed=Luna",
  ];

  useEffect(() => {
    const loadData = async () => {
      try {
        const [profileRes, genresRes] = await Promise.all([
          getMyProfile(),
          getGenres(),
        ]);
        setProfile(profileRes.data);
        setAvailableGenres(genresRes.data);
        setFormData({
          bio: profileRes.data.bio || "",
          location: profileRes.data.location || "",
          interests: profileRes.data.interests.map((g) => g.id),
        });
      } catch (err) {
        toast.error("Failed to load settings data");
      }
    };
    loadData();
  }, []);

  const handleSaveProfile = async () => {
    setLoading(true);
    try {
      const data = new FormData();
      data.append("bio", formData.bio);
      data.append("location", formData.location);
      formData.interests.forEach((id) => data.append("interests", id));

      const response = await updateProfile(data);
      toast.success("Profile updated successfully!");
      setProfile((prev) => ({ ...prev, ...response.data }));
    } catch (err) {
      if (err.response?.data) {
        const errors = err.response.data;
        Object.keys(errors).forEach((key) =>
          toast.error(`${key}: ${errors[key]}`),
        );
      } else {
        toast.error("Update failed.");
      }
    } finally {
      setLoading(false);
    }
  };

  const handlePasswordUpdate = async () => {
    if (passwords.new_password !== passwords.confirm_password) {
      return toast.error("New passwords do not match.");
    }
    setLoading(true);
    try {
      const res = await changePassword(passwords);
      toast.success(res.data.message || "Password changed successfully!");
      setPasswords({
        old_password: "",
        new_password: "",
        confirm_password: "",
      });
    } catch (err) {
      const errorData = err.response?.data;
      if (errorData?.error) {
        toast.error(errorData.error);
      } else if (typeof errorData === "object") {
        Object.keys(errorData).forEach((key) =>
          toast.error(`${key}: ${errorData[key]}`),
        );
      } else {
        toast.error("Failed to update password.");
      }
    } finally {
      setLoading(false);
    }
  };

  const handleFileUpload = async (e) => {
  const file = e.target.files[0];
  if (file) {
    const data = new FormData();
    data.append("avatar", file);
    data.append("avatar_url", "");  // clear cartoon url
    try {
      setLoading(true);
      const response = await updateProfile(data);
      setProfile({ ...profile, avatar_display: response.data.avatar_display });
      toast.success("Image uploaded!");
    } catch (err) {
      toast.error("Upload failed");
    } finally {
      setLoading(false);
    }
  }
};

  // Helper to save cartoon selection

  // In SettingsPage.jsx
  const saveCartoonAvatar = async (url) => {
    try {
      setLoading(true);
      // 1. Update local UI immediately
      setProfile({ ...profile, avatar_display: url });

      // 2. Send the 'avatar_url' key to match the updated serializer
      await updateProfile({ avatar_url: url });

      toast.success("Avatar selection saved!");
    } catch (err) {
      toast.error("Failed to save avatar choice");
      console.error("Backend Error:", err.response?.data);
    } finally {
      setLoading(false);
    }
  };

  if (!profile) return null;

  return (
    <div className="min-h-screen bg-[#F8F9FD] pt-28 pb-12 px-4 md:px-10 font-sans">
      <div className="max-w-4xl mx-auto mb-6 flex items-center justify-between">
        <div className="flex items-center gap-4">
          <button
            onClick={() => navigate(-1)}
            className="p-2 bg-white rounded-xl shadow-sm border border-slate-100 hover:bg-slate-50 transition-all"
          >
            <ArrowLeft size={20} className="text-slate-600" />
          </button>
          <h1 className="text-2xl font-bold text-slate-900 tracking-tight">
            Settings
          </h1>
        </div>
      </div>

      <div className="max-w-4xl mx-auto bg-white rounded-[3rem] shadow-sm border border-slate-100 overflow-hidden">
        <div className="flex border-b border-slate-100">
          <button
            onClick={() => setActiveTab("profile")}
            className={`flex-1 flex items-center justify-center gap-3 py-6 text-sm font-bold transition-all border-b-2 ${
              activeTab === "profile"
                ? "border-[#4F46E5] text-[#4F46E5] bg-indigo-50/30"
                : "border-transparent text-slate-400 hover:text-slate-600"
            }`}
          >
            <User size={18} /> Edit Profile
          </button>
          <button
            onClick={() => setActiveTab("security")}
            className={`flex-1 flex items-center justify-center gap-3 py-6 text-sm font-bold transition-all border-b-2 ${
              activeTab === "security"
                ? "border-[#4F46E5] text-[#4F46E5] bg-indigo-50/30"
                : "border-transparent text-slate-400 hover:text-slate-600"
            }`}
          >
            <Shield size={18} /> Security
          </button>
        </div>

        <div className="p-8 md:p-12">
          {activeTab === "profile" ? (
            <div className="space-y-10">
              <section className="flex flex-col md:flex-row items-center gap-8 bg-slate-50/50 p-6 rounded-[2rem] border border-slate-100">
                <div className="relative">
                  <div className="w-24 h-24 rounded-full border-4 border-white shadow-md overflow-hidden bg-white">
                    <img
                      src={profile.avatar_display || cartoonAvatars[0]}
                      alt="Avatar"
                      className="w-full h-full object-cover"
                      onError={(e) => {
                        e.target.src = cartoonAvatars[0];
                      }} // Fallback if link breaks
                    />
                  </div>
                  <button
                    onClick={() => fileInputRef.current.click()}
                    className="absolute -bottom-1 -right-1 bg-[#26187D] text-white p-2 rounded-full border-2 border-white shadow-lg hover:scale-110 transition-all"
                  >
                    <Camera size={14} />
                  </button>
                  <input
                    type="file"
                    ref={fileInputRef}
                    onChange={handleFileUpload}
                    className="hidden"
                    accept="image/*"
                  />
                </div>

                <div className="flex-1">
                  <p className="text-[10px] font-bold text-slate-400 uppercase tracking-widest mb-3 text-center md:text-left">
                    Quick Avatar Select
                  </p>
                  <div className="flex flex-wrap justify-center md:justify-start gap-3">
                    {cartoonAvatars.map((url) => (
                      <button
                        key={url}
                        onClick={() => saveCartoonAvatar(url)}
                        className={`w-10 h-10 rounded-full border-2 transition-all overflow-hidden bg-white p-0.5 shadow-sm ${
                          profile.avatar_display === url
                            ? "border-[#4F46E5]"
                            : "border-transparent hover:border-[#4F46E5]"
                        }`}
                      >
                        <img
                          src={url}
                          alt="Cartoon"
                          className="w-full h-full"
                        />
                      </button>
                    ))}
                  </div>
                </div>
              </section>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div className="space-y-1">
                  <label className="text-[10px] font-bold text-slate-400 uppercase tracking-widest ml-2">
                    Full Name (Locked)
                  </label>
                  <div className="w-full bg-slate-50 border border-slate-100 rounded-2xl px-5 py-3.5 text-sm font-bold text-slate-400 flex items-center gap-2">
                    <Lock size={14} /> {profile.name}
                  </div>
                </div>
                <Input
                  label="Location"
                  value={formData.location}
                  onChange={(val) =>
                    setFormData({ ...formData, location: val })
                  }
                />
              </div>

              <div className="space-y-3">
                <label className="text-[10px] font-bold text-slate-400 uppercase tracking-widest ml-2">
                  Interests
                </label>
                <div className="flex flex-wrap gap-2">
                  {availableGenres.map((genre) => (
                    <button
                      key={genre.id}
                      onClick={() => {
                        const exists = formData.interests.includes(genre.id);
                        setFormData({
                          ...formData,
                          interests: exists
                            ? formData.interests.filter((id) => id !== genre.id)
                            : [...formData.interests, genre.id],
                        });
                      }}
                      className={`px-4 py-2 rounded-xl text-xs font-bold border transition-all ${
                        formData.interests.includes(genre.id)
                          ? "bg-[#26187D] text-white border-[#26187D]"
                          : "bg-white text-slate-500 border-slate-200 hover:border-indigo-200"
                      }`}
                    >
                      {genre.label}
                    </button>
                  ))}
                </div>
              </div>

              <div className="space-y-1">
                <label className="text-[10px] font-bold text-slate-400 uppercase tracking-widest ml-2">
                  Bio
                </label>
                <textarea
                  value={formData.bio}
                  onChange={(e) =>
                    setFormData({ ...formData, bio: e.target.value })
                  }
                  className="w-full bg-slate-50 border border-slate-100 rounded-[2rem] px-6 py-4 text-sm font-medium focus:ring-4 focus:ring-indigo-50 outline-none h-32 resize-none transition-all"
                />
              </div>

              <button
                onClick={handleSaveProfile}
                disabled={loading}
                className="bg-[#26187D] hover:bg-black text-white px-10 py-4 rounded-2xl font-bold transition-all shadow-xl shadow-indigo-100 w-full md:w-auto"
              >
                {loading ? "Saving..." : "Save Profile Changes"}
              </button>
            </div>
          ) : (
            <div className="space-y-12">
              <section className="space-y-6">
                <h3 className="text-xl font-bold text-slate-800">
                  Change Password
                </h3>
                <div className="grid grid-cols-1 gap-4">
                  <Input
                    label="Current Password"
                    type="password"
                    value={passwords.old_password}
                    onChange={(val) =>
                      setPasswords({ ...passwords, old_password: val })
                    }
                  />
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <Input
                      label="New Password"
                      type="password"
                      value={passwords.new_password}
                      onChange={(val) =>
                        setPasswords({ ...passwords, new_password: val })
                      }
                    />
                    <Input
                      label="Confirm New Password"
                      type="password"
                      value={passwords.confirm_password}
                      onChange={(val) =>
                        setPasswords({ ...passwords, confirm_password: val })
                      }
                    />
                  </div>
                </div>
                <button
                  onClick={handlePasswordUpdate}
                  disabled={loading}
                  className="bg-slate-900 text-white px-8 py-3.5 rounded-xl font-bold text-sm hover:bg-black transition-all"
                >
                  {loading ? "Updating..." : "Update Password"}
                </button>
              </section>

              <div className="h-px bg-slate-100 w-full" />

              <section className="bg-indigo-50/50 border border-indigo-100 rounded-[2rem] p-8 flex flex-col md:flex-row items-center justify-between gap-6">
                <div className="flex items-center gap-5 text-center md:text-left">
                  <div className="w-16 h-16 bg-white rounded-2xl flex items-center justify-center text-indigo-600 shadow-sm border border-indigo-50">
                    <Smartphone size={28} />
                  </div>
                  <div>
                    <p className="font-bold text-slate-800">
                      Two-Factor Authentication
                    </p>
                    <p className="text-xs text-slate-500 mt-0.5">
                      Use an authenticator app to protect your library.
                    </p>
                  </div>
                </div>
                <button
                  onClick={() => navigate("/settings/security/mfa")}
                  className="bg-white text-indigo-600 border border-indigo-100 px-6 py-3 rounded-xl font-bold text-sm hover:bg-indigo-100 transition-all"
                >
                  Configure MFA
                </button>
              </section>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

const Input = ({ label, type = "text", value, onChange }) => (
  <div className="space-y-1">
    <label className="text-[10px] font-bold text-slate-400 uppercase tracking-widest ml-2">
      {label}
    </label>
    <input
      type={type}
      value={value}
      onChange={(e) => onChange && onChange(e.target.value)}
      className="w-full bg-slate-50 border border-slate-100 rounded-2xl px-5 py-3.5 text-sm font-medium focus:ring-4 focus:ring-indigo-50 outline-none transition-all shadow-sm"
    />
  </div>
);

export default SettingsPage;
