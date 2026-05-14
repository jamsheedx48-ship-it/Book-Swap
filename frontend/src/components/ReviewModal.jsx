import React, { useState } from "react";
import { Star, X } from "lucide-react";
import { toast } from "react-toastify";
import { submitRating } from "../api/profile"; 

const ReviewModal = ({ isOpen, onClose, userId, onReviewSubmitted }) => {
  const [score, setScore] = useState(0);
  const [hover, setHover] = useState(0);
  const [comment, setComment] = useState("");
  const [submitting, setSubmitting] = useState(false);

  if (!isOpen) return null;

  const handleSubmit = async () => {
    if (score === 0) {
      toast.error("Please select a star rating");
      return;
    }

    try {
      setSubmitting(true);
      await submitRating(userId, { score, comment });
      toast.success("Review submitted successfully!");
      onReviewSubmitted(); // Refresh parent list
      onClose(); // Close modal
      setScore(0);
      setComment("");
    } catch (error) {
      toast.error(error.response?.data?.error || "Failed to submit review");
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="fixed inset-0 z-[100] flex items-center justify-center p-4 bg-black/40 backdrop-blur-sm">
      <div className="bg-white w-full max-w-md rounded-[2.5rem] p-8 shadow-2xl animate-in fade-in zoom-in duration-200">
        <div className="flex justify-between items-center mb-6">
          <h2 className="text-2xl font-bold text-slate-900">Rate Experience</h2>
          <button onClick={onClose} className="p-2 hover:bg-gray-100 rounded-full transition">
            <X size={20} className="text-gray-400" />
          </button>
        </div>

        <p className="text-gray-500 text-sm font-medium mb-6">
          How was your interaction with this user regarding the book swap?
        </p>

        {/* Star Selection */}
        <div className="flex justify-center gap-2 mb-8">
          {[1, 2, 3, 4, 5].map((star) => (
            <button
              key={star}
              type="button"
              onClick={() => setScore(star)}
              onMouseEnter={() => setHover(star)}
              onMouseLeave={() => setHover(0)}
              className="transition-transform active:scale-90"
            >
              <Star
                size={36}
                className={`${
                  star <= (hover || score)
                    ? "text-amber-400 fill-amber-400"
                    : "text-gray-200"
                } transition-colors duration-150`}
              />
            </button>
          ))}
        </div>

        {/* Comment Input */}
        <textarea
          placeholder="Share your thoughts about the exchange..."
          className="w-full h-32 p-4 bg-gray-50 border border-gray-100 rounded-2xl text-sm font-medium focus:outline-none focus:ring-2 focus:ring-[#5B4CF0]/20 focus:bg-white transition-all resize-none mb-6"
          value={comment}
          onChange={(e) => setComment(e.target.value)}
        />

        <button
          onClick={handleSubmit}
          disabled={submitting}
          className="w-full bg-[#26187D] text-white py-4 rounded-2xl font-bold text-sm shadow-lg shadow-indigo-100 hover:bg-black transition-all active:scale-95 disabled:opacity-50"
        >
          {submitting ? "Submitting..." : "Post Review"}
        </button>
      </div>
    </div>
  );
};

export default ReviewModal;