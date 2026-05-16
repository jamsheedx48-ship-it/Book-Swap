import { useState, useEffect } from "react";
import { proposeMeetup, confirmMeetup, getMeetup } from ".././api/exchange";

export default function MeetupModal({ exchange, currentUserId, onClose }) {
  const [meetup, setMeetup] = useState(null);
  const [loading, setLoading] = useState(true);
  const [actionLoading, setActionLoading] = useState(false);
  const [error, setError] = useState("");
  const [form, setForm] = useState({ location: "", meetup_date: "", notes: "" });

  useEffect(() => {
    fetchMeetup();
  }, []);

  const fetchMeetup = async () => {
    try {
      setLoading(true);
      const res = await getMeetup(exchange.id);
      setMeetup(res.data);
    } catch {
      setMeetup(null);
    } finally {
      setLoading(false);
    }
  };

  const handlePropose = async () => {
    try {
      setActionLoading(true);
      setError("");
      const res = await proposeMeetup(exchange.id, form);
      setMeetup(res.data);
    } catch (err) {
      setError(err.response?.data?.detail || "Failed to propose meetup.");
    } finally {
      setActionLoading(false);
    }
  };

  const handleConfirm = async () => {
    try {
      setActionLoading(true);
      setError("");
      const res = await confirmMeetup(exchange.id);
      setMeetup(res.data);
    } catch (err) {
      setError(err.response?.data?.detail || "Failed to confirm meetup.");
    } finally {
      setActionLoading(false);
    }
  };


  return (
    <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50 px-4">
      <div className="bg-white rounded-2xl shadow-xl w-full max-w-md p-7">
        <div className="flex items-center justify-between mb-6">
          <h2 className="text-2xl font-bold text-[#26187D]">Meetup Details</h2>
          <button onClick={onClose} className="text-gray-400 hover:text-gray-600 text-2xl">✕</button>
        </div>

        {error && (
          <div className="mb-4 bg-red-50 border border-red-200 text-red-600 px-4 py-3 rounded-xl text-sm">
            {error}
          </div>
        )}

        {loading ? (
          <div className="flex justify-center py-8">
            <div className="w-8 h
            -8 border-4 border-[#26187D] border-t-transparent rounded-full animate-spin"></div>
          </div>
        ) : meetup ? (
          <div className="space-y-4">
            <div className="bg-[#F6F7FF] rounded-xl p-4 space-y-3">
              <div>
                <p className="text-xs text-gray-400 mb-1">Location</p>
                <p className="font-semibold text-black">{meetup.location}</p>
              </div>
              <div>
                <p className="text-xs text-gray-400 mb-1">Date & Time</p>
                <p className="font-semibold text-black">
                  {new Date(meetup.meetup_date).toLocaleString()}
                </p>
              </div>
              {meetup.notes && (
                <div>
                  <p className="text-xs text-gray-400 mb-1">Notes</p>
                  <p className="text-gray-600 italic">"{meetup.notes}"</p>
                </div>
              )}
              <div>
                <p className="text-xs text-gray-400 mb-1">Proposed by</p>
                <p className="font-medium text-black">{meetup.proposed_by}</p>
              </div>
              <div className="flex items-center gap-2">
                <div className={`w-2 h-2 rounded-full ${meetup.confirmed ? "bg-green-500" : "bg-yellow-400"}`}></div>
                <p className="text-sm font-medium">
                  {meetup.confirmed ? "Confirmed" : "Awaiting confirmation"}
                </p>
              </div>
            </div>

            {meetup && !meetup.confirmed && meetup.proposed_by_id !== currentUserId && (
              <button
                onClick={handleConfirm}
                disabled={actionLoading}
                className="w-full py-3 bg-[#26187D] hover:bg-[#1c125e] text-white rounded-xl font-medium disabled:opacity-50"
              >
                {actionLoading ? "Confirming..." : "Confirm Meetup"}
              </button>
            )}
          </div>
        ) : (
          <div className="space-y-4">
            <p className="text-gray-500 text-sm mb-2">No meetup proposed yet. Set one up below.</p>
            <input
              type="text"
              placeholder="Location"
              value={form.location}
              onChange={(e) => setForm({ ...form, location: e.target.value })}
              className="w-full border border-gray-200 rounded-xl px-4 py-3 text-sm focus:outline-none focus:border-[#26187D]"
            />
            <input
              type="datetime-local"
              value={form.meetup_date}
              onChange={(e) => setForm({ ...form, meetup_date: e.target.value })}
              className="w-full border border-gray-200 rounded-xl px-4 py-3 text-sm focus:outline-none focus:border-[#26187D]"
            />
            <textarea
              placeholder="Notes (optional)"
              value={form.notes}
              onChange={(e) => setForm({ ...form, notes: e.target.value })}
              rows={3}
              className="w-full border border-gray-200 rounded-xl px-4 py-3 text-sm focus:outline-none focus:border-[#26187D] resize-none"
            />
            <button
              onClick={handlePropose}
              disabled={actionLoading || !form.location || !form.meetup_date}
              className="w-full py-3 bg-[#26187D] hover:bg-[#1c125e] text-white rounded-xl font-medium disabled:opacity-50"
            >
              {actionLoading ? "Proposing..." : "Propose Meetup"}
            </button>
          </div>
        )}
      </div>
    </div>
  );
}