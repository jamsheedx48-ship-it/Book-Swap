import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { getMyExchanges, exchangeAction } from "../../api/exchange";
import { getMe } from "../../api/auth";
import { startConversation } from "../../api/chat";
import MeetupModal from "../../components/MeetupModal";

export default function MyExchanges() {
  const [user, setUser] = useState(null);
  const [exchanges, setExchanges] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [actionLoading, setActionLoading] = useState("");
  const [activeTab, setActiveTab] = useState("received");
  const [meetupExchange, setMeetupExchange] = useState(null);
  const navigate = useNavigate();

  useEffect(() => {
    fetchData();
  }, []);

  const fetchData = async () => {
    try {
      setLoading(true);
      setError("");
      const [userRes, exchangeRes] = await Promise.all([
        getMe(),
        getMyExchanges(),
      ]);
      setUser(userRes.data);
      setExchanges(exchangeRes.data);
    } catch (err) {
      console.error(err);
      setError("Failed to load exchanges.");
    } finally {
      setLoading(false);
    }
  };

  const handleAction = async (exchangeId, action) => {
    try {
      setActionLoading(`${exchangeId}-${action}`);
      setError("");
      await exchangeAction(exchangeId, action);
      await fetchData();
    } catch (err) {
      console.error(err);
      setError(`Failed to ${action} exchange.`);
    } finally {
      setActionLoading("");
    }
  };

  const handleMessage = async (exchange) => {
    try {
      const otherUserId =
        user?.id === exchange.receiver_id
          ? exchange.requester_id
          : exchange.receiver_id;
      const res = await startConversation(otherUserId);
      navigate(`/chat/${res.data.conversation_id}`);
    } catch (err) {
      console.error(err);
      setError("Could not start conversation.");
    }
  };

  const sentExchanges = exchanges.filter((e) => e.requester_id === user?.id);
  const receivedExchanges = exchanges.filter((e) => e.receiver_id === user?.id);
  const meetupExchanges = exchanges.filter((e) => e.meetup !== null);

  const currentList =
    activeTab === "received"
      ? receivedExchanges
      : activeTab === "sent"
      ? sentExchanges
      : meetupExchanges;

  const statusStyles = {
    pending: "bg-yellow-100 text-yellow-700",
    accepted: "bg-green-100 text-green-700",
    rejected: "bg-red-100 text-red-700",
    completed: "bg-blue-100 text-blue-700",
    cancelled: "bg-gray-100 text-gray-500",
  };

  const tabs = [
    { key: "received", label: "Received", count: receivedExchanges.length },
    { key: "sent", label: "Sent", count: sentExchanges.length },
    { key: "meetup", label: "Meetups", count: meetupExchanges.length },
  ];

  if (loading) {
    return (
      <div className="min-h-screen bg-[#F6F7FF] flex items-center justify-center">
        <div className="text-center">
          <div className="w-12 h-12 border-4 border-[#26187D] border-t-transparent rounded-full animate-spin mx-auto mb-4"></div>
          <p className="text-lg font-medium text-[#26187D]">
            Loading exchanges...
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-[#F6F7FF] px-6 md:px-10 py-10">
      <div className="max-w-6xl mx-auto">
        <h1 className="text-4xl font-bold text-[#26187D] mb-8">My Exchanges</h1>

        {error && (
          <div className="mb-6 bg-red-50 border border-red-200 text-red-600 px-5 py-4 rounded-2xl text-base">
            {error}
          </div>
        )}

        {/* Tabs */}
        <div className="bg-white rounded-2xl p-2 shadow-sm mb-8 flex w-fit">
          {tabs.map((tab) => (
            <button
              key={tab.key}
              onClick={() => setActiveTab(tab.key)}
              className={`px-6 py-3 rounded-xl text-base font-medium transition ${
                activeTab === tab.key
                  ? "bg-[#26187D] text-white"
                  : "text-gray-600 hover:bg-gray-100"
              }`}
            >
              {tab.label} ({tab.count})
            </button>
          ))}
        </div>

        {/* Empty State */}
        {currentList.length === 0 ? (
          <div className="bg-white rounded-2xl p-14 text-center shadow-sm">
            <div className="text-6xl mb-4">
              {activeTab === "meetup" ? "📅" : "📚"}
            </div>
            <h3 className="text-2xl font-semibold text-gray-700 mb-2">
              {activeTab === "meetup"
                ? "No meetups yet"
                : `No ${activeTab} exchanges`}
            </h3>
            <p className="text-gray-500 text-base">
              {activeTab === "meetup"
                ? "Meetups will appear here once proposed on an accepted exchange."
                : `Your ${activeTab} exchange requests will appear here.`}
            </p>
          </div>
        ) : (
          <div className="space-y-6">
            {currentList.map((exchange) => (
              <div
                key={exchange.id}
                className="bg-white rounded-2xl shadow-sm border border-gray-100 p-6 md:p-7"
              >
                {/* Book Section */}
                <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-5 mb-5">
                  <div className="flex items-center gap-6 flex-wrap">
                    <div>
                      <p className="text-sm text-gray-400 mb-1">
                        {activeTab === "received" ? "Offered Book" : "You Offered"}
                      </p>
                      <p className="font-semibold text-lg text-black">
                        {exchange.offered_book}
                      </p>
                    </div>
                    <span className="text-gray-400 text-2xl">⇄</span>
                    <div>
                      <p className="text-sm text-gray-400 mb-1">
                        {activeTab === "received" ? "Your Book" : "Requested Book"}
                      </p>
                      <p className="font-semibold text-lg text-[#26187D]">
                        {exchange.requested_book}
                      </p>
                    </div>
                  </div>
                  <div className="flex items-center gap-3 flex-wrap">
                    <span
                      className={`px-4 py-2 rounded-full text-sm font-semibold capitalize ${
                        statusStyles[exchange.status]
                      }`}
                    >
                      {exchange.status}
                    </span>
                    {exchange.meetup && (
                      <span
                        className={`px-4 py-2 rounded-full text-sm font-semibold ${
                          exchange.meetup.confirmed
                            ? "bg-purple-100 text-purple-700"
                            : "bg-orange-100 text-orange-600"
                        }`}
                      >
                        {exchange.meetup.confirmed ? "Meetup Confirmed" : "Meetup Pending"}
                      </span>
                    )}
                  </div>
                </div>

                {/* User Info */}
                <p className="text-base text-gray-500 mb-4">
                  {activeTab === "received"
                    ? `From: ${exchange.requester}`
                    : `To: ${exchange.receiver}`}
                </p>

                {/* Meetup summary (meetup tab only) */}
                {activeTab === "meetup" && exchange.meetup && (
                  <div className="bg-[#F6F7FF] rounded-xl p-4 mb-5 flex flex-wrap gap-6">
                    <div>
                      <p className="text-xs text-gray-400 mb-1">Location</p>
                      <p className="font-medium text-black">{exchange.meetup.location}</p>
                    </div>
                    <div>
                      <p className="text-xs text-gray-400 mb-1">Date & Time</p>
                      <p className="font-medium text-black">
                        {new Date(exchange.meetup.meetup_date).toLocaleString()}
                      </p>
                    </div>
                    {exchange.meetup.notes && (
                      <div>
                        <p className="text-xs text-gray-400 mb-1">Notes</p>
                        <p className="text-gray-600 italic">"{exchange.meetup.notes}"</p>
                      </div>
                    )}
                  </div>
                )}

                {/* Exchange message (not in meetup tab) */}
                {exchange.message && activeTab !== "meetup" && (
                  <div className="bg-gray-50 rounded-xl p-4 mb-5">
                    <p className="text-base text-gray-600 italic">
                      "{exchange.message}"
                    </p>
                  </div>
                )}

                {/* Action Buttons */}
                <div className="flex flex-wrap gap-4">

                  {/* Received tab — pending actions */}
                  {activeTab === "received" && exchange.status === "pending" && (
                    <>
                      <button
                        onClick={() => handleAction(exchange.id, "accept")}
                        disabled={actionLoading === `${exchange.id}-accept`}
                        className="px-5 py-3 bg-green-500 hover:bg-green-600 text-white rounded-xl text-base font-medium disabled:opacity-50"
                      >
                        {actionLoading === `${exchange.id}-accept` ? "Accepting..." : "Accept"}
                      </button>
                      <button
                        onClick={() => handleAction(exchange.id, "reject")}
                        disabled={actionLoading === `${exchange.id}-reject`}
                        className="px-5 py-3 bg-red-500 hover:bg-red-600 text-white rounded-xl text-base font-medium disabled:opacity-50"
                      >
                        {actionLoading === `${exchange.id}-reject` ? "Rejecting..." : "Reject"}
                      </button>
                    </>
                  )}

                  {/* Sent tab — cancel */}
                  {activeTab === "sent" && exchange.status === "pending" && (
                    <button
                      onClick={() => handleAction(exchange.id, "cancel")}
                      disabled={actionLoading === `${exchange.id}-cancel`}
                      className="px-5 py-3 bg-red-500 hover:bg-red-600 text-white rounded-xl text-base font-medium disabled:opacity-50"
                    >
                      {actionLoading === `${exchange.id}-cancel` ? "Cancelling..." : "Cancel Request"}
                    </button>
                  )}

                  {/* Received/Sent tabs — accepted actions */}
                  {exchange.status === "accepted" && activeTab !== "meetup" && (
                    <>
                      <button
                        onClick={() => handleAction(exchange.id, "complete")}
                        disabled={actionLoading === `${exchange.id}-complete`}
                        className="px-5 py-3 bg-[#26187D] hover:bg-[#1c125e] text-white rounded-xl text-base font-medium disabled:opacity-50"
                      >
                        {actionLoading === `${exchange.id}-complete` ? "Completing..." : "Mark as Completed"}
                      </button>
                      <button
                        onClick={() => setMeetupExchange(exchange)}
                        className="px-5 py-3 bg-white border border-[#26187D] text-[#26187D] hover:bg-[#26187D] hover:text-white rounded-xl text-base font-medium transition"
                      >
                        {exchange.meetup ? "View Meetup" : "Meetup"}
                      </button>
                    </>
                  )}

                  {/* Meetup tab actions */}
                  {activeTab === "meetup" && (
                    <>
                      <button
                        onClick={() => handleAction(exchange.id, "complete")}
                        disabled={actionLoading === `${exchange.id}-complete`}
                        className="px-5 py-3 bg-[#26187D] hover:bg-[#1c125e] text-white rounded-xl text-base font-medium disabled:opacity-50"
                      >
                        {actionLoading === `${exchange.id}-complete` ? "Completing..." : "Mark as Completed"}
                      </button>
                      <button
                        onClick={() => setMeetupExchange(exchange)}
                        className="px-5 py-3 bg-white border border-[#26187D] text-[#26187D] hover:bg-[#26187D] hover:text-white rounded-xl text-base font-medium transition"
                      >
                        View Meetup
                      </button>
                      {!exchange.meetup?.confirmed && exchange.meetup?.proposed_by_id !== user?.id && (
                        <button
                          onClick={() => setMeetupExchange(exchange)}
                          className="px-5 py-3 bg-white border border-[#26187D] text-[#26187D] hover:bg-[#26187D] hover:text-white rounded-xl text-base font-medium transition"
                        >
                          Confirm Meetup
                        </button>
                      )}
                    </>
                  )}

                  {/* Message button — always visible */}
                  <button
                    onClick={() => handleMessage(exchange)}
                    className="px-5 py-3 bg-white border border-[#26187D] text-[#26187D] hover:bg-[#26187D] hover:text-white rounded-xl text-base font-medium transition"
                  >
                    Message
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Meetup Modal */}
      {meetupExchange && (
        <MeetupModal
          exchange={meetupExchange}
          currentUserId={user?.id}
          onClose={() => {
            setMeetupExchange(null);
            fetchData();
          }}
        />
      )}
    </div>
  );
}