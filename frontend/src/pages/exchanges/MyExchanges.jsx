import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { getMyExchanges, exchangeAction } from "../../api/exchange";
import { getMe } from "../../api/auth";
import { startConversation } from "../../api/chat";

export default function MyExchanges() {
  const [user, setUser] = useState(null);
  const [exchanges, setExchanges] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [actionLoading, setActionLoading] = useState("");
  const [activeTab, setActiveTab] = useState("received");
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
      // if i'm the receiver, message the requester. if i'm the requester, message the receiver.
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

  const sentExchanges = exchanges.filter(
    (exchange) => exchange.requester_id === user?.id,
  );
  const receivedExchanges = exchanges.filter(
    (exchange) => exchange.receiver_id === user?.id,
  );
  const currentList =
    activeTab === "received" ? receivedExchanges : sentExchanges;

  const statusStyles = {
    pending: "bg-yellow-100 text-yellow-700",
    accepted: "bg-green-100 text-green-700",
    rejected: "bg-red-100 text-red-700",
    completed: "bg-blue-100 text-blue-700",
    cancelled: "bg-gray-100 text-gray-500",
  };

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
          <button
            onClick={() => setActiveTab("received")}
            className={`px-6 py-3 rounded-xl text-base font-medium transition ${
              activeTab === "received"
                ? "bg-[#26187D] text-white"
                : "text-gray-600 hover:bg-gray-100"
            }`}
          >
            Received ({receivedExchanges.length})
          </button>
          <button
            onClick={() => setActiveTab("sent")}
            className={`px-6 py-3 rounded-xl text-base font-medium transition ${
              activeTab === "sent"
                ? "bg-[#26187D] text-white"
                : "text-gray-600 hover:bg-gray-100"
            }`}
          >
            Sent ({sentExchanges.length})
          </button>
        </div>

        {/* Empty State */}
        {currentList.length === 0 ? (
          <div className="bg-white rounded-2xl p-14 text-center shadow-sm">
            <div className="text-6xl mb-4">📚</div>
            <h3 className="text-2xl font-semibold text-gray-700 mb-2">
              No {activeTab} exchanges
            </h3>
            <p className="text-gray-500 text-base">
              Your {activeTab} exchange requests will appear here.
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
                        {activeTab === "received"
                          ? "Offered Book"
                          : "You Offered"}
                      </p>
                      <p className="font-semibold text-lg text-black">
                        {exchange.offered_book}
                      </p>
                    </div>
                    <span className="text-gray-400 text-2xl">⇄</span>
                    <div>
                      <p className="text-sm text-gray-400 mb-1">
                        {activeTab === "received"
                          ? "Your Book"
                          : "Requested Book"}
                      </p>
                      <p className="font-semibold text-lg text-[#26187D]">
                        {exchange.requested_book}
                      </p>
                    </div>
                  </div>
                  <span
                    className={`px-4 py-2 rounded-full text-sm font-semibold capitalize ${
                      statusStyles[exchange.status]
                    }`}
                  >
                    {exchange.status}
                  </span>
                </div>

                {/* User Info */}
                <p className="text-base text-gray-500 mb-4">
                  {activeTab === "received"
                    ? `From: ${exchange.requester}`
                    : `To: ${exchange.receiver}`}
                </p>

                {/* Message */}
                {exchange.message && (
                  <div className="bg-gray-50 rounded-xl p-4 mb-5">
                    <p className="text-base text-gray-600 italic">
                      "{exchange.message}"
                    </p>
                  </div>
                )}

                {/* Action Buttons */}
                <div className="flex flex-wrap gap-4">
                  {activeTab === "received" &&
                    exchange.status === "pending" && (
                      <>
                        <button
                          onClick={() => handleAction(exchange.id, "accept")}
                          disabled={actionLoading === `${exchange.id}-accept`}
                          className="px-5 py-3 bg-green-500 hover:bg-green-600 text-white rounded-xl text-base font-medium disabled:opacity-50"
                        >
                          {actionLoading === `${exchange.id}-accept`
                            ? "Accepting..."
                            : "Accept"}
                        </button>
                        <button
                          onClick={() => handleAction(exchange.id, "reject")}
                          disabled={actionLoading === `${exchange.id}-reject`}
                          className="px-5 py-3 bg-red-500 hover:bg-red-600 text-white rounded-xl text-base font-medium disabled:opacity-50"
                        >
                          {actionLoading === `${exchange.id}-reject`
                            ? "Rejecting..."
                            : "Reject"}
                        </button>
                      </>
                    )}
                  {activeTab === "sent" && exchange.status === "pending" && (
                    <button
                      onClick={() => handleAction(exchange.id, "cancel")}
                      disabled={actionLoading === `${exchange.id}-cancel`}
                      className="px-5 py-3 bg-red-500 hover:bg-red-600 text-white rounded-xl text-base font-medium disabled:opacity-50"
                    >
                      {actionLoading === `${exchange.id}-cancel`
                        ? "Cancelling..."
                        : "Cancel Request"}
                    </button>
                  )}

                  {exchange.status === "accepted" && (
                    <>
                      <button
                        onClick={() => handleAction(exchange.id, "complete")}
                        disabled={actionLoading === `${exchange.id}-complete`}
                        className="px-5 py-3 bg-[#26187D] hover:bg-[#1c125e] text-white rounded-xl text-base font-medium disabled:opacity-50"
                      >
                        {actionLoading === `${exchange.id}-complete`
                          ? "Completing..."
                          : "Mark as Completed"}
                      </button>
                    </>
                  )}
                  <>
                    {/* Message button  */}
                    <button
                      onClick={() => handleMessage(exchange)}
                      className="px-5 py-3 bg-white border border-[#26187D] text-[#26187D] hover:bg-[#26187D] hover:text-white rounded-xl text-base font-medium transition"
                    >
                      Message
                    </button>
                  </>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
