import { useState, useRef, useEffect } from "react";

const API_URL =
  import.meta.env.VITE_AI_SERVICE_URL || "http://localhost/ai";

export default function BookChat({ bookId, bookTitle }) {
  const [isOpen, setIsOpen] = useState(false);
  const [messages, setMessages] = useState([
    {
      role: "assistant",
      text: `Ask me anything about "${bookTitle}"`,
    },
  ]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);

  const bottomRef = useRef(null);

  useEffect(() => {
    if (isOpen) {
      bottomRef.current?.scrollIntoView({
        behavior: "smooth",
      });
    }
  }, [messages, isOpen]);

  const sendMessage = async () => {
    const question = input.trim();
    if (!question || loading) return;

    setMessages((prev) => [
      ...prev,
      { role: "user", text: question },
    ]);

    setInput("");
    setLoading(true);

    try {
      const res = await fetch(`${API_URL}/api/ai/ask`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          book_id: bookId,
          question,
        }),
      });

      const data = await res.json();

      setMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          text: data.answer,
        },
      ]);
    } catch {
      setMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          text: "Something went wrong. Please try again.",
        },
      ]);
    } finally {
      setLoading(false);
    }
  };

  const handleKey = (e) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      sendMessage();
    }
  };

  return (
    <>
      {/* Floating Button */}
      <button
        onClick={() => setIsOpen((prev) => !prev)}
        className="fixed bottom-7 right-7 z-[1000] flex h-14 w-14 items-center justify-center rounded-full bg-[#26187D] shadow-lg transition hover:scale-105"
        aria-label="Open book chat"
      >
        {isOpen ? (
          <svg
            viewBox="0 0 24 24"
            fill="none"
            stroke="white"
            strokeWidth="2.5"
            strokeLinecap="round"
            className="h-6 w-6"
          >
            <line x1="18" y1="6" x2="6" y2="18" />
            <line x1="6" y1="6" x2="18" y2="18" />
          </svg>
        ) : (
          <svg
            viewBox="0 0 24 24"
            fill="none"
            stroke="white"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
            className="h-6 w-6"
          >
            <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z" />
          </svg>
        )}
      </button>

      {/* Chat Window */}
      {isOpen && (
        <div
          className="
            fixed bottom-24 right-7 z-[999]
            w-[650px] h-[750px]
            max-w-[95vw] max-h-[85vh]
            rounded-2xl border border-gray-200
            bg-[#F6F7FF]
            shadow-2xl
            flex flex-col
            overflow-hidden
            sm:right-3 sm:bottom-20
          "
        >
          {/* Header */}
          <div className="flex items-center justify-between bg-[#26187D] px-5 py-4 text-white">
            <div className="flex items-center gap-3">
              <div className="flex h-9 w-9 items-center justify-center rounded-full bg-white/20 text-sm font-medium">
                AI
              </div>

              <div>
                <p className="text-sm font-semibold">
                  Book Assistant
                </p>
                <p className="max-w-[250px] truncate text-xs text-white/70">
                  {bookTitle}
                </p>
              </div>
            </div>

            <button
              onClick={() => setIsOpen(false)}
              className="rounded-md p-1 hover:bg-white/10"
            >
              ✕
            </button>
          </div>

          {/* Messages */}
          <div className="flex-1 space-y-3 overflow-y-auto p-4">
            {messages.map((msg, index) => (
              <div
                key={index}
                className={`max-w-[80%] rounded-2xl px-4 py-3 text-sm leading-relaxed ${
                  msg.role === "user"
                    ? "ml-auto rounded-br-md bg-[#26187D] text-white"
                    : "rounded-bl-md border border-gray-200 bg-white text-black"
                }`}
              >
                {msg.text}
              </div>
            ))}

            {/* Typing Indicator */}
            {loading && (
              <div className="flex w-fit gap-1 rounded-2xl rounded-bl-md border border-gray-200 bg-white px-4 py-3">
                <div className="h-2 w-2 animate-bounce rounded-full bg-[#26187D]" />
                <div className="h-2 w-2 animate-bounce rounded-full bg-[#26187D] delay-100" />
                <div className="h-2 w-2 animate-bounce rounded-full bg-[#26187D] delay-200" />
              </div>
            )}

            <div ref={bottomRef}></div>
          </div>

          {/* Input Area */}
          <div className="flex items-end gap-3 border-t bg-white p-4">
            <textarea
              rows={1}
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={handleKey}
              placeholder="Ask anything about this book..."
              className="
                flex-1 resize-none rounded-xl border border-gray-200
                bg-[#F6F7FF] px-4 py-3 text-sm
                outline-none focus:border-[#26187D]
              "
            />

            <button
              onClick={sendMessage}
              disabled={!input.trim() || loading}
              className="
                flex h-11 w-11 items-center justify-center
                rounded-full bg-[#26187D]
                text-white
                transition hover:scale-105
                disabled:cursor-not-allowed disabled:opacity-50
              "
            >
              ➤
            </button>
          </div>
        </div>
      )}
    </>
  );
}