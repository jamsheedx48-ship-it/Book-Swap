import { X } from "lucide-react";

export default function ConfirmationModal({
  isOpen,
  onClose,
  onConfirm,
  title,
  message,
  confirmText = "Confirm",
  cancelText = "Cancel",
  confirmColor = "bg-red-500 hover:bg-red-600",
}) {
  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50 px-4">
      <div className="bg-white w-full max-w-md rounded-3xl p-6 shadow-lg animate-fadeIn">
        
        {/* Header */}
        <div className="flex justify-between items-center mb-4">
          <h2 className="text-2xl font-bold text-[#26187D]">
            {title}
          </h2>

          <button onClick={onClose}>
            <X className="text-gray-500 hover:text-black" />
          </button>
        </div>

        {/* Message */}
        <p className="text-gray-500 mb-6">
          {message}
        </p>

        {/* Buttons */}
        <div className="flex gap-3">
          <button
            onClick={onClose}
            className="flex-1 border border-gray-300 py-3 rounded-xl font-medium hover:bg-gray-50"
          >
            {cancelText}
          </button>

          <button
            onClick={onConfirm}
            className={`flex-1 text-white py-3 rounded-xl font-medium ${confirmColor}`}
          >
            {confirmText}
          </button>
        </div>
      </div>
    </div>
  );
}