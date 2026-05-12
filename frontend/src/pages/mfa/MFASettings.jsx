import { useEffect, useState } from "react";
import { ShieldCheck, ShieldOff, KeyRound, Sparkles, ChevronRight, X } from "lucide-react";
import { toast } from "react-toastify";

import {
  getMFAStatus,
  setupMFA,
  verifyMFASetup,
  disableMFA,
} from "../../api/auth";

export default function MFASettings() {
  const [loading, setLoading] = useState(true);
  const [mfaEnabled, setMfaEnabled] = useState(false);

  const [showSetupBox, setShowSetupBox] = useState(false);
  const [showDisableBox, setShowDisableBox] = useState(false);

  const [qrCode, setQrCode] = useState("");
  const [secret, setSecret] = useState("");

  const [setupCode, setSetupCode] = useState("");
  const [disableCode, setDisableCode] = useState("");

  useEffect(() => {
    fetchMFAStatus();
  }, []);

  const fetchMFAStatus = async () => {
    try {
      const res = await getMFAStatus();
      setMfaEnabled(res.data.mfa_enabled);
    } catch (error) {
      toast.error(error.response?.data?.detail || "Failed to fetch MFA status");
    } finally {
      setLoading(false);
    }
  };

  const handleSetupMFA = async () => {
    try {
      const res = await setupMFA();
      setQrCode(res.data.qr_code);
      setSecret(res.data.secret);
      setShowSetupBox(true);
      setShowDisableBox(false);
      toast.success("QR code generated");
    } catch (error) {
      toast.error(error.response?.data?.detail || "Failed to setup MFA");
    }
  };

  const handleVerifySetup = async () => {
    if (!setupCode.trim()) { toast.error("Enter verification code"); return; }
    try {
      await verifyMFASetup({ code: setupCode });
      toast.success("MFA enabled successfully");
      setMfaEnabled(true);
      setShowSetupBox(false);
      setSetupCode("");
    } catch (error) {
      toast.error(error.response?.data?.detail || "Invalid code");
    }
  };

  const handleDisableMFA = async () => {
    if (!disableCode.trim()) { toast.error("Enter authentication code"); return; }
    try {
      await disableMFA({ code: disableCode });
      toast.success("MFA disabled successfully");
      setMfaEnabled(false);
      setShowDisableBox(false);
      setDisableCode("");
    } catch (error) {
      toast.error(error.response?.data?.detail || "Failed to disable MFA");
    }
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-[#F8FAFF] flex flex-col items-center justify-center">
        <div className="w-10 h-10 border-4 border-[#26187D] border-t-transparent rounded-full animate-spin mb-4"></div>
        <p className="text-[10px] font-bold text-gray-400 uppercase tracking-widest">Encrypting Connection...</p>
      </div>
    );
  }

  return (
    <div className="min-h-screen pt-28 pb-12 px-6 bg-gradient-to-br from-[#F1F4F9] via-[#F8FAFF] to-white font-sans text-slate-900">
      <div className="max-w-[1000px] mx-auto">
        
        {/* Header Section */}
        <div className="mb-10">
          <div className="flex items-center gap-2 mb-2">
            <Sparkles className="text-[#5B4CF0]" size={16} />
            <span className="text-[10px] font-bold uppercase tracking-[0.2em] text-[#26187D]">
              Security Protocol
            </span>
          </div>
          <h1 className="text-4xl font-bold tracking-tight">Account Security</h1>
          <p className="text-gray-500 mt-2 font-medium">Protect your library and messages with Multi-Factor Authentication.</p>
        </div>

        <div className="bg-white rounded-[2.5rem] p-8 md:p-12 shadow-sm border border-white">
          {/* Current Status Card */}
          <div className={`rounded-3xl p-6 border ${mfaEnabled ? 'bg-green-50/50 border-green-100' : 'bg-rose-50/50 border-rose-100'} flex items-center justify-between flex-wrap gap-4`}>
            <div className="flex items-center gap-5">
              <div className={`w-14 h-14 rounded-2xl flex items-center justify-center shadow-sm ${mfaEnabled ? 'bg-white text-green-600' : 'bg-white text-rose-500'}`}>
                {mfaEnabled ? <ShieldCheck size={28} /> : <ShieldOff size={28} />}
              </div>
              <div>
                <h3 className="font-bold text-slate-900">MFA Status</h3>
                <p className="text-sm text-slate-500 font-medium">
                  {mfaEnabled ? "Your account is fully protected." : "Your account is vulnerable. Enable MFA now."}
                </p>
              </div>
            </div>
            
            <button
              onClick={mfaEnabled ? () => setShowDisableBox(true) : handleSetupMFA}
              className={`px-8 py-3 rounded-xl font-bold text-sm transition-all active:scale-95 shadow-sm ${
                mfaEnabled 
                ? "bg-white text-rose-500 hover:bg-rose-500 hover:text-white border border-rose-100" 
                : "bg-[#26187D] text-white hover:bg-black shadow-indigo-50"
              }`}
            >
              {mfaEnabled ? "Disable" : "Enable MFA"}
            </button>
          </div>

          {/* Setup MFA Section */}
          {showSetupBox && !mfaEnabled && (
            <div className="mt-10 p-8 bg-gray-50 rounded-[2rem] border border-gray-100 animate-in fade-in slide-in-from-top-4 duration-500">
              <div className="flex justify-between items-start mb-6">
                <div className="flex items-center gap-3">
                  <KeyRound className="text-[#26187D]" size={20} />
                  <h3 className="font-bold text-lg">Setup Authenticator</h3>
                </div>
                <button onClick={() => setShowSetupBox(false)} className="text-gray-400 hover:text-gray-600"><X size={20}/></button>
              </div>

              <div className="grid md:grid-cols-2 gap-10 items-center">
                <div className="bg-white p-4 rounded-3xl shadow-sm border border-gray-100 flex flex-col items-center">
                  {qrCode ? (
                    <img src={qrCode} alt="QR Code" className="w-48 h-48" />
                  ) : (
                    <div className="w-48 h-48 bg-gray-50 animate-pulse rounded-2xl" />
                  )}
                  <p className="text-[10px] font-bold text-gray-400 uppercase tracking-widest mt-4">Scan with Google Authenticator</p>
                </div>

                <div className="space-y-6">
                  <div className="space-y-2">
                    <label className="text-[10px] font-bold text-gray-400 uppercase tracking-widest ml-1">Secret Key (Manual Entry)</label>
                    <div className="bg-white border border-gray-100 rounded-xl p-3 font-mono text-xs break-all text-[#26187D] font-bold">
                      {secret}
                    </div>
                  </div>

                  <div className="space-y-2">
                    <label className="text-[10px] font-bold text-gray-400 uppercase tracking-widest ml-1">Verification Code</label>
                    <input
                      type="text"
                      maxLength="6"
                      placeholder="000000"
                      value={setupCode}
                      onChange={(e) => setSetupCode(e.target.value)}
                      className="w-full bg-white border border-gray-100 rounded-xl px-5 py-3 font-bold text-center text-lg tracking-[0.5em] focus:ring-2 focus:ring-indigo-100 outline-none transition-all"
                    />
                  </div>

                  <button
                    onClick={handleVerifySetup}
                    className="w-full bg-[#26187D] text-white py-4 rounded-xl font-bold text-sm shadow-lg shadow-indigo-100 flex items-center justify-center gap-2 hover:bg-black transition-all"
                  >
                    Verify & Activate <ChevronRight size={18} />
                  </button>
                </div>
              </div>
            </div>
          )}

          {/* Disable MFA Section */}
          {showDisableBox && mfaEnabled && (
            <div className="mt-10 p-8 bg-rose-50/30 rounded-[2rem] border border-rose-100 animate-in fade-in slide-in-from-top-4">
              <div className="flex justify-between items-center mb-6">
                <h3 className="font-bold text-rose-600">Deactivate Protection</h3>
                <button onClick={() => setShowDisableBox(false)} className="text-gray-400 hover:text-gray-600"><X size={20}/></button>
              </div>

              <div className="max-w-md space-y-4">
                <p className="text-sm text-slate-500 font-medium">Enter your current 6-digit code to confirm deactivation.</p>
                <input
                  type="text"
                  maxLength="6"
                  placeholder="000000"
                  value={disableCode}
                  onChange={(e) => setDisableCode(e.target.value)}
                  className="w-full bg-white border border-rose-100 rounded-xl px-5 py-3 font-bold text-center text-lg tracking-[0.5em] outline-none"
                />
                <button
                  onClick={handleDisableMFA}
                  className="w-full bg-rose-500 text-white py-4 rounded-xl font-bold text-sm hover:bg-rose-600 transition-all shadow-lg shadow-rose-100"
                >
                  Confirm Deactivation
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}