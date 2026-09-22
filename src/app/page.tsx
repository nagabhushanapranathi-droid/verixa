"use client";

import React, { useState, useRef } from "react";
import {
  FileText,
  Link as LinkIcon,
  Image as ImageIcon,
  Upload,
  Copy,
  Check,
  RefreshCw,
  ExternalLink,
  X,
  AlertCircle,
  CheckCircle2,
  AlertTriangle,
  Loader2,
  ArrowRight,
  ShieldAlert,
} from "lucide-react";
import type { FinalAnalysisReport } from "@/types/analysis";
import { ScamThreatDial } from "@/components/ScamThreatDial";
import { ScanSkeleton } from "@/components/ScanSkeleton";
import ParticleText from "@/components/ParticleText";
import DecryptedText from "@/components/DecryptedText";

export default function Home() {
  const [activeTab, setActiveTab] = useState<"text" | "url" | "screenshot">("text");
  const [inputText, setInputText] = useState("");
  const [inputUrl, setInputUrl] = useState("");
  const [imageFile, setImageFile] = useState<File | null>(null);
  const [imageBase64, setImageBase64] = useState<string | null>(null);
  const [imagePreview, setImagePreview] = useState<string | null>(null);
  const [isDragging, setIsDragging] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [report, setReport] = useState<FinalAnalysisReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  const resultsRef = useRef<HTMLDivElement>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Handle image files
  const processImageFile = (file: File) => {
    if (!file.type.startsWith("image/")) {
      setError("Please provide a valid image format (PNG, JPG, WEBP).");
      return;
    }
    if (file.size > 10 * 1024 * 1024) {
      setError("File exceeds 10MB limit. Please provide a lighter image.");
      return;
    }

    setError(null);
    setImageFile(file);

    const reader = new FileReader();
    reader.onload = () => {
      const result = reader.result as string;
      setImagePreview(result);
      const base64Only = result.split(",")[1];
      setImageBase64(base64Only);
    };
    reader.onerror = () => {
      setError("Unable to read selected image.");
    };
    reader.readAsDataURL(file);
  };

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    const files = e.dataTransfer.files;
    if (files && files[0]) {
      processImageFile(files[0]);
    }
  };

  const handleFileInput = (e: React.ChangeEvent<HTMLInputElement>) => {
    const files = e.target.files;
    if (files && files[0]) {
      processImageFile(files[0]);
    }
  };

  const removeImage = () => {
    setImageFile(null);
    setImageBase64(null);
    setImagePreview(null);
    if (fileInputRef.current) {
      fileInputRef.current.value = "";
    }
  };

  // Perform Analysis
  const handleScan = async () => {
    setError(null);
    setReport(null);

    let endpoint = "/api/analyze";
    let payload: Record<string, any> = {};

    if (activeTab === "text") {
      if (!inputText.trim()) {
        setError("Please enter or paste correspondence to examine.");
        return;
      }
      payload = { text: inputText.trim() };
    } else if (activeTab === "url") {
      if (!inputUrl.trim()) {
        setError("Please enter a web address to inspect.");
        return;
      }
      endpoint = "/api/analyze-url";
      payload = { url: inputUrl.trim() };
    } else if (activeTab === "screenshot") {
      if (!imageBase64) {
        setError("Please upload an image screenshot for analysis.");
        return;
      }
      payload = {
        text: "Analyze this uploaded document screenshot for fraud, phishing lures, or fake offers.",
        imageBase64,
      };
    }

    setIsLoading(true);

    try {
      const res = await fetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || "Analysis was not completed. Please try again.");
      }

      setReport(data);

      setTimeout(() => {
        resultsRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
      }, 150);
    } catch (err: any) {
      setError(err.message || "An unexpected error occurred while reviewing the document.");
    } finally {
      setIsLoading(false);
    }
  };

  const handleClear = () => {
    if (activeTab === "text") setInputText("");
    if (activeTab === "url") setInputUrl("");
    if (activeTab === "screenshot") removeImage();
    setError(null);
    setReport(null);
  };

  const handleCopyReport = () => {
    if (!report) return;
    const textReport = `VERIXA — Forensic Examination Report
Scam Threat Index: ${report.scamThreatIndex}/100 (${report.severityLevel})
Confidence: ${Math.round((report.details.confidence || 0) * 100)}%

SUMMARY
${report.details.summary}

OBSERVED SIGNALS
${report.details.riskSignals.map((s, i) => `${i + 1}. [${s.severity.toUpperCase()}] ${s.category}: ${s.description}${s.evidence ? ` (Excerpt: "${s.evidence}")` : ""}`).join("\n")}

RECOMMENDED PRECAUTIONS
${report.details.recommendedActions.map((a, i) => `${i + 1}. ${a}`).join("\n")}

Report compiled by VERIXA`;

    navigator.clipboard.writeText(textReport);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const isHighRisk = report ? report.scamThreatIndex >= 65 : false;
  const isModerateRisk = report ? report.scamThreatIndex >= 40 && report.scamThreatIndex < 65 : false;

  const tabs = [
    { id: "text", label: "Document Text", icon: FileText },
    { id: "url", label: "Web Link", icon: LinkIcon },
    { id: "screenshot", label: "Screenshot", icon: ImageIcon },
  ] as const;



  return (
    <main className="min-h-screen bg-[#faf6f0] text-[#2c2524] flex flex-col justify-between selection:bg-[#e8d3cc] selection:text-[#2c2524]">
      {/* Header */}
      <header className="w-full border-b border-[#e6dfd5]/80 bg-[#faf6f0]/95 backdrop-blur-sm sticky top-0 z-40">
        <div className="mx-auto flex max-w-5xl items-center justify-between px-6 py-4 sm:px-8">
          <div className="flex items-center gap-3">
            {/* Minimalist boutique badge logo */}
            <div className="h-8 w-8 rounded-full bg-[#f2e7e2] border border-[#e5d5cd] flex items-center justify-center font-serif italic text-base font-bold text-[#3d2f2b] select-none shadow-xs">
              V
            </div>
            <div>
              <span className="font-serif tracking-[0.18em] text-base font-bold text-[#2c2524]">
                VERIXA
              </span>
              <span className="hidden sm:inline text-xs text-[#8c7e79] font-serif italic ml-3 pl-3 border-l border-[#e6dfd5]">
                Forensic Correspondence Inspector
              </span>
            </div>
          </div>

          <div className="flex items-center gap-3">
            {report && (
              <button
                type="button"
                onClick={() => {
                  setReport(null);
                  setError(null);
                }}
                className="inline-flex items-center gap-1.5 rounded-full border border-[#dfd6cb] bg-[#fbf9f6] px-3.5 py-1.5 text-xs font-serif italic text-[#5c524f] hover:border-[#c99d93] hover:text-[#2c2524] transition cursor-pointer"
              >
                <RefreshCw className="h-3 w-3 text-[#a67c74]" />
                New Examination
              </button>
            )}
          </div>
        </div>
      </header>

      {/* Main Container */}
      <div className="mx-auto flex w-full max-w-5xl flex-1 flex-col gap-10 px-6 py-10 sm:px-8">
        {/* Split Hero Section */}
        <section className="grid md:grid-cols-12 gap-8 items-center pt-2">
          {/* Left Column: Clear, bold editorial typography */}
          <div className="md:col-span-7 space-y-4">
            <span className="inline-block text-[11px] font-serif uppercase tracking-[0.28em] text-[#a67c74]">
              Discreet Forensic Verification
            </span>
            <h1 className="font-serif text-4xl sm:text-5xl lg:text-6xl font-bold tracking-tight text-[#2c2524] leading-[1.08]">
              Detect Fraud with Clarity.
            </h1>
            <p className="font-sans text-base sm:text-lg text-[#5c524f] max-w-lg leading-relaxed pt-1">
              Scrutinize suspect job offers, deceptive correspondence, and fraudulent domains before you reply, deposit funds, or share personal credentials.
            </p>
          </div>

          {/* Right Column: ParticleText Component on Light Canvas */}
          <div className="md:col-span-5 flex items-center justify-center">
            <div className="w-full rounded-2xl border border-[#e6dfd5] bg-[#fbf8f4] p-3 shadow-xs">
              <ParticleText
                text="VERIXA"
                fontSize={56}
                className="w-full"
              />
            </div>
          </div>
        </section>

        {/* Input Form Card */}
        <section className="rounded-3xl border border-[#e6dfd5] bg-[#ffffff] p-6 sm:p-8 shadow-xs space-y-6">
          {/* Subtle Segmented Tabs */}
          <div className="inline-flex p-1 rounded-2xl border border-[#e6dfd5] bg-[#fbf9f6] gap-1">
            {tabs.map(({ id, label, icon: Icon }) => {
              const active = activeTab === id;
              return (
                <button
                  key={id}
                  type="button"
                  onClick={() => {
                    setActiveTab(id);
                    setError(null);
                  }}
                  className={`inline-flex items-center gap-2 rounded-xl px-4 py-2 text-xs font-serif transition-all cursor-pointer ${
                    active
                      ? "bg-[#ffffff] text-[#2c2524] font-semibold shadow-xs border border-[#e6dfd5]"
                      : "text-[#7d726d] hover:text-[#2c2524] border border-transparent"
                  }`}
                >
                  <Icon className={`h-3.5 w-3.5 ${active ? "text-[#a67c74]" : "text-[#7d726d]"}`} />
                  <span>{label}</span>
                </button>
              );
            })}
          </div>

          {/* Tab: Text */}
          {activeTab === "text" && (
            <div className="space-y-2">
              <label className="flex items-center justify-between text-xs font-serif text-[#5c524f]">
                <span>Correspondence or Document Body</span>
                <span className="font-sans text-[11px] text-[#8c7e79]">
                  {inputText.length > 0 ? `${inputText.length} characters` : ""}
                </span>
              </label>
              <textarea
                value={inputText}
                onChange={(e) => setInputText(e.target.value)}
                placeholder="Paste the email body, job description, or message text here..."
                rows={6}
                className="w-full rounded-2xl border border-[#e6dfd5] bg-[#faf8f5]/60 p-4 text-sm text-[#2c2524] placeholder:text-[#a89d98] focus:border-[#c99d93] focus:bg-[#ffffff] focus:outline-none transition resize-y font-sans leading-relaxed"
              />
            </div>
          )}

          {/* Tab: URL */}
          {activeTab === "url" && (
            <div className="space-y-2">
              <label className="block text-xs font-serif text-[#5c524f]">
                Suspicious Web Address or Portal Link
              </label>
              <div className="relative">
                <div className="pointer-events-none absolute inset-y-0 left-0 flex items-center pl-4 text-[#8c7e79]">
                  <LinkIcon className="h-4 w-4" />
                </div>
                <input
                  type="url"
                  value={inputUrl}
                  onChange={(e) => setInputUrl(e.target.value)}
                  placeholder="https://company-careers.example.com/login"
                  className="w-full rounded-2xl border border-[#e6dfd5] bg-[#faf8f5]/60 py-3.5 pl-11 pr-4 text-sm text-[#2c2524] placeholder:text-[#a89d98] focus:border-[#c99d93] focus:bg-[#ffffff] focus:outline-none transition font-sans"
                />
              </div>
            </div>
          )}

          {/* Tab: Screenshot */}
          {activeTab === "screenshot" && (
            <div className="space-y-2">
              <label className="block text-xs font-serif text-[#5c524f]">
                Screenshot, Letterhead, or Image Excerpt
              </label>
              {!imagePreview ? (
                <div
                  onDragOver={handleDragOver}
                  onDragLeave={handleDragLeave}
                  onDrop={handleDrop}
                  onClick={() => fileInputRef.current?.click()}
                  className={`cursor-pointer rounded-2xl border-2 border-dashed p-8 text-center transition-all ${
                    isDragging
                      ? "border-[#c99d93] bg-[#f5ede8]"
                      : "border-[#dfd6cb] bg-[#faf8f5]/60 hover:border-[#c99d93] hover:bg-[#faf7f3]"
                  }`}
                >
                  <div className="mx-auto flex h-10 w-10 items-center justify-center rounded-full bg-[#f2e7e2] text-[#a67c74] mb-3">
                    <Upload className="h-5 w-5" />
                  </div>
                  <p className="text-sm font-serif font-medium text-[#2c2524]">
                    Select or drop an image file
                  </p>
                  <p className="text-xs text-[#8c7e79] font-sans mt-1">
                    PNG, JPG, or WEBP up to 10MB
                  </p>
                  <input
                    ref={fileInputRef}
                    type="file"
                    accept="image/png, image/jpeg, image/webp"
                    onChange={handleFileInput}
                    className="hidden"
                  />
                </div>
              ) : (
                <div className="rounded-2xl border border-[#e6dfd5] bg-[#faf8f5]/60 p-3">
                  <div className="flex items-center justify-between mb-2">
                    <div className="flex items-center gap-2">
                      <ImageIcon className="h-4 w-4 text-[#a67c74]" />
                      <span className="text-xs font-sans text-[#2c2524] truncate max-w-xs">
                        {imageFile?.name || "Attached document image"}
                      </span>
                    </div>
                    <button
                      type="button"
                      onClick={removeImage}
                      className="inline-flex items-center gap-1 rounded-full bg-[#f0e7e2] px-2.5 py-1 text-xs text-[#5c524f] hover:bg-[#e8d8d1] transition cursor-pointer"
                    >
                      <X className="h-3 w-3" />
                      Remove
                    </button>
                  </div>
                  <div className="max-h-60 overflow-hidden rounded-xl border border-[#e6dfd5] bg-[#ffffff] flex justify-center p-2">
                    {/* eslint-disable-next-line @next/next/no-img-element */}
                    <img
                      src={imagePreview}
                      alt="Preview"
                      className="h-full object-contain max-h-56"
                    />
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Error Banner */}
          {error && (
            <div className="rounded-2xl border border-[#eed1c7] bg-[#fbf3ef] p-4 text-xs text-[#8c3a30] flex items-start gap-3">
              <AlertTriangle className="h-4 w-4 shrink-0 text-[#b95c50] mt-0.5" />
              <div className="flex-1">
                <p className="font-serif italic font-semibold text-[#8c3a30]">Unable to complete review</p>
                <p className="mt-0.5 text-[#5c524f] font-sans leading-relaxed">{error}</p>
              </div>
            </div>
          )}

          {/* Actions */}
          <div className="flex items-center justify-between pt-2 border-t border-[#f0e9e1]">
            <button
              type="button"
              onClick={handleClear}
              disabled={isLoading}
              className="text-xs font-serif italic text-[#8c7e79] hover:text-[#2c2524] transition cursor-pointer disabled:opacity-40"
            >
              Clear input
            </button>

            <button
              type="button"
              onClick={handleScan}
              disabled={isLoading}
              className="inline-flex items-center gap-2 rounded-xl bg-[#2c2524] hover:bg-[#433734] px-6 py-3 text-xs font-serif font-medium tracking-wider text-[#faf6f0] shadow-sm transition disabled:cursor-not-allowed disabled:opacity-75 cursor-pointer"
            >
              {isLoading ? (
                <>
                  <Loader2 className="h-3.5 w-3.5 animate-spin text-[#faf6f0]" />
                  <span>
                    <DecryptedText
                      text="Examining document..."
                      speed={35}
                      maxIterations={12}
                      characters="VERIXA123456789!?#$@"
                      className="text-[#faf6f0]"
                      encryptedClassName="text-[#d6b5ad]"
                      animateOn="view"
                    />
                  </span>
                </>
              ) : (
                <>
                  <span>Examine Document</span>
                  <ArrowRight className="h-3.5 w-3.5 text-[#d6b5ad]" />
                </>
              )}
            </button>
          </div>
        </section>

        {/* Loading State */}
        {isLoading && <ScanSkeleton />}

        {/* Results Section */}
        {report && (
          <section ref={resultsRef} className="space-y-8 pt-2">
            {/* Overall Verdict Card */}
            <div
              className={`rounded-3xl border p-6 sm:p-8 ${
                isHighRisk
                  ? "border-[#eed1c7] bg-[#fbf3ef]"
                  : isModerateRisk
                  ? "border-[#eddcc7] bg-[#fdf8f0]"
                  : "border-[#d8e5dd] bg-[#f4f8f5]"
              }`}
            >
              <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-4">
                <div className="space-y-2">
                  <div className="flex items-center gap-2">
                    <span className="text-[11px] font-serif uppercase tracking-[0.25em] text-[#8c7e79]">
                      Forensic Verdict
                    </span>
                    <span
                      className={`text-[11px] px-2.5 py-0.5 rounded-full font-serif italic border ${
                        isHighRisk
                          ? "bg-[#faeee9] text-[#913b31] border-[#eed1c7]"
                          : isModerateRisk
                          ? "bg-[#fdf6ec] text-[#8c5e26] border-[#eddcc7]"
                          : "bg-[#eef4f0] text-[#365742] border-[#d4e4da]"
                      }`}
                    >
                      {report.severityLevel}
                    </span>
                  </div>

                  <h2 className="font-serif text-2xl sm:text-3xl font-bold text-[#2c2524]">
                    {isHighRisk
                      ? "High Probability of Fraud or Phishing"
                      : isModerateRisk
                      ? "Suspicious Patterns Observed — Exercise Discretion"
                      : "No Direct Indicators of Malicious Intent"}
                  </h2>

                  {/* Concise forensic digest badge/summary */}
                  <div className="rounded-xl border border-[#e6dfd5] bg-[#ffffff]/80 p-3 text-xs font-serif italic text-[#3d2f2b]">
                    <span className="font-semibold text-[#8c635b] not-italic mr-1.5 uppercase text-[10px] tracking-wider font-sans">
                      Forensic Digest:
                    </span>
                    {report.scamThreatIndex >= 65
                      ? `Critical irregularities detected in correspondence. High likelihood of unauthorized impersonation or financial lure.`
                      : report.scamThreatIndex >= 40
                      ? `Elevated caution advised. Inconsistencies noted in domain, sender credentials, or communication pattern.`
                      : `Standard communication traits observed with no immediate red flags or coercive patterns detected.`}
                  </div>

                  <p className="text-sm font-sans text-[#5c524f] leading-relaxed max-w-3xl pt-1">
                    {report.details.summary}
                  </p>
                </div>

                <button
                  type="button"
                  onClick={handleCopyReport}
                  className="inline-flex items-center gap-1.5 rounded-full border border-[#dfd6cb] bg-[#ffffff] px-4 py-2 text-xs font-serif text-[#2c2524] hover:border-[#c99d93] transition cursor-pointer shrink-0"
                >
                  {copied ? (
                    <>
                      <Check className="h-3.5 w-3.5 text-[#52755e]" />
                      <span>Report Copied</span>
                    </>
                  ) : (
                    <>
                      <Copy className="h-3.5 w-3.5 text-[#8c7e79]" />
                      <span>Copy Report</span>
                    </>
                  )}
                </button>
              </div>
            </div>

            {/* Split Editorial Monograph Layout */}
            <div className="grid gap-8 lg:grid-cols-12 items-start">
              {/* Left Column: Dial & Core Metrics */}
              <div className="lg:col-span-5 space-y-6">
                {/* Threat Dial Card */}
                <div className="rounded-3xl border border-[#e6dfd5] bg-[#ffffff] p-6 text-center space-y-6">
                  <div className="flex items-center justify-between border-b border-[#f0e9e1] pb-3">
                    <span className="text-[11px] font-serif uppercase tracking-[0.2em] text-[#8c7e79]">
                      Scam Threat Index
                    </span>
                    <span className="text-xs font-serif italic text-[#8c7e79]">
                      Harmonic Scale
                    </span>
                  </div>

                  <ScamThreatDial
                    score={report.scamThreatIndex}
                    severityLevel={report.severityLevel}
                    size={190}
                  />

                  {/* Marker Breakdown */}
                  <div className="grid grid-cols-2 gap-2 pt-2 border-t border-[#f0e9e1]">
                    <div className="rounded-2xl border border-[#e6dfd5] bg-[#fbf9f6] p-3 text-left">
                      <p className="text-[10px] font-serif uppercase tracking-wider text-[#8c7e79]">
                        Confidence
                      </p>
                      <p className="font-serif italic text-base font-bold text-[#2c2524] mt-0.5">
                        {Math.round((report.details.confidence || 0) * 100)}%
                      </p>
                    </div>

                    <div className="rounded-2xl border border-[#e6dfd5] bg-[#fbf9f6] p-3 text-left">
                      <p className="text-[10px] font-serif uppercase tracking-wider text-[#8c7e79]">
                        Payment Demand
                      </p>
                      <p
                        className={`font-serif italic text-sm font-semibold mt-0.5 ${
                          report.details.paymentRequests ? "text-[#b95c50]" : "text-[#52755e]"
                        }`}
                      >
                        {report.details.paymentRequests ? "Detected" : "Clean"}
                      </p>
                    </div>

                    <div className="rounded-2xl border border-[#e6dfd5] bg-[#fbf9f6] p-3 text-left">
                      <p className="text-[10px] font-serif uppercase tracking-wider text-[#8c7e79]">
                        Impersonation
                      </p>
                      <p
                        className={`font-serif italic text-sm font-semibold mt-0.5 ${
                          report.details.impersonationIndicators ? "text-[#b95c50]" : "text-[#52755e]"
                        }`}
                      >
                        {report.details.impersonationIndicators ? "Suspected" : "None"}
                      </p>
                    </div>

                    <div className="rounded-2xl border border-[#e6dfd5] bg-[#fbf9f6] p-3 text-left">
                      <p className="text-[10px] font-serif uppercase tracking-wider text-[#8c7e79]">
                        Urgency Pressure
                      </p>
                      <p
                        className={`font-serif italic text-sm font-semibold mt-0.5 ${
                          report.details.urgencyIndicators ? "text-[#b5844a]" : "text-[#52755e]"
                        }`}
                      >
                        {report.details.urgencyIndicators ? "High" : "Normal"}
                      </p>
                    </div>
                  </div>
                </div>

                {/* Extracted Credential Details */}
                {report.details.extractedEntities && (
                  <div className="rounded-3xl border border-[#e6dfd5] bg-[#ffffff] p-6 space-y-4">
                    <span className="text-[11px] font-serif uppercase tracking-[0.2em] text-[#8c7e79] block">
                      Extracted Credentials & Marks
                    </span>

                    <div className="space-y-3 text-xs font-sans">
                      <div className="rounded-2xl border border-[#e6dfd5] bg-[#fbf9f6] p-3.5">
                        <p className="text-[#8c7e79] font-serif italic">Claimed Entity / Organization</p>
                        <p className="text-[#2c2524] font-medium mt-1">
                          {report.details.extractedEntities.companyName || "Unspecified in text"}
                        </p>
                      </div>

                      <div className="rounded-2xl border border-[#e6dfd5] bg-[#fbf9f6] p-3.5">
                        <p className="text-[#8c7e79] font-serif italic">Contact Identifiers</p>
                        <p className="text-[#2c2524] font-mono mt-1 break-all">
                          {report.details.extractedEntities.contactInfo || "None identified"}
                        </p>
                      </div>

                      {report.details.extractedEntities.urls &&
                        report.details.extractedEntities.urls.length > 0 && (
                          <div className="rounded-2xl border border-[#e6dfd5] bg-[#fbf9f6] p-3.5">
                            <p className="text-[#8c7e79] font-serif italic mb-1.5">Associated Web Links</p>
                            <div className="space-y-1 font-mono text-[11px] text-[#2c2524]">
                              {report.details.extractedEntities.urls.map((u, i) => (
                                <div key={i} className="flex items-center gap-1.5 truncate">
                                  <LinkIcon className="h-3 w-3 text-[#a67c74] shrink-0" />
                                  <span className="truncate">{u}</span>
                                </div>
                              ))}
                            </div>
                          </div>
                        )}
                    </div>
                  </div>
                )}
              </div>

              {/* Right Column: Signals & Precautions */}
              <div className="lg:col-span-7 space-y-6">
                {/* Signals */}
                <div className="rounded-3xl border border-[#e6dfd5] bg-[#ffffff] p-6 sm:p-8 space-y-4">
                  <div className="flex items-center justify-between border-b border-[#f0e9e1] pb-3">
                    <span className="text-[11px] font-serif uppercase tracking-[0.2em] text-[#8c7e79]">
                      Observed Signals
                    </span>
                    <span className="text-xs font-serif italic text-[#8c7e79]">
                      {report.details.riskSignals?.length || 0} findings
                    </span>
                  </div>

                  {report.details.riskSignals && report.details.riskSignals.length > 0 ? (
                    <div className="space-y-3.5">
                      {report.details.riskSignals.map((signal, idx) => {
                        const isCrit = signal.severity === "critical" || signal.severity === "high";
                        return (
                          <div
                            key={idx}
                            className={`rounded-2xl border p-4.5 space-y-2 ${
                              isCrit
                                ? "border-[#eed1c7] bg-[#fcf5f2]"
                                : signal.severity === "medium"
                                ? "border-[#eddcc7] bg-[#fdf9f2]"
                                : "border-[#e6dfd5] bg-[#fbf9f6]"
                            }`}
                          >
                            <div className="flex items-center justify-between gap-2">
                              <span className="font-serif font-bold text-sm text-[#2c2524]">
                                {signal.category}
                              </span>
                              <span
                                className={`text-[10px] font-serif italic px-2 py-0.5 rounded-full border ${
                                  isCrit
                                    ? "border-[#eed1c7] text-[#913b31] bg-[#faeee9]"
                                    : signal.severity === "medium"
                                    ? "border-[#eddcc7] text-[#8c5e26] bg-[#fdf6ec]"
                                    : "border-[#e6dfd5] text-[#5c524f] bg-[#ffffff]"
                                }`}
                              >
                                {signal.severity}
                              </span>
                            </div>

                            <p className="text-xs font-sans text-[#5c524f] leading-relaxed">
                              {signal.description}
                            </p>

                            {signal.evidence && (
                              <div className="mt-2 rounded-xl border border-[#e6dfd5] bg-[#ffffff] px-3.5 py-2 text-xs font-mono text-[#3d3331] break-words">
                                <span className="font-serif italic text-[10px] text-[#8c7e79] block mb-0.5">
                                  Excerpted evidence:
                                </span>
                                &ldquo;{signal.evidence}&rdquo;
                              </div>
                            )}
                          </div>
                        );
                      })}
                    </div>
                  ) : (
                    <div className="rounded-2xl border border-[#e6dfd5] bg-[#fbf9f6] p-6 text-center text-xs text-[#7d726d] font-serif italic">
                      No deceptive signals identified in the provided material.
                    </div>
                  )}
                </div>

                {/* Recommended Precautions */}
                <div className="rounded-3xl border border-[#e6dfd5] bg-[#ffffff] p-6 sm:p-8 space-y-4">
                  <span className="text-[11px] font-serif uppercase tracking-[0.2em] text-[#8c7e79] block border-b border-[#f0e9e1] pb-3">
                    Recommended Precautions
                  </span>

                  <div className="space-y-3">
                    {report.details.recommendedActions?.map((action, i) => (
                      <div
                        key={i}
                        className="flex items-start gap-3 rounded-2xl border border-[#e6dfd5] bg-[#fbf9f6] p-3.5 text-xs text-[#3d3331]"
                      >
                        <CheckCircle2 className="h-4 w-4 shrink-0 text-[#52755e] mt-0.5" />
                        <span className="font-sans leading-relaxed">{action}</span>
                      </div>
                    ))}
                  </div>

                  <div className="pt-3 border-t border-[#f0e9e1] flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs text-[#8c7e79]">
                    <span className="font-serif italic">Suspect cyber fraud, financial loss, or scam calls?</span>
                    <div className="flex items-center gap-3">
                      <a
                        href="https://cybercrime.gov.in"
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-flex items-center gap-1 font-serif text-[#a67c74] hover:text-[#2c2524] transition underline underline-offset-4"
                      >
                        National Cyber Crime Portal (India) <ExternalLink className="h-3 w-3" />
                      </a>
                      <span>&bull;</span>
                      <a
                        href="https://sancharsaathi.gov.in/sfc/"
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-flex items-center gap-1 font-serif text-[#a67c74] hover:text-[#2c2524] transition underline underline-offset-4"
                      >
                        Chakshu Portal <ExternalLink className="h-3 w-3" />
                      </a>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </section>
        )}
      </div>

      {/* Footer */}
      <footer className="w-full border-t border-[#e6dfd5] bg-[#faf6f0] py-6 mt-16">
        <div className="mx-auto flex max-w-5xl flex-col sm:flex-row items-center justify-between gap-3 px-6 sm:px-8 text-xs text-[#8c7e79] font-serif">
          <div className="flex items-center gap-2">
            <span className="font-bold text-[#2c2524]">VERIXA</span>
            <span>&bull;</span>
            <span className="italic">Forensic correspondence inspection</span>
          </div>
          <div className="text-[11px] tracking-wider uppercase text-[#a89d98]">
            Confidential &bull; Zero retention architecture
          </div>
        </div>
      </footer>
    </main>
  );
}