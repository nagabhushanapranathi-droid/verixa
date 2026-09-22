import React from "react";
import { Loader2 } from "lucide-react";
import DecryptedText from "./DecryptedText";

export function ScanSkeleton() {
  return (
    <div className="w-full space-y-6 animate-pulse">
      {/* Editorial Status Banner */}
      <div className="flex items-center justify-between p-5 rounded-2xl border border-[#e6dfd5] bg-[#fbf8f4]">
        <div className="flex items-center gap-3.5">
          <div className="flex items-center justify-center h-8 w-8 rounded-full bg-[#f2eae4] text-[#a67c74]">
            <Loader2 className="h-4 w-4 animate-spin text-[#8c635b]" />
          </div>
          <div>
            <p className="text-sm font-serif italic font-semibold text-[#2c2524]">
              <DecryptedText
                text="Conducting forensic review..."
                speed={40}
                maxIterations={15}
                characters="VERIXASECURITY12345890!#"
                className="text-[#2c2524]"
                encryptedClassName="text-[#c99d93]"
                animateOn="view"
              />
            </p>
            <p className="text-xs text-[#7d726d] font-sans">
              <DecryptedText
                text="Analyzing semantic structures, sender credibility, and discrepancy patterns..."
                speed={25}
                maxIterations={12}
                sequential
                revealDirection="start"
                className="text-[#7d726d]"
                encryptedClassName="text-[#a67c74]/60"
                animateOn="view"
              />
            </p>
          </div>
        </div>
        <div className="h-1.5 w-24 bg-[#ede5dc] rounded-full overflow-hidden">
          <div className="h-full bg-[#c99d93] w-2/3 animate-[pulse_1.2s_infinite]"></div>
        </div>
      </div>

      {/* Grid skeleton */}
      <div className="grid gap-6 lg:grid-cols-[1.1fr_0.9fr]">
        <div className="rounded-2xl border border-[#e6dfd5] bg-[#fbf8f4] p-6 space-y-6">
          <div className="flex items-center gap-4">
            <div className="h-12 w-12 rounded-full bg-[#ede5dc]"></div>
            <div className="space-y-2 flex-1">
              <div className="h-3 w-20 bg-[#ede5dc] rounded"></div>
              <div className="h-5 w-48 bg-[#ede5dc] rounded"></div>
            </div>
          </div>

          <div className="flex justify-center py-4">
            <div className="h-44 w-44 rounded-full border border-[#ede5dc] bg-[#f5efe8]/60"></div>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            <div className="h-16 rounded-xl bg-[#ede5dc]/60"></div>
            <div className="h-16 rounded-xl bg-[#ede5dc]/60"></div>
            <div className="h-16 rounded-xl bg-[#ede5dc]/60"></div>
            <div className="h-16 rounded-xl bg-[#ede5dc]/60"></div>
          </div>

          <div className="h-24 rounded-xl bg-[#ede5dc]/50 p-4 space-y-2">
            <div className="h-3 w-32 bg-[#dfd6cb] rounded"></div>
            <div className="h-3 w-full bg-[#ede5dc] rounded"></div>
            <div className="h-3 w-4/5 bg-[#ede5dc] rounded"></div>
          </div>
        </div>

        <div className="space-y-6">
          <div className="rounded-2xl border border-[#e6dfd5] bg-[#fbf8f4] p-6 space-y-4">
            <div className="h-4 w-32 bg-[#ede5dc] rounded"></div>
            <div className="h-20 rounded-xl bg-[#ede5dc]/50"></div>
            <div className="h-20 rounded-xl bg-[#ede5dc]/50"></div>
          </div>

          <div className="rounded-2xl border border-[#e6dfd5] bg-[#fbf8f4] p-6 space-y-4">
            <div className="h-4 w-40 bg-[#ede5dc] rounded"></div>
            <div className="h-14 rounded-xl bg-[#ede5dc]/50"></div>
            <div className="h-14 rounded-xl bg-[#ede5dc]/50"></div>
          </div>
        </div>
      </div>
    </div>
  );
}

