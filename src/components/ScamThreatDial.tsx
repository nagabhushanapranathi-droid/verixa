"use client";

import React, { useEffect, useState } from "react";

interface ScamThreatDialProps {
  score: number; // 0 - 100
  severityLevel: string;
  size?: number;
}

export function ScamThreatDial({
  score,
  severityLevel,
  size = 190,
}: ScamThreatDialProps) {
  const [animatedScore, setAnimatedScore] = useState(0);

  const strokeWidth = 9;
  const radius = (size - strokeWidth * 2) / 2;
  const circumference = 2 * Math.PI * radius;

  const normalizedScore = Math.min(Math.max(Math.round(score), 0), 100);

  useEffect(() => {
    const timer = setTimeout(() => {
      setAnimatedScore(normalizedScore);
    }, 120);
    return () => clearTimeout(timer);
  }, [normalizedScore]);

  const strokeDashoffset =
    circumference - (animatedScore / 100) * circumference;

  const getEditorialScheme = (val: number) => {
    if (val >= 70) {
      return {
        stroke: "#b95c50", // rich terracotta dusky red
        badgeBg: "bg-[#faeee9] text-[#913b31] border-[#eed1c7]",
        label: "Critical Risk Detected",
        gradientId: "dialEditorialRed",
        fromColor: "#c96f63",
        toColor: "#a3453a",
      };
    }
    if (val >= 40) {
      return {
        stroke: "#b5844a", // warm amber sand
        badgeBg: "bg-[#fdf6ec] text-[#8c5e26] border-[#eddcc7]",
        label: "Moderate Caution Advised",
        gradientId: "dialEditorialAmber",
        fromColor: "#c4965f",
        toColor: "#a37035",
      };
    }
    return {
      stroke: "#52755e", // soft refined forest sage
      badgeBg: "bg-[#eef4f0] text-[#365742] border-[#d4e4da]",
      label: "Low Risk Verified",
      gradientId: "dialEditorialSage",
      fromColor: "#648a71",
      toColor: "#42634e",
    };
  };

  const scheme = getEditorialScheme(normalizedScore);

  return (
    <div className="flex flex-col items-center justify-center relative">
      <div
        className="relative flex items-center justify-center"
        style={{ width: size, height: size }}
      >
        <svg
          width={size}
          height={size}
          className="transform -rotate-90 origin-center"
        >
          <defs>
            <linearGradient
              id={scheme.gradientId}
              x1="0%"
              y1="0%"
              x2="100%"
              y2="100%"
            >
              <stop offset="0%" stopColor={scheme.fromColor} />
              <stop offset="100%" stopColor={scheme.toColor} />
            </linearGradient>
          </defs>

          {/* Background Track */}
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            stroke="#ede6dd"
            strokeWidth={strokeWidth}
            fill="transparent"
          />

          {/* Active Progress Arc */}
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            stroke={`url(#${scheme.gradientId})`}
            strokeWidth={strokeWidth}
            fill="transparent"
            strokeDasharray={circumference}
            strokeDashoffset={strokeDashoffset}
            strokeLinecap="round"
            className="dial-ring"
          />
        </svg>

        {/* Center content */}
        <div className="absolute inset-0 flex flex-col items-center justify-center text-center select-none pointer-events-none">
          <span className="text-4xl font-serif italic font-bold tracking-tight text-[#2c2524]">
            {animatedScore}
          </span>
          <span className="text-[11px] tracking-[0.2em] uppercase text-[#7d726d] font-sans mt-0.5">
            Index / 100
          </span>
        </div>
      </div>

      {/* Severity Badge */}
      <div
        className={`mt-3.5 inline-flex items-center gap-2 px-3 py-1 rounded-full text-xs font-serif italic border ${scheme.badgeBg}`}
      >
        <span
          className="h-1.5 w-1.5 rounded-full"
          style={{ backgroundColor: scheme.stroke }}
        />
        {scheme.label}
      </div>
    </div>
  );
}
