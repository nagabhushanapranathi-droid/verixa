"use client";

import React, { useRef, useEffect } from "react";

interface ParticleTextProps {
  text?: string;
  className?: string;
  fontSize?: number;
}

interface Particle {
  x: number;
  y: number;
  originX: number;
  originY: number;
  vx: number;
  vy: number;
  size: number;
  color: string;
}

export default function ParticleText({
  text = "VERIXA",
  className = "",
  fontSize = 58,
}: ParticleTextProps) {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    let animationFrameId: number;
    let particles: Particle[] = [];

    const mouse = {
      x: -2000,
      y: -2000,
      radius: 70,
    };

    // Refined dusky rose & warm espresso palette
    const colors = [
      "#2c2524", // rich charcoal espresso
      "#3d3432", // warm dark roast
      "#c99d93", // soft dusky rose
      "#d6b5ad", // pale blush rose
      "#a67c74", // muted terracotta
      "#8c635b", // dusky brick
    ];

    const init = () => {
      const rect = canvas.getBoundingClientRect();
      const dpr = window.devicePixelRatio || 1;
      const width = rect.width;
      const height = rect.height;

      canvas.width = width * dpr;
      canvas.height = height * dpr;
      ctx.scale(dpr, dpr);

      // Create off-screen canvas to sample typography pixels
      const offCanvas = document.createElement("canvas");
      offCanvas.width = width;
      offCanvas.height = height;
      const offCtx = offCanvas.getContext("2d");
      if (!offCtx) return;

      offCtx.fillStyle = "#000";
      offCtx.font = `italic 700 ${fontSize}px var(--font-playfair), "Playfair Display", Georgia, serif`;
      offCtx.textAlign = "center";
      offCtx.textBaseline = "middle";
      offCtx.fillText(text, width / 2, height / 2);

      const imgData = offCtx.getImageData(0, 0, width, height).data;
      particles = [];

      // Grid sampling step
      const step = Math.max(2, Math.floor(fontSize / 24));

      for (let y = 0; y < height; y += step) {
        for (let x = 0; x < width; x += step) {
          const index = (y * width + x) * 4;
          const alpha = imgData[index + 3];
          if (alpha > 128) {
            const color = colors[Math.floor(Math.random() * colors.length)];
            const scatter = (Math.random() - 0.5) * 14;
            particles.push({
              x: x + scatter,
              y: y + scatter,
              originX: x,
              originY: y,
              vx: 0,
              vy: 0,
              size: Math.random() * 1.4 + 1.1,
              color,
            });
          }
        }
      }
    };

    const handleMouseMove = (e: MouseEvent) => {
      const rect = canvas.getBoundingClientRect();
      mouse.x = e.clientX - rect.left;
      mouse.y = e.clientY - rect.top;
    };

    const handleMouseLeave = () => {
      mouse.x = -2000;
      mouse.y = -2000;
    };

    const render = () => {
      const rect = canvas.getBoundingClientRect();
      ctx.clearRect(0, 0, rect.width, rect.height);

      const friction = 0.86;
      const springFactor = 0.085;

      for (let i = 0; i < particles.length; i++) {
        const p = particles[i];

        // Repel from mouse
        const dx = mouse.x - p.x;
        const dy = mouse.y - p.y;
        const dist = Math.sqrt(dx * dx + dy * dy);

        if (dist < mouse.radius) {
          const force = (mouse.radius - dist) / mouse.radius;
          const angle = Math.atan2(dy, dx);
          p.vx -= Math.cos(angle) * force * 7.5;
          p.vy -= Math.sin(angle) * force * 7.5;
        }

        // Return to home position
        const springX = (p.originX - p.x) * springFactor;
        const springY = (p.originY - p.y) * springFactor;

        p.vx = (p.vx + springX) * friction;
        p.vy = (p.vy + springY) * friction;

        p.x += p.vx;
        p.y += p.vy;

        // Draw particle
        ctx.fillStyle = p.color;
        ctx.beginPath();
        ctx.arc(p.x, p.y, p.size, 0, Math.PI * 2);
        ctx.fill();
      }

      animationFrameId = requestAnimationFrame(render);
    };

    init();
    render();

    window.addEventListener("resize", init);
    canvas.addEventListener("mousemove", handleMouseMove);
    canvas.addEventListener("mouseleave", handleMouseLeave);

    return () => {
      cancelAnimationFrame(animationFrameId);
      window.removeEventListener("resize", init);
      canvas.removeEventListener("mousemove", handleMouseMove);
      canvas.removeEventListener("mouseleave", handleMouseLeave);
    };
  }, [text, fontSize]);

  return (
    <div className={`relative w-full h-full flex flex-col items-center justify-center ${className}`}>
      <canvas
        ref={canvasRef}
        className="w-full h-36 sm:h-44 md:h-52 block cursor-pointer select-none"
        style={{ touchAction: "none" }}
      />
    </div>
  );
}
