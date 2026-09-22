import type { Metadata } from "next";
import { Playfair_Display, Roboto } from "next/font/google";
import "./globals.css";

const playfair = Playfair_Display({
  subsets: ["latin"],
  variable: "--font-playfair",
  display: "swap",
});

const roboto = Roboto({
  weight: ["300", "400", "500", "700"],
  subsets: ["latin"],
  variable: "--font-roboto",
  display: "swap",
});

export const metadata: Metadata = {
  title: "VERIXA — Forensic Offer & Phishing Inspector",
  description: "Boutique intelligence for inspecting correspondence, job offers, and suspicious domains.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className={`${playfair.variable} ${roboto.variable}`}>
      <body
        className="min-h-screen flex flex-col bg-[#faf6f0] text-[#2c2524] antialiased selection:bg-[#e8d3cc] selection:text-[#2c2524]"
        suppressHydrationWarning
      >
        {children}
      </body>
    </html>
  );
}

