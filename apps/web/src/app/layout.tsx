import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Orvex Recon",
  description: "Authorized bug-bounty recon & vulnerability scanning",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html suppressHydrationWarning>
      <body>{children}</body>
    </html>
  );
}
