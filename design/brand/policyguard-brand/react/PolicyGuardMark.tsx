import * as React from "react";

/**
 * PolicyGuard — Terminal Shield mark.
 * The shield inherits `color` (currentColor); the >_ prompt is the fixed brand accent.
 *
 *   <PolicyGuardMark size={32} />                    // shield = current text color
 *   <PolicyGuardMark size={48} className="text-white" />
 *   <PolicyGuardMark size={48} accent="#C2F24A" />   // override accent
 *   <PolicyGuardMark size={48} mono />               // monochrome (prompt follows currentColor too)
 */
export interface PolicyGuardMarkProps extends React.SVGProps<SVGSVGElement> {
  size?: number;
  /** Accent color for the >_ prompt. Default = PolicyGuard lime. */
  accent?: string;
  /** Render the whole mark in one color (currentColor). */
  mono?: boolean;
}

export function PolicyGuardMark({
  size = 24,
  accent = "#C2F24A",
  mono = false,
  ...props
}: PolicyGuardMarkProps) {
  const promptColor = mono ? "currentColor" : accent;
  return (
    <svg
      width={size}
      height={(size * 104) / 100}
      viewBox="0 0 100 104"
      fill="none"
      role="img"
      aria-label="PolicyGuard"
      {...props}
    >
      <path
        d="M50 6 L88 20 V54 C88 80 50 98 50 98 C50 98 12 80 12 54 V20 Z"
        stroke="currentColor"
        strokeWidth={3}
        strokeLinejoin="round"
      />
      <path
        d="M37 42 L49 52 L37 62"
        stroke={promptColor}
        strokeWidth={4.5}
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      <path d="M55 62 H69" stroke={promptColor} strokeWidth={4.5} strokeLinecap="round" />
    </svg>
  );
}

/** Mark + wordmark lockup. Requires IBM Plex Mono to be loaded. */
export function PolicyGuardLockup({
  height = 28,
  accent = "#C2F24A",
  ...props
}: { height?: number; accent?: string } & React.HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      style={{ display: "inline-flex", alignItems: "center", gap: height * 0.42 }}
      {...props}
    >
      <PolicyGuardMark size={height} accent={accent} />
      <span
        style={{
          fontFamily: "'IBM Plex Mono', ui-monospace, SFMono-Regular, Menlo, monospace",
          fontWeight: 700,
          fontSize: height * 0.78,
          letterSpacing: "-0.02em",
          lineHeight: 1,
        }}
      >
        PolicyGuard
      </span>
    </div>
  );
}

export default PolicyGuardMark;
