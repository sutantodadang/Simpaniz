# Design System — Simpaniz Console ("Mission Tape")

## Product Context
- **What this is:** Built-in web admin console for Simpaniz, a single-binary S3-compatible object storage server written in Zig. Login, bucket/object browser, metrics dashboard.
- **Who it's for:** Infrastructure engineers and self-hosters running their own storage.
- **Space/industry:** Object storage consoles. Peers: AWS S3 console, MinIO console (removed from community edition 2025 — Simpaniz console fills that gap), Cloudflare R2, Garage.
- **Project type:** Internal tool / infrastructure dashboard. Vanilla JS + one CSS file, no framework, no build step; all assets embedded in the binary (no CDN, offline-capable).
- **Memorable thing:** "Fast, serious infra tool — feels instant and dense, engineer-grade, like a well-made terminal." Every design decision serves this.

## Aesthetic Direction
- **Direction:** Industrial/Utilitarian — "instrument panel, not dashboard." The console is a terminal that grew a UI, not a web app cosplaying as software.
- **Decoration level:** Minimal, with exactly one signature flourish: subtle phosphor glow (`text-shadow: 0 0 8px rgba(255,180,84,.45)`) on live-updating amber values. Everything else bone dry.
- **Mood:** Flight recorder for your data. The biggest thing on any screen is a *number*, never a heading. Hairline 1px borders everywhere — the visible grid IS the decoration. A screen at rest is grayscale; a screen doing work glows.
- **Anti-patterns (banned):** border-radius pillows, floating card shadows, gradients, skeleton loaders, spinners (paint fast instead), empty-state illustrations, proportional sans-serif anywhere.

## Typography
- **All roles: JetBrains Mono** (monospace, embedded) — all-mono identity reads "tool," proportional sans reads "SaaS." Iosevka remains an acceptable local-install fallback (condensed width, ~30% more table columns) but is not embedded — its latin woff2 is too heavy for a single-binary target. Berkeley Mono acceptable substitute if licensed.
- **Weights:** 400 (body), 500 (data/emphasis), 700 (headings, hero numbers).
- **Data/Tables:** same family with `font-variant-numeric: tabular-nums` — mandatory on all numbers.
- **Loading:** self-hosted woff2 subset (Latin), 3 weights ≈ 64 KB total, embedded in binary via `ui_assets/`. NO font CDN ever.
- **Fallback stack (zero-byte):** `"JetBrains Mono", ui-monospace, "Cascadia Mono", "SF Mono", Menlo, Consolas, monospace` — metrics close enough to avoid layout shift.
- **Scale:** hero-number 40–96px/700 (clamp), h1 22px/700, body 14px/400, data 14px/500, label 12px, micro-label 10–11px uppercase +1.5px letter-spacing muted.

## Color
- **Approach:** Restrained — amber is *earned*: live values, focus states, links, active nav. Never decorative fills. Blue is banned (category default; the beige of infra).
- **Dark (default):**
  - Background: `#0B0C0E` (carbon, slightly warm)
  - Surface: `#131417` — panels sit ON the bg, never float
  - Surface-2 (hover): `#1A1C20`
  - Border: `#26282D` — hairline 1px, everywhere
  - Text: `#E8E6E3` (warm off-white, not clinical #FFF)
  - Muted: `#8A8F98` — timestamps, byte counts, labels
  - **Accent: `#FFB454` phosphor amber**
  - Semantic: ok `#4BD865`, danger `#FF5C5C` (destructive/error only), warning = accent amber
- **Light (optional theme):** bg `#F2F0EB` warm paper, surface `#FBFAF7`, border `#D6D2C8`, text `#1C1B18`, muted `#6E6A61`, accent darkens to `#B87514` (AA contrast), ok `#1E8F45`, danger `#C43A3A`. No glow in light mode.

## Spacing
- **Base unit:** 4px
- **Density:** compact — engineer-grade dense, not cramped. Table rows 7–8px vertical padding.
- **Scale:** 2xs(2) xs(4) sm(8) md(12) lg(16) xl(24) 2xl(32) 3xl(48)

## Layout
- **Approach:** grid-disciplined. Three-pane app shell: sidebar (200px, bucket tree with CSS-drawn `├─` tree lines) / main (object table) / inspector rail (280px, raw-first).
- **Header:** slim topbar with persistent status ticker (uptime, req/s, nodes, bytes stored) — always live, proves "feels instant."
- **Inspector rail (raw-first):** selecting an object/bucket shows the actual HEAD response / policy JSON / lifecycle XML, syntax-highlighted — no form-modal translation layer.
- **Max content width:** none (full-bleed app); preview/docs pages 1100px.
- **Border radius:** 0 everywhere. Hairline grid aesthetic; 999px allowed only for status dots.

## Motion
- **Approach:** minimal-functional. No entrance animations, no skeletons. Speed IS the motion design: paint < 100ms from embedded assets.
- **Easing:** enter(ease-out) exit(ease-in) move(ease-in-out)
- **Duration:** micro(50-100ms) hover/focus only; short(150ms) rail slide-in; nothing longer.
- **Live data:** values tick in place (no fade); phosphor glow marks them.

## Roadmap Risks (approved direction, implement incrementally)
1. **Amber accent + all-mono identity** — ship with restyle (this system).
2. **Raw-first inspector rail** — replaces delete/download modals; less code than forms.
3. **Command palette (`Ctrl+K`)** — verbs (`mb`, `rm`, `cp`, `presign`) with autocomplete against real buckets; each action shows equivalent API call. Feature work, separate from restyle.

## Decisions Log
| Date | Decision | Rationale |
|------|----------|-----------|
| 2026-07-10 | Initial design system created | /design-consultation: research (MinIO console removal gap, 2026 dashboard trends) + outside voice (Claude subagent, single-model — Codex auth failed). User approved preview. |
| 2026-07-10 | Amber `#FFB454` accent, blue banned | Every infra console is blue; amber (oscilloscope/departure-board) is unowned in category → recognizable screenshots. |
| 2026-07-10 | All-mono (Iosevka embedded) | "Fast serious infra tool" memorable thing; condensed mono = denser tables; no-CDN constraint honored via embedded woff2. |
| 2026-07-10 | Embed JetBrains Mono instead of Iosevka | Iosevka latin woff2 = 984KB/weight (2.9MB total) vs JetBrains Mono 21KB/weight (64KB); single-binary size wins |
