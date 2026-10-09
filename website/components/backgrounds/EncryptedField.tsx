"use client";

/**
 * "Encrypted field" hero background.
 *
 * Inspired by React Bits backgrounds (DotGrid / Threads) but written for ZWA:
 * plain Canvas 2D, no WebGL, no dependencies.
 *
 *  - Hundreds of faint points in an imperfect grid.
 *  - Occasionally neighbouring points connect into a short path; roughly one
 *    path in three resolves in electric blue, the rest fade away.
 *  - A slow proof wave passes through the field every few seconds.
 *  - Pointer movement adds a very small depth offset (no particles chasing it).
 *
 * Pauses when off-screen or when the tab is hidden; renders a single static
 * frame under prefers-reduced-motion.
 */

import { useEffect, useRef } from "react";

type Pt = { x: number; y: number; a: number; d: number };
type Path = { idx: number[]; born: number; resolve: boolean };

const GAP_DESKTOP = 34;
const GAP_MOBILE = 42;

export function EncryptedField({ className = "", origin = { x: 0.66, y: 0.42 } }: { className?: string; origin?: { x: number; y: number } }) {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    const coarse = window.matchMedia("(pointer: coarse)").matches;

    let w = 0;
    let h = 0;
    let cols = 0;
    let rows = 0;
    let pts: Pt[] = [];
    let paths: Path[] = [];
    let raf = 0;
    let running = false;
    let lastPath = 0;
    let waveStart = 0;
    const pointer = { tx: 0, ty: 0, x: 0, y: 0 };

    // Deterministic jitter so the field doesn't reshuffle on resize.
    const rand = (i: number) => {
      const s = Math.sin(i * 127.1 + 311.7) * 43758.5453;
      return s - Math.floor(s);
    };

    const build = () => {
      const rect = canvas.getBoundingClientRect();
      w = rect.width;
      h = rect.height;
      const dpr = Math.min(window.devicePixelRatio || 1, 2);
      canvas.width = Math.round(w * dpr);
      canvas.height = Math.round(h * dpr);
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      const gap = w < 768 ? GAP_MOBILE : GAP_DESKTOP;
      cols = Math.ceil(w / gap) + 2;
      rows = Math.ceil(h / gap) + 2;
      pts = [];
      for (let r = 0; r < rows; r++) {
        for (let c = 0; c < cols; c++) {
          const i = r * cols + c;
          pts.push({
            x: (c - 1) * gap + (rand(i) - 0.5) * gap * 0.38,
            y: (r - 1) * gap + (rand(i + 9999) - 0.5) * gap * 0.38,
            a: 0.07 + rand(i + 4242) * 0.1,
            d: 0.4 + rand(i + 777) * 0.6, // depth factor for parallax
          });
        }
      }
      paths = [];
    };

    const neighbour = (i: number) => {
      const r = Math.floor(i / cols);
      const c = i % cols;
      // Drift mostly rightwards: private state moving toward the boundary.
      const options = [
        [r, c + 1],
        [r, c + 1],
        [r - 1, c + 1],
        [r + 1, c + 1],
        [r - 1, c],
        [r + 1, c],
      ].filter(([rr, cc]) => rr >= 0 && rr < rows && cc >= 0 && cc < cols);
      const [rr, cc] = options[Math.floor(Math.random() * options.length)];
      return rr * cols + cc;
    };

    const spawnPath = (t: number) => {
      const start = Math.floor(Math.random() * pts.length);
      const len = 4 + Math.floor(Math.random() * 4);
      const idx = [start];
      for (let k = 1; k < len; k++) idx.push(neighbour(idx[k - 1]));
      paths.push({ idx, born: t, resolve: Math.random() < 0.34 });
      if (paths.length > 7) paths.shift();
    };

    const draw = (t: number) => {
      ctx.clearRect(0, 0, w, h);
      pointer.x += (pointer.tx - pointer.x) * 0.04;
      pointer.y += (pointer.ty - pointer.y) * 0.04;

      const ox = origin.x * w;
      const oy = origin.y * h;
      const waveR = reduce ? -1 : ((t - waveStart) / 1000) * 360;
      const maxR = Math.hypot(Math.max(ox, w - ox), Math.max(oy, h - oy)) + 120;
      if (!reduce && waveR > maxR + 2400) waveStart = t; // ~8–9s cycle incl. rest

      for (let i = 0; i < pts.length; i++) {
        const p = pts[i];
        const x = p.x + pointer.x * p.d;
        const y = p.y + pointer.y * p.d;
        let a = p.a;
        let blue = 0;
        if (waveR > 0) {
          const dist = Math.hypot(x - ox, y - oy);
          const band = Math.abs(dist - waveR);
          if (band < 70) {
            const k = 1 - band / 70;
            const fade = Math.max(0, 1 - waveR / maxR);
            a += k * 0.32 * fade;
            blue = k * fade;
          }
        }
        if (blue > 0.05) {
          ctx.fillStyle = `rgba(96,165,250,${a})`;
        } else {
          ctx.fillStyle = `rgba(148,163,184,${a})`;
        }
        ctx.fillRect(x - 0.75, y - 0.75, 1.5, 1.5);
      }

      // Paths: draw progressively (1.2s), hold, fade (1.6s).
      for (const path of paths) {
        const age = (t - path.born) / 1000;
        const life = 4.2;
        if (age > life) continue;
        const grow = Math.min(1, age / 1.2);
        const fadeOut = age > 2.6 ? 1 - (age - 2.6) / (life - 2.6) : 1;
        const segs = path.idx.length - 1;
        const drawn = grow * segs;
        ctx.lineWidth = path.resolve ? 1.1 : 0.8;
        ctx.strokeStyle = path.resolve
          ? `rgba(96,165,250,${0.55 * fadeOut})`
          : `rgba(148,163,184,${0.16 * fadeOut})`;
        ctx.beginPath();
        for (let s = 0; s <= Math.ceil(drawn) && s <= segs; s++) {
          const p = pts[path.idx[s]];
          let x = p.x + pointer.x * p.d;
          let y = p.y + pointer.y * p.d;
          if (s === Math.ceil(drawn) && s > 0) {
            const prev = pts[path.idx[s - 1]];
            const px = prev.x + pointer.x * prev.d;
            const py = prev.y + pointer.y * prev.d;
            const f = drawn - Math.floor(drawn) || 1;
            x = px + (x - px) * f;
            y = py + (y - py) * f;
          }
          if (s === 0) ctx.moveTo(x, y);
          else ctx.lineTo(x, y);
        }
        ctx.stroke();
        if (path.resolve && grow >= 1) {
          const end = pts[path.idx[segs]];
          ctx.fillStyle = `rgba(96,165,250,${0.9 * fadeOut})`;
          ctx.beginPath();
          ctx.arc(end.x + pointer.x * end.d, end.y + pointer.y * end.d, 2.1, 0, Math.PI * 2);
          ctx.fill();
        }
      }
    };

    const loop = (t: number) => {
      if (!running) return;
      if (t - lastPath > 1500) {
        spawnPath(t);
        lastPath = t;
      }
      draw(t);
      raf = requestAnimationFrame(loop);
    };

    const start = () => {
      if (running || reduce) return;
      running = true;
      raf = requestAnimationFrame(loop);
    };
    const stop = () => {
      running = false;
      cancelAnimationFrame(raf);
    };

    build();
    if (reduce) {
      draw(0);
    } else {
      waveStart = performance.now() - 600;
    }

    const ro = new ResizeObserver(() => {
      build();
      if (reduce) draw(0);
    });
    ro.observe(canvas);

    const io = new IntersectionObserver(([entry]) => (entry.isIntersecting ? start() : stop()), { threshold: 0 });
    io.observe(canvas);

    const onVis = () => (document.hidden ? stop() : start());
    document.addEventListener("visibilitychange", onVis);

    const onMove = (e: PointerEvent) => {
      pointer.tx = (e.clientX / window.innerWidth - 0.5) * -10;
      pointer.ty = (e.clientY / window.innerHeight - 0.5) * -10;
    };
    if (!coarse && !reduce) window.addEventListener("pointermove", onMove, { passive: true });

    return () => {
      stop();
      ro.disconnect();
      io.disconnect();
      document.removeEventListener("visibilitychange", onVis);
      window.removeEventListener("pointermove", onMove);
    };
  }, [origin.x, origin.y]);

  return <canvas ref={canvasRef} aria-hidden="true" className={`pointer-events-none absolute inset-0 h-full w-full ${className}`} />;
}
