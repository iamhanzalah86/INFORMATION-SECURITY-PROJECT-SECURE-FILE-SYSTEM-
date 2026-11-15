import { useEffect, useState, useCallback, useRef } from 'react';
import { APP_NAME } from './config';

/** Sets document.title like the Jinja `{% block title %}` did. */
export function useTitle(title) {
  useEffect(() => {
    document.title = title ? `${title} · ${APP_NAME}` : APP_NAME;
  }, [title]);
}

/** Dark / light theme toggle (same data-theme attribute + localStorage key as app.js). */
export function useTheme() {
  const toggle = useCallback(() => {
    const root = document.documentElement;
    const next = root.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
    const apply = () => root.setAttribute('data-theme', next);
    const reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    // cross-fade the whole page between themes where the browser supports it
    if (document.startViewTransition && !reduced) document.startViewTransition(apply);
    else apply();
    try { localStorage.setItem('theme', next); } catch (e) {}
  }, []);
  return toggle;
}

/** Adds/removes a class on <body> (landing-page). */
export function useBodyClass(name, on = true) {
  useEffect(() => {
    if (!name) return undefined;
    document.body.classList.toggle(name, on);
    return () => document.body.classList.remove(name);
  }, [name, on]);
}

/** Landing page reveal-on-scroll animation (ported from app.js). */
export function useRevealOnScroll() {
  const rootRef = useRef(null);
  useEffect(() => {
    const items = Array.from((rootRef.current || document).querySelectorAll('.reveal-on-scroll'));
    if (!items.length) return undefined;
    if ('IntersectionObserver' in window && !window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
      const obs = new IntersectionObserver((entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            entry.target.classList.add('is-visible');
            obs.unobserve(entry.target);
          }
        });
      }, { threshold: 0.12, rootMargin: '0px 0px -24px 0px' });
      items.forEach((el) => obs.observe(el));
      return () => obs.disconnect();
    }
    items.forEach((el) => el.classList.add('is-visible'));
    return undefined;
  }, []);
  return rootRef;
}

/** Human readable size, same output as Flask's human_size(). */
export function humanSize(num) {
  let n = Number(num || 0);
  const units = ['B', 'KB', 'MB', 'GB'];
  for (let i = 0; i < units.length; i++) {
    if (n < 1024 || i === units.length - 1) return i === 0 ? `${Math.floor(n)} B` : `${n.toFixed(1)} ${units[i]}`;
    n /= 1024;
  }
  return `${n}`;
}

/** Password strength scoring (ported from app.js). */
export function passwordStrength(v) {
  if (!v) return { width: '0%', color: '', label: '' };
  let s = 0;
  if (v.length >= 12) s++;
  if (v.length >= 16) s++;
  if (/[a-z]/.test(v) && /[A-Z]/.test(v)) s++;
  if (/\d/.test(v)) s++;
  if (/[^A-Za-z0-9]/.test(v)) s++;
  if (v.length < 12) s = Math.min(s, 1);
  const map = [
    ['0%', '', ''], ['25%', '#dc2626', 'Weak'], ['50%', '#d97706', 'Fair'],
    ['75%', '#0891b2', 'Good'], ['100%', '#059669', 'Strong'], ['100%', '#059669', 'Excellent'],
  ];
  const m = map[Math.min(s, 5)];
  return { width: m[0], color: m[1], label: m[2] };
}

/** File type badge (ported from the dashboard `ftype` macro). */
export function fileTypeBadge(name) {
  const ext = (name.includes('.') ? name.split('.').pop() : 'file').toLowerCase();
  const label = ext.slice(0, 4).toUpperCase();
  if (ext === 'pdf') return { cls: 'ico-bad', label: 'PDF' };
  if (['doc', 'docx', 'txt', 'md', 'rtf', 'odt'].includes(ext)) return { cls: 'ico-info', label };
  if (['xls', 'xlsx', 'csv'].includes(ext)) return { cls: 'ico-ok', label };
  if (['png', 'jpg', 'jpeg', 'gif', 'webp', 'svg'].includes(ext)) return { cls: 'ico-warn', label };
  if (['zip', 'rar', '7z', 'gz', 'tar'].includes(ext)) return { cls: 'ico-warn', label };
  return { cls: 'ico-brand', label };
}

/** "FILE_UPLOADED" -> "File Uploaded" (Jinja: replace('_',' ')|title) */
export const eventTitle = (t) =>
  t.replace(/_/g, ' ').toLowerCase().replace(/\b\w/g, (c) => c.toUpperCase()).replace(/^Mfa\b/, 'MFA');

export const isBadEvent = (t) => t.includes('TAMPER') || ['LOGIN_FAILED', 'RECOVERY_FAILED', 'MFA_FAILED', 'ACCESS_DENIED', 'ACCOUNT_DISABLED'].includes(t);
export const isOkEvent = (t) => ['FILE_UPLOADED', 'ACCOUNT_VERIFIED', 'FILE_RECOVERED'].includes(t);

/** Category used by the Security events filter pills. */
export function eventCategory(t) {
  if (isBadEvent(t)) return 'alerts';
  if (t.startsWith('FILE_')) return 'files';
  if (t === 'INTEGRITY_SCAN') return 'scans';
  return 'account';
}

/** "5 min ago" style label for a UTC timestamp from the API. */
export function timeAgo(value) {
  if (!value) return '';
  const iso = /[zZ]|[+-]\d\d:?\d\d$/.test(value) ? value : `${value}Z`;
  const secs = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
  if (secs < 60) return 'just now';
  const m = Math.floor(secs / 60);
  if (m < 60) return `${m} min ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h} hr ago`;
  const d = Math.floor(h / 24);
  if (d < 30) return `${d} day${d === 1 ? '' : 's'} ago`;
  return new Date(iso).toLocaleDateString(undefined, { day: 'numeric', month: 'short', year: 'numeric' });
}

const EVENT_VISUALS = {
  FILE_UPLOADED: ['upload', 'ico-ok'],
  FILE_DOWNLOADED: ['download', 'ico-info'],
  FILE_DELETED: ['trash', 'ico-warn'],
  FILE_RECOVERED: ['shield', 'ico-ok'],
  FILE_SHARED: ['share', 'ico-info'],
  FILE_RECEIVED: ['share', 'ico-ok'],
  FILE_SHARE_REVOKED: ['lock', 'ico-warn'],
  FILE_LINK_CREATED: ['share', 'ico-info'],
  FILE_LINK_USED: ['share', 'ico-ok'],
  FILE_LINK_REVOKED: ['lock', 'ico-warn'],
  FILE_SHARE_DOWNLOADED: ['download', 'ico-info'],
  FILE_TAMPERING_DETECTED: ['shield-alert', 'ico-bad'],
  DEMO_TAMPER: ['shield-alert', 'ico-bad'],
  INTEGRITY_SCAN: ['scan', 'ico-info'],
  LOGIN_SUCCESS: ['key', 'ico-ok'],
  LOGIN_FAILED: ['alert', 'ico-bad'],
  LOGOUT: ['logout', 'ico-info'],
  ACCOUNT_VERIFIED: ['check', 'ico-ok'],
  PASSWORD_RESET_REQUESTED: ['mail', 'ico-info'],
  PASSWORD_RESET: ['lock', 'ico-ok'],
  RECOVERY_FAILED: ['alert', 'ico-bad'],
  MFA_FAILED: ['key', 'ico-bad'],
  DEVICE_TRUSTED: ['key', 'ico-info'],
  ACCESS_DENIED: ['lock', 'ico-bad'],
  ROLE_CHANGED: ['users', 'ico-info'],
  ACCOUNT_DISABLED: ['user', 'ico-bad'],
  ACCOUNT_ENABLED: ['user', 'ico-ok'],
};

/** Icon + colour tone for each kind of security event. */
export function eventVisual(type) {
  const m = EVENT_VISUALS[type];
  if (m) return { icon: m[0], tone: m[1] };
  if (type.includes('TAMPER')) return { icon: 'shield-alert', tone: 'ico-bad' };
  return { icon: 'activity', tone: 'ico-info' };
}
