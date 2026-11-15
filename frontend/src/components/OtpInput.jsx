import { useEffect, useRef } from 'react';

/** 6-digit code box: digits only, optional auto-submit when complete. */
export default function OtpInput({ value, onChange, onComplete, autoFocus = true }) {
  const ref = useRef(null);
  useEffect(() => { if (autoFocus && ref.current) ref.current.focus(); }, [autoFocus]);
  return (
    <input
      ref={ref}
      className="input otp-input" name="otp" inputMode="numeric" autoComplete="one-time-code"
      pattern="\d{6}" maxLength={6} placeholder="••••••" required aria-label="6-digit code"
      value={value}
      onChange={(e) => {
        const v = e.target.value.replace(/\D/g, '').slice(0, 6);
        onChange(v);
        if (v.length === 6 && onComplete) onComplete(v);
      }}
    />
  );
}
