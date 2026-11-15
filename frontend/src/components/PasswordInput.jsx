import { useState } from 'react';
import Icon from './Icon';
import { passwordStrength } from '../hooks';

/** Password field with leading lock icon, show/hide toggle and optional strength meter. */
export default function PasswordInput({
  id = 'password', name = 'password', value, onChange, autoComplete,
  minLength, autoFocus, strength = false, icon = 'lock',
}) {
  const [show, setShow] = useState(false);
  const s = passwordStrength(value);
  return (
    <>
      <div className="input-wrap">
        <Icon name={icon} />
        <input
          className="input has-toggle" id={id} name={name} type={show ? 'text' : 'password'}
          value={value} onChange={(e) => onChange(e.target.value)}
          minLength={minLength} autoComplete={autoComplete} autoFocus={autoFocus} required
        />
        <button className="toggle-pw" type="button" aria-label="Show password" aria-pressed={show} onClick={() => setShow((v) => !v)}>
          <Icon name="eye" />
        </button>
      </div>
      {strength && (
        <>
          <div className="meter"><i id="strength-bar" style={{ width: s.width, background: s.color }} /></div>
          <div className="hint row-split"><span>At least 12 characters.</span><b id="strength-text">{s.label}</b></div>
        </>
      )}
    </>
  );
}
