import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import Icon from '../components/Icon';
import { useFlash } from '../context';
import { useTitle } from '../hooks';
import { api } from '../api';

// Ported from forgot_password.html
export default function ForgotPassword() {
  useTitle('Forgot password');
  const { flash, clear } = useFlash();
  const navigate = useNavigate();
  const [email, setEmail] = useState('');
  const [busy, setBusy] = useState(false);

  const submit = async (e) => {
    e.preventDefault();
    setBusy(true);
    clear();
    try {
      const res = await api.forgotPassword({ email });
      flash(res.message, 'info');
      navigate('/reset-password');
    } catch (err) {
      flash(err.message, 'error');
      setBusy(false);
    }
  };

  return (
    <>
      <h1>Forgot your password?</h1>
      <p className="sub">Enter your account email and we'll send you a 6-digit reset code.</p>
      <form onSubmit={submit}>
        <div className="field">
          <label htmlFor="email">Email address</label>
          <div className="input-wrap"><Icon name="mail" />
            <input className="input" id="email" name="email" type="email" value={email} onChange={(e) => setEmail(e.target.value)} autoComplete="email" required autoFocus /></div>
        </div>
        <button className="btn btn-primary btn-block" type="submit" disabled={busy}>Send reset code <Icon name="arrow" /></button>
      </form>
      <p className="auth-foot"><Link to="/login">&larr; Back to log in</Link></p>
    </>
  );
}
