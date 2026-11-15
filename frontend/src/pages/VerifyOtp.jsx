import { useEffect, useRef, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import Icon from '../components/Icon';
import OtpInput from '../components/OtpInput';
import PasswordInput from '../components/PasswordInput';
import ResendButton from '../components/ResendButton';
import { useFlash } from '../context';
import { useTitle } from '../hooks';
import { api } from '../api';

// Ported from verify_otp.html — mode="register" (verify email) or mode="reset" (reset password)
export default function VerifyOtp({ mode }) {
  const isRegister = mode === 'register';
  useTitle(isRegister ? 'Verify email' : 'Reset password');
  const { flash, clear } = useFlash();
  const navigate = useNavigate();
  const [info, setInfo] = useState(null); // { masked_email, ttl } from the server session

  const [otp, setOtp] = useState('');
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [busy, setBusy] = useState(false);
  const formRef = useRef(null);

  // The server remembers which email this flow belongs to (session cookie).
  useEffect(() => {
    (isRegister ? api.verifyStatus() : api.resetStatus())
      .then(setInfo)
      .catch((err) => {
        const goto = err.data && err.data.goto;
        flash(err.message, goto === 'login' ? 'info' : 'error');
        navigate(goto === 'login' ? '/login' : isRegister ? '/register' : '/forgot-password', { replace: true });
      });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isRegister]);

  const submit = async (e) => {
    e && e.preventDefault();
    if (busy) return;
    setBusy(true);
    clear();
    try {
      if (isRegister) {
        const res = await api.verifyEmail({ otp });
        flash(res.message, 'success');
        navigate('/login');
      } else {
        const res = await api.resetPassword({ otp, password, confirm_password: confirm });
        flash(res.message, 'success');
        navigate('/login');
      }
    } catch (err) {
      flash(err.message, 'error');
      if (err.data && err.data.goto) navigate(err.data.goto === 'forgot' ? '/forgot-password' : '/register');
      setBusy(false);
    }
  };

  const resend = async () => {
    clear();
    try {
      const res = await (isRegister ? api.verifyResend() : api.resetResend());
      flash(res.message, res.ok === false ? 'error' : isRegister ? 'success' : 'info');
    } catch (err) {
      flash(err.message, 'error');
    }
  };

  if (!info) return null;

  return (
    <>
      <span className="mail-chip"><Icon name="mail" /> {info.masked_email}</span>
      <h1>{isRegister ? 'Verify your email' : 'Reset your password'}</h1>
      <p className="sub">Enter the 6-digit code we sent. It expires in {info.ttl} minutes.</p>
      <form ref={formRef} onSubmit={submit}>
        <div className="field">
          <OtpInput
            value={otp}
            onChange={setOtp}
            onComplete={isRegister ? () => setTimeout(() => formRef.current && formRef.current.requestSubmit(), 0) : undefined}
            autoFocus={isRegister}
          />
        </div>
        {!isRegister && (
          <>
            <div className="field">
              <label htmlFor="password">New password</label>
              <PasswordInput value={password} onChange={setPassword} minLength={12} autoComplete="new-password" strength />
            </div>
            <div className="field">
              <label htmlFor="confirm_password">Confirm new password</label>
              <div className="input-wrap"><Icon name="key" />
                <input className="input" id="confirm_password" name="confirm_password" type="password" value={confirm} onChange={(e) => setConfirm(e.target.value)} minLength={12} autoComplete="new-password" required /></div>
            </div>
          </>
        )}
        <button className="btn btn-primary btn-block" type="submit" disabled={busy}>
          {isRegister ? 'Verify & continue' : 'Update password'} <Icon name="check" />
        </button>
      </form>
      <div style={{ marginTop: 12 }}>
        <ResendButton seconds={60} onClick={resend} />
      </div>
      <p className="auth-foot"><Link to="/login">&larr; Back to log in</Link></p>
    </>
  );
}
