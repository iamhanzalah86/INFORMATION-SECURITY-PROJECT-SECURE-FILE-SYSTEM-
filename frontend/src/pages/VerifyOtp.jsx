import { useEffect, useRef, useState } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import Icon from '../components/Icon';
import OtpInput from '../components/OtpInput';
import PasswordInput from '../components/PasswordInput';
import ResendButton from '../components/ResendButton';
import { useAuth, useFlash } from '../context';
import { useTitle } from '../hooks';
import { api } from '../api';
import { pendingLinkPath } from '../pendingLink';

// mode="register" (verify email), mode="reset" (reset password) or mode="login" (second sign-in step)
const TEXT = {
  register: { title: 'Verify email', heading: 'Verify your email', button: 'Verify & continue' },
  reset: { title: 'Reset password', heading: 'Reset your password', button: 'Update password' },
  login: { title: 'Confirm sign-in', heading: 'Two-step verification', button: 'Verify & sign in' },
};

export default function VerifyOtp({ mode }) {
  const isRegister = mode === 'register';
  const isLogin = mode === 'login';
  const codeOnly = isRegister || isLogin; // only the reset form has extra fields
  const text = TEXT[mode];
  useTitle(text.title);
  const { flash, clear } = useFlash();
  const { signIn } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [info, setInfo] = useState(null); // { masked_email, ttl } from the server session

  const [otp, setOtp] = useState('');
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [busy, setBusy] = useState(false);
  const [remember, setRemember] = useState(false); // login mode: skip the code on this device next time
  const formRef = useRef(null);

  // The server remembers which email this flow belongs to (session cookie).
  useEffect(() => {
    (isLogin ? api.loginVerifyStatus() : isRegister ? api.verifyStatus() : api.resetStatus())
      .then(setInfo)
      .catch((err) => {
        const goto = err.data && err.data.goto;
        flash(err.message, goto === 'login' ? 'info' : 'error');
        navigate(goto === 'login' ? '/login' : isRegister ? '/register' : '/forgot-password', { replace: true });
      });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [mode]);

  const submit = async (e) => {
    e && e.preventDefault();
    if (busy) return;
    setBusy(true);
    clear();
    try {
      if (isLogin) {
        const res = await api.loginVerify({ otp, remember });
        signIn(res.user);
        navigate(pendingLinkPath() || (location.state?.portal === 'admin' ? '/admin' : location.state?.from?.pathname || '/dashboard'), { replace: true });
      } else if (isRegister) {
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
      const goto = err.data && err.data.goto;
      if (goto) navigate(goto === 'forgot' ? '/forgot-password' : goto === 'login' ? '/login' : '/register');
      setOtp('');
      setBusy(false);
    }
  };

  const resend = async () => {
    clear();
    try {
      const res = await (isLogin ? api.loginResend() : isRegister ? api.verifyResend() : api.resetResend());
      flash(res.message, res.ok === false ? 'error' : codeOnly ? 'success' : 'info');
    } catch (err) {
      flash(err.message, 'error');
    }
  };

  if (!info) return null;

  return (
    <>
      <span className="mail-chip"><Icon name="mail" /> {info.masked_email}</span>
      <h1>{text.heading}</h1>
      <p className="sub">{isLogin ? 'Your password was correct. ' : ''}Enter the 6-digit code we sent. It expires in {info.ttl} minutes.</p>
      <form ref={formRef} onSubmit={submit}>
        {isLogin && (
          <label className="check-row">
            <input type="checkbox" className="chk" checked={remember} onChange={(e) => setRemember(e.target.checked)} />
            <span><b>Remember this device for 30 days</b><small>Next time only your password is needed here. Don't use on a shared computer.</small></span>
          </label>
        )}
        <div className="field">
          <OtpInput
            value={otp}
            onChange={setOtp}
            onComplete={codeOnly ? () => setTimeout(() => formRef.current && formRef.current.requestSubmit(), 0) : undefined}
            autoFocus={codeOnly}
          />
        </div>
        {!codeOnly && (
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
          {text.button} <Icon name="check" />
        </button>
      </form>
      <div style={{ marginTop: 12 }}>
        <ResendButton seconds={60} onClick={resend} />
      </div>
      <p className="auth-foot"><Link to="/login">&larr; Back to log in</Link></p>
    </>
  );
}
