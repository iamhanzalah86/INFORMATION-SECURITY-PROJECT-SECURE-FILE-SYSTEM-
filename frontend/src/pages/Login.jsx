import { useState } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import Icon from '../components/Icon';
import PasswordInput from '../components/PasswordInput';
import { useAuth, useFlash } from '../context';
import { useTitle } from '../hooks';
import { api } from '../api';

// Ported from login.html
export default function Login() {
  useTitle('Log in');
  const { signIn } = useAuth();
  const { flash, clear } = useFlash();
  const navigate = useNavigate();
  const location = useLocation();
  const [identifier, setIdentifier] = useState('');
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false);

  const submit = async (e) => {
    e.preventDefault();
    setBusy(true);
    clear();
    try {
      const res = await api.login({ username: identifier, password });
      if (res.verify_required) {
        flash(res.message, res.otp_sent ? 'info' : 'error');
        navigate('/verify-email');
        return;
      }
      signIn(res.user);
      navigate(location.state?.from?.pathname || '/dashboard', { replace: true });
    } catch (err) {
      flash(err.message, 'error');
      setBusy(false);
    }
  };

  return (
    <>
      <h1>Welcome back</h1>
      <p className="sub">Log in to manage your encrypted files.</p>
      <form onSubmit={submit}>
        <div className="field">
          <label htmlFor="username">Username or email</label>
          <div className="input-wrap"><Icon name="user" />
            <input className="input" id="username" name="username" value={identifier} onChange={(e) => setIdentifier(e.target.value)} autoComplete="username" required autoFocus /></div>
        </div>
        <div className="field">
          <div className="row-split"><label htmlFor="password">Password</label><Link to="/forgot-password" style={{ fontSize: 13, fontWeight: 600 }}>Forgot password?</Link></div>
          <PasswordInput value={password} onChange={setPassword} autoComplete="current-password" />
        </div>
        <button className="btn btn-primary btn-block" type="submit" disabled={busy}>Log in <Icon name="arrow" /></button>
      </form>
      <p className="auth-foot">New here? <Link to="/register"><b>Create an account</b></Link></p>
    </>
  );
}
