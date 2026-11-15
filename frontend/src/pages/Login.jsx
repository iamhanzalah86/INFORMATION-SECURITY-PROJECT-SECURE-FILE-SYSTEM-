import { useRef, useState } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import Icon from '../components/Icon';
import PasswordInput from '../components/PasswordInput';
import { Glider, useGlider } from '../components/Glider';
import { useAuth, useFlash } from '../context';
import { useTitle } from '../hooks';
import { api } from '../api';

const PORTALS = [['user', 'User login', 'user'], ['admin', 'Admin login', 'key']];

// One page, two doors: "User login" opens the vault, "Admin login" opens the admin
// console and is refused by the server for accounts without a staff role.
export default function Login() {
  const [portal, setPortal] = useState('user');
  const isAdmin = portal === 'admin';
  useTitle(isAdmin ? 'Admin login' : 'Log in');
  const switchRef = useRef(null);
  useGlider(switchRef, portal);
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
      const res = await api.login({ username: identifier, password, portal });
      if (res.verify_required) {
        flash(res.message, res.otp_sent ? 'info' : 'error');
        navigate('/verify-email');
        return;
      }
      if (res.mfa_required) {
        flash(res.message, res.otp_sent ? 'info' : 'error');
        navigate('/login/verify', { state: { ...location.state, portal } });
        return;
      }
      signIn(res.user);
      navigate(isAdmin ? '/admin' : location.state?.from?.pathname || '/dashboard', { replace: true });
    } catch (err) {
      flash(err.message, 'error');
      setBusy(false);
    }
  };

  return (
    <>
      <div className="filter glass-tabs has-glider login-switch" ref={switchRef} role="tablist" aria-label="Login type">
        <Glider />
        {PORTALS.map(([key, label, icon]) => (
          <button key={key} type="button" role="tab" aria-selected={portal === key} className={`pill${portal === key ? ' on' : ''}`} onClick={() => setPortal(key)}>
            <Icon name={icon} /> {label}
          </button>
        ))}
      </div>
      <div className="auth-view" key={portal}>
        <h1>{isAdmin ? 'Admin sign-in' : 'Welcome back'}</h1>
        <p className="sub">{isAdmin ? 'For administrators and security analysts only.' : 'Log in to manage your encrypted files.'}</p>
      </div>
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
        <button className="btn btn-primary btn-block" type="submit" disabled={busy}>{isAdmin ? 'Log in as admin' : 'Log in'} <Icon name="arrow" /></button>
      </form>
      {isAdmin
        ? <p className="auth-foot">Admin access is given by an existing administrator.</p>
        : <p className="auth-foot">New here? <Link to="/register"><b>Create an account</b></Link></p>}
    </>
  );
}
