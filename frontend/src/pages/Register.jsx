import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import Icon from '../components/Icon';
import PasswordInput from '../components/PasswordInput';
import { useFlash } from '../context';
import { useTitle } from '../hooks';
import { api } from '../api';

// Ported from register.html
export default function Register() {
  useTitle('Create account');
  const { flash, clear } = useFlash();
  const navigate = useNavigate();
  const [form, setForm] = useState({ username: '', email: '', password: '', confirm_password: '' });
  const [busy, setBusy] = useState(false);
  const set = (k) => (v) => setForm((f) => ({ ...f, [k]: v }));

  const submit = async (e) => {
    e.preventDefault();
    setBusy(true);
    clear();
    try {
      const res = await api.register(form);
      flash(res.message, res.otp_sent ? 'success' : 'error');
      navigate('/verify-email');
    } catch (err) {
      flash(err.message, 'error');
      setBusy(false);
    }
  };

  return (
    <>
      <h1>Create your account</h1>
      <p className="sub">We'll email you a 6-digit code to verify it's you.</p>
      <form onSubmit={submit}>
        <div className="field">
          <label htmlFor="username">Username</label>
          <div className="input-wrap"><Icon name="user" />
            <input className="input" id="username" name="username" value={form.username} onChange={(e) => set('username')(e.target.value)} maxLength={30} autoComplete="username" required autoFocus /></div>
        </div>
        <div className="field">
          <label htmlFor="email">Email address</label>
          <div className="input-wrap"><Icon name="mail" />
            <input className="input" id="email" name="email" type="email" value={form.email} onChange={(e) => set('email')(e.target.value)} maxLength={255} autoComplete="email" required /></div>
        </div>
        <div className="field">
          <label htmlFor="password">Password</label>
          <PasswordInput value={form.password} onChange={set('password')} minLength={12} autoComplete="new-password" strength />
        </div>
        <div className="field">
          <label htmlFor="confirm_password">Confirm password</label>
          <div className="input-wrap"><Icon name="key" />
            <input className="input" id="confirm_password" name="confirm_password" type="password" value={form.confirm_password} onChange={(e) => set('confirm_password')(e.target.value)} minLength={12} autoComplete="new-password" required /></div>
        </div>
        <button className="btn btn-primary btn-block" type="submit" disabled={busy}>Create account &amp; send code <Icon name="arrow" /></button>
      </form>
      <p className="auth-foot">Already registered? <Link to="/login"><b>Log in</b></Link></p>
    </>
  );
}
