import { useEffect, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import Icon from '../components/Icon';
import OtpInput from '../components/OtpInput';
import PasswordInput from '../components/PasswordInput';
import { useFlash } from '../context';
import { useTitle } from '../hooks';
import { api } from '../api';

// Ported from recover.html (2-step: password -> emailed code)
export default function Recover() {
  useTitle('Recover file');
  const { fileId } = useParams();
  const id = Number(fileId);
  const navigate = useNavigate();
  const { flash, clear } = useFlash();
  const [file, setFile] = useState(undefined);
  const [step, setStep] = useState('password');
  const [masked, setMasked] = useState('');
  const [password, setPassword] = useState('');
  const [otp, setOtp] = useState('');
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    api.getFile(id).then(setFile).catch((err) => {
      flash(err.message, err.status === 409 && !/backup/i.test(err.message) ? 'info' : 'error');
      navigate('/dashboard', { replace: true });
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [id]);

  if (!file) return null;

  const start = async (e) => {
    e.preventDefault();
    setBusy(true);
    clear();
    try {
      const r = await api.recoverStart(id, { password });
      setMasked(r.masked_email);
      flash(r.message, r.category || 'info');
      setStep('otp');
    } catch (err) {
      flash(err.message, 'error');
      if (err.data && err.data.redirect) navigate('/dashboard');
    }
    setBusy(false);
  };

  const verify = async (e) => {
    e.preventDefault();
    setBusy(true);
    clear();
    try {
      const res = await api.recoverVerify(id, { otp });
      flash(res.message, 'success');
      navigate('/dashboard');
    } catch (err) {
      flash(err.message, 'error');
      if (err.data && err.data.redirect) navigate('/dashboard');
      else if (err.data && err.data.restart) { setStep('password'); setOtp(''); setBusy(false); }
      else { setOtp(''); setBusy(false); }
    }
  };

  return (
    <>
      <div className="page-head"><div><h1>Recover file</h1><p>Restore a tampered file from its verified backup.</p></div>
        <Link className="btn" to="/dashboard">&larr; Back</Link></div>
      <div className="card card-pad" style={{ maxWidth: 520 }}>
        <div className="fname" style={{ marginBottom: 18 }}><span className="ftype ico-bad"><Icon name="shield-alert" /></span>
          <div><b>{file.original_filename}</b><small>Status: Tampered</small></div></div>

        {step === 'password' ? (
          <>
            <p className="muted" style={{ marginTop: 0 }}><b>Step 1 of 2.</b> Confirm it's you with your password. We'll then email a 6-digit code.</p>
            <form onSubmit={start}>
              <div className="field"><label htmlFor="password">Your password</label>
                <PasswordInput value={password} onChange={setPassword} autoComplete="current-password" autoFocus /></div>
              <button className="btn btn-primary btn-block" type="submit" disabled={busy}>Send code to my email <Icon name="arrow" /></button>
            </form>
          </>
        ) : (
          <>
            <span className="mail-chip"><Icon name="mail" /> {masked}</span>
            <p className="muted" style={{ marginTop: 0 }}><b>Step 2 of 2.</b> Enter the 6-digit code we emailed you.</p>
            <form onSubmit={verify}>
              <div className="field"><OtpInput value={otp} onChange={setOtp} /></div>
              <button className="btn btn-primary btn-block" type="submit" disabled={busy}>Verify &amp; restore file <Icon name="check" /></button>
            </form>
          </>
        )}
      </div>
    </>
  );
}
