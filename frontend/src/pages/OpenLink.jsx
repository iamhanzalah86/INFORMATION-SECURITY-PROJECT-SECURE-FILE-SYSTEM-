import { useEffect, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import Icon from '../components/Icon';
import { useAuth, useFlash } from '../context';
import { useTitle } from '../hooks';
import { forgetLink, rememberLink } from '../pendingLink';
import { api } from '../api';

/**
 * Landing page of a share link (/s/<token>).
 *  - signed in:  the file is added to "Shared with me" (read-only) and the dashboard opens
 *  - visitor:    shows who shared what, and asks them to log in or create an account first
 */
export default function OpenLink() {
  useTitle('Shared file');
  const { token } = useParams();
  const { user } = useAuth();
  const { flash } = useFlash();
  const navigate = useNavigate();
  const [info, setInfo] = useState(undefined); // undefined = loading, null = invalid

  useEffect(() => {
    let alive = true;
    (async () => {
      try {
        if (user) {
          const res = await api.claimLink(token);
          forgetLink();
          if (!alive) return;
          flash(res.message, res.own ? 'info' : 'success');
          navigate(res.own ? '/dashboard' : '/dashboard#shared', { replace: true });
        } else {
          const res = await api.linkInfo(token);
          rememberLink(token);
          if (alive) setInfo(res);
        }
      } catch (err) {
        forgetLink();
        if (alive) setInfo(null);
      }
    })();
    return () => { alive = false; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [token, user]);

  if (info === undefined) return <p className="sub">Opening shared file…</p>;

  if (info === null) {
    return (
      <>
        <div className="modal-ico ico-bad link-ico"><Icon name="alert" /></div>
        <h1>Link not valid</h1>
        <p className="sub">This share link has expired or was turned off by its owner. Ask them for a new one.</p>
        <Link className="btn btn-block" to={user ? '/dashboard' : '/login'}>{user ? 'Go to dashboard' : 'Go to log in'}</Link>
      </>
    );
  }

  return (
    <>
      <div className="modal-ico ico-brand link-ico"><Icon name="share" /></div>
      <h1>A file was shared with you</h1>
      <p className="sub"><b>{info.owner}</b> shared this file. You can download a verified copy; you cannot change or delete it.</p>
      <div className="link-file"><span className="ftype ico-brand"><Icon name="file" /></span><div><b>{info.filename}</b><small>Read-only · encrypted in SecureVault</small></div></div>
      <Link className="btn btn-primary btn-block" to="/login">Log in to open <Icon name="arrow" /></Link>
      <Link className="btn btn-block" to="/register" style={{ marginTop: 10 }}>Create an account</Link>
      <p className="auth-foot">The file opens right after you sign in, in this browser tab.</p>
    </>
  );
}
