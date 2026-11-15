import { Link } from 'react-router-dom';
import Icon from '../components/Icon';
import Brand from '../components/Brand';
import ThemeIcon from '../components/ThemeIcon';
import { useBodyClass, useRevealOnScroll, useTheme, useTitle } from '../hooks';
import { APP_NAME } from '../config';

// Ported from index.html
export default function Landing() {
  useTitle('');
  useBodyClass('landing-page');
  const toggleTheme = useTheme();
  const rootRef = useRevealOnScroll();

  return (
    <div ref={rootRef}>
      <header className="landing-hero">
        <div className="landing-orb orb-one" aria-hidden="true" /><div className="landing-orb orb-two" aria-hidden="true" />
        <nav className="land-nav landing-nav">
          <Brand to="/" />
          <div className="actions">
            <button className="btn btn-ghost btn-icon landing-theme" onClick={toggleTheme} type="button" aria-label="Toggle theme"><ThemeIcon /></button>
            <Link className="btn btn-ghost" to="/login">Log in</Link>
            <Link className="btn btn-primary" to="/register">Get started <Icon name="arrow" /></Link>
          </div>
        </nav>
        <div className="landing-hero-grid">
          <div className="landing-copy reveal-on-scroll">
            <span className="eyebrow"><Icon name="lock" /> AES-256-GCM <span className="eyebrow-dot" /> SHA-256 integrity checks</span>
            <h1>Your files.<br /><span>Your privacy, protected.</span></h1>
            <p className="landing-lead">A secure vault that encrypts files before storage, verifies their integrity, and flags unexpected changes.</p>
            <div className="actions landing-cta">
              <Link className="btn btn-primary btn-large" to="/register">Create your vault <Icon name="arrow" /></Link>
              <a className="btn btn-glass btn-large" href="#how-it-works">Explore how it works</a>
            </div>
            <div className="landing-proof"><span className="proof-check">✓</span> Encrypted before storage <span className="proof-separator">·</span> Integrity checked on download</div>
          </div>
          <div className="vault-preview reveal-on-scroll" aria-label="Illustration of secure file vault">
            <div className="preview-top"><span className="window-dots"><i /><i /><i /></span><span className="preview-label">SECURE VAULT</span><span className="preview-lock"><Icon name="lock" /></span></div>
            <div className="preview-shield"><div className="shield-halo"><Icon name="shield" /></div><span className="preview-status"><i /> Protection active</span></div>
            <div className="preview-file"><div className="file-symbol"><Icon name="file" /></div><div className="file-copy"><b>Confidential_Report.pdf</b><small>Encrypted file · AES-256-GCM</small></div><span className="file-verified"><Icon name="check" /></span></div>
            <div className="preview-file"><div className="file-symbol blue"><Icon name="file" /></div><div className="file-copy"><b>Project_Archive.zip</b><small>Integrity verified · SHA-256</small></div><span className="file-verified"><Icon name="check" /></span></div>
            <div className="preview-foot"><span><Icon name="activity" /> Integrity monitoring</span><b><i /> Ready</b></div>
            <div className="preview-glint" aria-hidden="true" />
          </div>
        </div>
        <div className="hero-bottom-fade" aria-hidden="true" />
      </header>
      <main>
        <section className="landing-feature-wrap reveal-on-scroll" aria-label="Security features">
          <div className="landing-feature card"><div className="feature-icon teal"><Icon name="lock" /></div><div><h3>Encrypted at rest</h3><p>Files are encrypted before they reach persistent storage using AES-256-GCM.</p></div></div>
          <div className="landing-feature card"><div className="feature-icon green"><Icon name="shield" /></div><div><h3>Tamper detection</h3><p>SHA-256 integrity checks help identify modified or missing encrypted files.</p></div></div>
          <div className="landing-feature card"><div className="feature-icon blue"><Icon name="activity" /></div><div><h3>Security audit trail</h3><p>Review recorded uploads, downloads, sign-ins, scans, and security alerts.</p></div></div>
        </section>
        <section id="how-it-works" className="landing-how">
          <div className="section-heading reveal-on-scroll"><span className="section-kicker">SIMPLE BY DESIGN</span><h2>Security built into every step.</h2><p>From upload to download, each step is designed to protect your files and surface integrity issues.</p></div>
          <div className="landing-steps">
            <article className="landing-step reveal-on-scroll"><span className="step-number">01</span><div className="step-icon"><Icon name="user" /></div><h3>Create your account</h3><p>Register and verify your email to access your personal vault.</p></article>
            <article className="landing-step reveal-on-scroll"><span className="step-number">02</span><div className="step-icon"><Icon name="upload" /></div><h3>Upload securely</h3><p>Your file is encrypted before it is written to storage.</p></article>
            <article className="landing-step reveal-on-scroll"><span className="step-number">03</span><div className="step-icon"><Icon name="activity" /></div><h3>Verify integrity</h3><p>Run scans and review security events to identify potential tampering.</p></article>
            <article className="landing-step reveal-on-scroll"><span className="step-number">04</span><div className="step-icon"><Icon name="download" /></div><h3>Download with checks</h3><p>Integrity is checked before the application delivers your file.</p></article>
          </div>
        </section>
        <section className="landing-bottom-cta reveal-on-scroll"><div><span className="section-kicker">YOUR FILES, IN YOUR CONTROL</span><h2>Make secure storage your default.</h2><p>Start using your personal tamper-aware vault.</p></div><Link className="btn btn-primary btn-large" to="/register">Get started <Icon name="arrow" /></Link></section>
      </main>
      <footer className="foot landing-footer">{APP_NAME} · Tamper-Aware Secure File Management System</footer>
    </div>
  );
}
