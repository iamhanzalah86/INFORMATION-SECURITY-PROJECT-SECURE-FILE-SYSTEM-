import Icon from './Icon';

/** Moon in light mode, sun in dark mode (swapped by CSS, so it follows the theme instantly). */
export default function ThemeIcon() {
  return (
    <span className="theme-ico" aria-hidden="true">
      <span className="when-light"><Icon name="moon" /></span>
      <span className="when-dark"><Icon name="sun" /></span>
    </span>
  );
}
