import { Link } from 'react-router-dom';
import Icon from './Icon';
import { APP_NAME } from '../config';

export default function Brand({ to, className = 'brand' }) {
  return (
    <Link className={className} to={to}>
      <span className="brand-mark"><Icon name="shield" /></span>{APP_NAME}
    </Link>
  );
}
