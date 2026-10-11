from flask_bcrypt import Bcrypt

bcrypt = Bcrypt()

# bcrypt only uses the first 72 bytes of a password (and bcrypt>=5 raises
# an error above that), so we reject longer passwords up front.
MAX_PASSWORD_BYTES = 72


def hash_password(password):
    return bcrypt.generate_password_hash(password).decode("utf-8")


def verify_password(password_hash, password):
    if len(password.encode("utf-8")) > MAX_PASSWORD_BYTES:
        return False
    return bcrypt.check_password_hash(password_hash, password)
