from werkzeug.security import check_password_hash, generate_password_hash


def hash_password(value):
    return generate_password_hash(value)


def verify_password(hashed, value):
    return bool(hashed) and check_password_hash(hashed, value)
