import html
import os
from urllib.parse import urlparse

import requests


class EmailDeliveryError(RuntimeError):
    """Raised when the configured transactional email API cannot deliver mail."""


def _required(name):
    value = os.environ.get(name, '').strip()
    if not value:
        raise EmailDeliveryError(f'{name} is not configured')
    return value


def _api_url():
    value = os.environ.get('EMAIL_API_URL', 'https://api.brevo.com/v3/smtp/email').strip()
    try:
        parsed = urlparse(value)
        port = parsed.port
    except ValueError as error:
        raise EmailDeliveryError('EMAIL_API_URL must be a valid HTTPS URL') from error
    if parsed.scheme != 'https' or port not in (None, 443):
        raise EmailDeliveryError('EMAIL_API_URL must use HTTPS on port 443')
    return value


def _sender():
    # EMAIL_FROM must exactly match a verified Brevo Sender; Gmail-style addresses are allowed.
    address = _required('EMAIL_FROM')
    name = os.environ.get('EMAIL_FROM_NAME', '').strip()
    sender = {'email': address}
    if name:
        sender['name'] = name
    return sender


def send_otp_email(email, otp, purpose):
    action = 'complete your signup' if purpose == 'signup' else 'reset your password'
    action_html = html.escape(action)
    code_html = html.escape(str(otp))
    payload = {
        'sender': _sender(),
        'to': [{'email': email}],
        'subject': 'Authentication verification code',
        'textContent': f'Your code to {action} is {otp}. It expires in 10 minutes.',
        'htmlContent': (
            f'<p>Your code to {action_html} is '
            f'<strong>{code_html}</strong>. It expires in 10 minutes.</p>'
        ),
    }

    try:
        response = requests.post(
            _api_url(),
            headers={
                'api-key': _required('EMAIL_API_KEY'),
                'accept': 'application/json',
                'content-type': 'application/json',
            },
            json=payload,
            timeout=10,
        )
    except requests.RequestException as error:
        raise EmailDeliveryError('Email provider request failed') from error

    if response.status_code == 429:
        raise EmailDeliveryError('Email provider rate limit reached')
    if not 200 <= response.status_code < 300:
        raise EmailDeliveryError('Email provider rejected the message')

    try:
        response_data = response.json()
    except ValueError as error:
        raise EmailDeliveryError('Email provider returned an invalid response') from error
    if not isinstance(response_data, dict) or not response_data.get('messageId'):
        raise EmailDeliveryError('Email provider did not confirm the message')
