export const SESSION_SECONDS = 7 * 24 * 60 * 60;
export const TOKEN_PATTERN = /^[a-f0-9]{64}$/;

export const SECURITY_HEADERS = {
  'Cache-Control': 'no-store',
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'same-origin',
  'Content-Security-Policy': "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; img-src https: http:; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
};
