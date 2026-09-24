import type { ProtectedBrand } from './types.js';

/**
 * gmail.com and googlemail.com are deliberately NOT listed. Anybody can open an
 * address there, and a listed domain may wear the brand's name unchallenged:
 * with them in, "Google Security" <anyone@gmail.com> was waved through — one
 * of the commonest lures there is. Google's own notices come from google.com
 * and its subdomains (accounts.google.com, calendar-notification@google.com).
 */
export const google = {
  id: 'google',
  name: 'Google',
  phrases: [
    'gmail team',
    'google account',
    'google cloud',
    'google docs',
    'google drive',
    'google pay',
    'google play',
    'google security',
    'google support',
    'google team',
    'google workspace',
  ],
  domains: [
    'google.ca',
    'google.co.in',
    'google.co.uk',
    'google.com',
    'google.com.au',
    'google.de',
    'google.fr',
    'withgoogle.com',
    'youtube.com',
  ],
} satisfies ProtectedBrand;
