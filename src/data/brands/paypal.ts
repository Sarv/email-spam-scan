import type { ProtectedBrand } from './types.js';

export const paypal = {
  id: 'paypal',
  name: 'PayPal',
  phrases: ['paypal'],
  domains: [
    'paypal-communication.com',
    'paypal-corp.com',
    'paypal.co.uk',
    'paypal.com',
    'paypal.de',
    'paypal.me',
    'paypalobjects.com',
  ],
} satisfies ProtectedBrand;
