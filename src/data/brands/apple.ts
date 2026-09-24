import type { ProtectedBrand } from './types.js';

/**
 * icloud.com, me.com and mac.com are deliberately NOT listed: anybody with an
 * Apple ID has an address there, so "Apple Support" <someone@icloud.com> must
 * be judged, not exempted. Apple's own notices come from apple.com
 * (id.apple.com, email.apple.com, insideapple.apple.com).
 */
export const apple = {
  id: 'apple',
  name: 'Apple',
  phrases: [
    'app store',
    'apple account',
    'apple id',
    'apple pay',
    'apple support',
    'icloud',
    'itunes',
  ],
  domains: ['apple.com', 'itunes.com'],
} satisfies ProtectedBrand;
