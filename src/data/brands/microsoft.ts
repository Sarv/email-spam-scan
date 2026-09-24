import type { ProtectedBrand } from './types.js';

/**
 * hotmail.com, live.com, msn.com and outlook.com are deliberately NOT listed.
 * They are free mailbox hosts: anybody can register "Microsoft account team"
 * <someone@outlook.com>, and with them in the list that sender was exempt from
 * the very rule written for it. Microsoft's own account and billing notices
 * come from microsoft.com and its service domains below.
 */
export const microsoft = {
  id: 'microsoft',
  name: 'Microsoft',
  phrases: [
    'microsoft 365',
    'microsoft account',
    'microsoft azure',
    'microsoft online',
    'microsoft outlook',
    'microsoft security',
    'microsoft support',
    'microsoft teams',
    'office 365',
    'office365',
    'onedrive',
    'outlook team',
    'sharepoint',
  ],
  domains: [
    'azure.com',
    'azurecomm.net',
    'microsoft.com',
    'microsoft365.com',
    'microsoftonline.com',
    'microsoftsupport.com',
    'office.com',
    'office365.com',
    'onedrive.com',
    'sharepoint.com',
    'skype.com',
    'windows.com',
  ],
} satisfies ProtectedBrand;
