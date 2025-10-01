export type ResendOptionsType = 'confirm' | 'otp';
export const ResendOptions: ResendOptionsType[] = ['otp', 'confirm'];

export type ConfirmOptionsType = 'creation' | 'deletion';
export const ConfirmOptions: ConfirmOptionsType[] = ['creation', 'deletion'];

export type sendSMSMediumType = 'email' | 'sms';
export const sendSMSMedium: sendSMSMediumType[] = ['email', 'sms'];
