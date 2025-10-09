export type ResendOptionsType = 'confirm' | 'otp';
export const ResendOptions: ResendOptionsType[] = ['otp', 'confirm'];

export type ConfirmOptionsType = 'creation' | 'deletion';
export const ConfirmOptions: ConfirmOptionsType[] = ['creation', 'deletion'];

export type SendOTPMediumType = 'email' | 'sms';
export const SendOTPMedium: SendOTPMediumType[] = ['email', 'sms'];

export type SegmentType = 'log-in' | 'sign-up';
export const Segments: SegmentType[] = ['log-in', 'sign-up'];
