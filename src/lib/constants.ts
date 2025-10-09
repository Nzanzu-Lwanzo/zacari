import { Role } from '@prisma/client';

// GLOBAL
export const API_ORIGIN = 'http://localhost:3000';

// CRYPTING
export const SALT_LENGTH = 16;
export const ITERATIONS = 10000;
export const KEY_LENGTH = 64;
export const DIGEST = 'sha512';

// AUTHENTICATION
export const MAX_LOGIN_ATTEMPTS = 5;
export const TIME_BEFORE_NEXT_LOGIN = 15;
export const TEMP_AT_EXP = 15;
export const RT_COOKIE = 'rt';
export const CONFIRM_TOKEN_EXP = 15;
export const OTP_EXP = 15;
export const TEMP_AT_AUD = 'tat';
export const AT_AUD = 'at';
export const RT_AUD = 'rt';

// DEFAULT
export const DEFAULT_PHONE_NUMBE = '000';

// ENUMS
export const USER_ROLES_ENUM_ARR: Role[] = ['client', 'admin'];
