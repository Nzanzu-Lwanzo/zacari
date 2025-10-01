import { registerAs } from '@nestjs/config';

export default registerAs('jwt', () => ({
  defaultSecret: process.env.JWT_DEFAULT_SECRET,
  tempAtSecret: process.env.TEMPORARY_TOKEN_SECRET,
  tempAtExp: process.env.TEMP_AT_EXP
    ? parseInt(process.env.TEMP_AT_EXP)
    : undefined,
  rtSecret: process.env.RT_SECRET,
  rtExp: process.env.RT_EXP ? parseInt(process.env.RT_EXP) : undefined,
  atSecret: process.env.AT_SECRET,
  atExp: process.env.AT_EXP ? parseInt(process.env.AT_EXP) : undefined,
}));
