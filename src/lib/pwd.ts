import { compare, hash } from 'bcryptjs';

export async function hashPwd(plain: string) {
  return await hash(plain, 10);
}

export async function checkPwdMatch(pwdHash: string, plain: string) {
  return await compare(plain, pwdHash);
}