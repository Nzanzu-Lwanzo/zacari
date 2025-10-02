import { Profile } from 'passport-google-oauth20';
import { CreateAccountDto } from 'src/auth/credential/dtos/create.dto';
import { hashPwd } from './pwd';
import { DEFAULT_PHONE_NUMBE } from './constants';

export const getUserFromGoogleProfile = async (
  profile: Profile,
): Promise<CreateAccountDto> => {
  let email = profile.emails![0].value;
  let name = email.split('@').at(0)?.replace(/\./gi, '-');
  return {
    email,
    name: name || profile.displayName,
    password: await hashPwd(Math.random().toString(36).slice(2, 20)),
    phone: DEFAULT_PHONE_NUMBE,
  };
};
