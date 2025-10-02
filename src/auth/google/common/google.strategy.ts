import {
  ConflictException,
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { Request } from 'express';
import { Strategy, Profile, VerifyCallback } from 'passport-google-oauth20';
import { UserService } from 'src/api/user/user.service';
import { SegmentType } from 'src/auth/lib/@types';
import { API_ORIGIN } from 'src/lib/constants';
import { PayloadType } from 'src/lib/global.types';
import { getUserFromGoogleProfile } from 'src/lib/helpers';
import { TokenService } from 'src/services/token/token.service';

@Injectable()
export class GoogleStrategy extends PassportStrategy(Strategy, 'google') {
  constructor(
    private readonly config: ConfigService,
    private readonly user_service: UserService,
    private readonly token_service: TokenService,
  ) {
    super({
      clientID: config.getOrThrow('google.clientID'),
      clientSecret: config.getOrThrow('google.clientSecret'),
      callbackURL: `${API_ORIGIN}/auth/google/callback`,
      scope: 'profile email',
      passReqToCallback: true,
    });
  }

  async validate(
    request: Request,
    at: string,
    rt: string,
    profile: Profile,
    done: VerifyCallback,
  ) {
    let segment = request['AUTH_SEGMENT'] as SegmentType;
    let payload: PayloadType;

    switch (segment) {
      case 'log-in': {
        payload = await this.logIn(profile);
        break;
      }

      case 'sign-up': {
        payload = await this.signUp(profile);
        break;
      }
    }

    if (!payload) throw new UnauthorizedException('Authentication failed');

    const tokens = await this.token_service.getAuthTokens(payload);
    await this.user_service.saveRt(payload.id, tokens.rt);
    request['AUTH_TOKENS'] = tokens;

    // Populate request.user -> @GetUser()
    done(null, payload);
  }

  async logIn(profile: Profile) {
    const user = await this.user_service.getOAuthUser('google', profile.id);
    if (!user) throw new NotFoundException('User not found');
    return user;
  }

  async signUp(profile: Profile) {
    const user = await getUserFromGoogleProfile(profile);
    const exists = await this.user_service.getOAuthUser('google', profile.id);
    if (exists) throw new ConflictException('Account exists');
    return await this.user_service.createOAuthUser(user, 'google', profile.id);
  }
}
