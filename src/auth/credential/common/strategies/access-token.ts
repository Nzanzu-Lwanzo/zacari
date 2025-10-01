import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { AT_AUD } from 'src/lib/constants';
import { PayloadType } from 'src/lib/global.types';

@Injectable()
export class AccessTokenStrategy extends PassportStrategy(
  Strategy,
  'access-token',
) {
  constructor(private readonly config: ConfigService) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      secretOrKey: config.getOrThrow('jwt.atSecret'),
      ignoreExpiration: false,
      audience: AT_AUD,
    });
  }

  async validate(payload: PayloadType) {
    console.log(payload, ' is the payload');
    return payload;
  }
}
