import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { RT_AUD } from 'src/lib/constants';
import { PayloadType } from 'src/lib/global.types';

@Injectable()
export class RefreshTokenStrategy extends PassportStrategy(
  Strategy,
  'refresh-token',
) {
  constructor(private readonly config: ConfigService) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      secretOrKey: config.getOrThrow('jwt.rtSecret'),
      ignoreExpiration: false,
      audience: RT_AUD,
    });
  }

  validate(payload: PayloadType) {
    return payload;
  }
}
