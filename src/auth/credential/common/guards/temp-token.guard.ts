import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { type Request } from 'express';
import { ExtractJwt } from 'passport-jwt';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { User } from 'src/lib/global.types';
import { isExpired } from 'src/lib/datetime';
import { TEMP_AT_AUD } from 'src/lib/constants';

@Injectable()
export class TempAtGuard implements CanActivate {
  constructor(
    private readonly jwt: JwtService,
    private readonly config: ConfigService,
  ) {}

  async canActivate(context: ExecutionContext) {
    const request = context.switchToHttp().getRequest() as Request;
    const token = ExtractJwt.fromAuthHeaderAsBearerToken()(request);
    if (!token) return false;

    // Decode the token
    let user: User | undefined;
    try {
      user = (await this.jwt.verifyAsync(token, {
        secret: this.config.getOrThrow('jwt.tempAtSecret'),
        ignoreExpiration: false,
        ignoreNotBefore: false,
      })) as User;
    } catch {
      throw new UnauthorizedException('Invalid or corrupted token');
    }

    if (user.aud !== TEMP_AT_AUD) return false;
    if (!user) return false;

    // Has the token expired ?
    let expired = isExpired(new Date(user.exp));
    if (!expired) throw new UnauthorizedException('Expired token');

    // Save user on request and proceed
    request.user = user;
    return true;
  }
}
