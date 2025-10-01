import { ExecutionContext, Injectable } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { SKIP_AT_KEY } from '../decorators/skip-at.decorator';
import { AuthGuard } from '@nestjs/passport';

@Injectable()
export class AccessTokenGuard extends AuthGuard('access-token') {
  constructor(private readonly reflector: Reflector) {
    super();
  }

  canActivate(context: ExecutionContext) {
    const skip = this.reflector.getAllAndOverride<boolean>(SKIP_AT_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);

    if (skip) return true;

    return super.canActivate(context);
  }
}
