import {
  createParamDecorator,
  ExecutionContext,
  UnauthorizedException,
} from '@nestjs/common';
import { Request } from 'express';
import { User } from 'src/lib/global.types';

export const GetUser = createParamDecorator(
  (data: keyof User, context: ExecutionContext) => {
    const request = context.switchToHttp().getRequest() as Request;
    if (!request.user) throw new UnauthorizedException('No user authenticated');
    if (!data) return request.user;
    return request.user[data];
  },
);
