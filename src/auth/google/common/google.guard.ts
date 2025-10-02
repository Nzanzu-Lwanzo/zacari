import { ExecutionContext, Injectable } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { Request } from 'express';
import { Segments, SegmentType } from 'src/auth/lib/@types';

@Injectable()
export class GoogleGuard extends AuthGuard('google') {
  static url: string = '';

  getRequest(context: ExecutionContext) {
    const request = context.switchToHttp().getRequest() as Request;
    const url = request.url.split('/').at(-1) as SegmentType;

    if (Segments.includes(url)) {
      GoogleGuard.url = url;
    }

    request['AUTH_SEGMENT'] = GoogleGuard.url;

    return request;
  }
}
