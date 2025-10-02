import { Controller, Get, Req, UseGuards } from '@nestjs/common';
import { GoogleGuard } from './common/google.guard';
import { Request } from 'express';
import { SkipAtCheck } from '../credential/common/decorators/skip-at.decorator';

@Controller('/auth/google')
export class GoogleController {
  @Get('/sign-up')
  @SkipAtCheck()
  @UseGuards(GoogleGuard)
  async signUp() {
    return;
  }

  @Get('/log-in')
  @SkipAtCheck()
  @UseGuards(GoogleGuard)
  async logIn() {
    return;
  }

  @Get('/callback')
  @SkipAtCheck()
  @UseGuards(GoogleGuard)
  async callback(@Req() request: Request) {
    return request['AUTH_TOKENS'];
  }
}
