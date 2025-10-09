import { Controller, Get, Req, UseGuards } from '@nestjs/common';
import { GoogleGuard } from './common/google.guard';
import { Request } from 'express';
import { SkipAtCheck } from '../credential/common/decorators/skip-at.decorator';
import GoogleAuthDoc from './lib/google.doc';
import { ApiExcludeEndpoint } from '@nestjs/swagger';

@Controller('/auth/google')
export class GoogleController {
  @Get('/sign-up')
  @SkipAtCheck()
  @UseGuards(GoogleGuard)
  @GoogleAuthDoc.signUp()
  async signUp() {
    return;
  }

  @Get('/log-in')
  @SkipAtCheck()
  @UseGuards(GoogleGuard)
  @GoogleAuthDoc.logIn()
  async logIn() {
    return;
  }

  @Get('/callback')
  @SkipAtCheck()
  @UseGuards(GoogleGuard)
  @ApiExcludeEndpoint()
  async callback(@Req() request: Request) {
    return request['AUTH_TOKENS'];
  }
}
