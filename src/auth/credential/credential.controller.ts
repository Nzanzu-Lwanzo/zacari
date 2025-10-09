import {
  BadRequestException,
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Ip,
  ParseEnumPipe,
  Patch,
  Post,
  Query,
  UseGuards,
} from '@nestjs/common';
import { CredentialService } from './credential.service';
import { CreateAccountDto } from './dtos/create.dto';
import { ValidateDtoPipe } from 'src/lib/pipes/validate-dtos.pipe';
import { CredentialsDto } from './dtos/credentials.dto';
import { ValidateOtpDto } from './dtos/otp.dto';
import { TempAtGuard } from './common/guards/temp-token.guard';
import { GetUser } from './common/decorators/user.decorator';
import { User } from 'src/lib/global.types';
import { SkipAtCheck } from './common/decorators/skip-at.decorator';
import { RefreshTokenGuard } from './common/guards/refresh-token.guard';
import {
  ConfirmOptions,
  ConfirmOptionsType,
  ResendOptions,
  ResendOptionsType,
  SendOTPMedium,
  SendOTPMediumType,
} from '../lib/@types';
import { UpdateCredentialsDto } from './dtos/update.dto';
import CredentialAuthDoc from './lib/credential.doc';

@Controller('auth')
export class CredentialController {
  constructor(private readonly service: CredentialService) {}

  /**
   * Initiate the sign up procedure.
   */
  @Post('/sign-up')
  @SkipAtCheck()
  @HttpCode(HttpStatus.CREATED)
  @CredentialAuthDoc.createAccount()
  async createAccount(@Body(ValidateDtoPipe) dto: CreateAccountDto) {
    const { at } = await this.service.createAccount(dto);
    return at;
  }

  /**
   * Confirm :
   *  - Account creation : in case user signed up
   *  - Account deletion : in case user deleted their account
   */
  @Get('/confirm')
  @SkipAtCheck()
  @CredentialAuthDoc.confirm()
  async confirm(
    @Query('token') token: string,
    @Query('action', new ParseEnumPipe(ConfirmOptions))
    action: ConfirmOptionsType,
  ) {
    switch (action) {
      case 'creation': {
        return await this.service.confirmAccountCreation(token);
      }
      case 'deletion': {
        return await this.service.confirmAccountDeletion(token);
      }
    }
  }

  /**
   * Initiate the log in procedure.
   */
  @Post('/log-in')
  @SkipAtCheck()
  @HttpCode(HttpStatus.OK)
  @CredentialAuthDoc.logIn()
  async logIn(@Body(ValidateDtoPipe) dto: CredentialsDto, @Ip() ip: string) {
    const { at } = await this.service.logIn(dto, ip);
    return at;
  }

  /**
   * Validate the OTP and grant access & refresh tokens.
   */
  @Post('/validate')
  @SkipAtCheck()
  @HttpCode(HttpStatus.OK)
  @UseGuards(TempAtGuard)
  @CredentialAuthDoc.validateOTP()
  async validateOTP(
    @Body(ValidateDtoPipe) dto: ValidateOtpDto,
    @GetUser() user: User,
    @Ip() ip: string,
  ) {
    return await this.service.validateOTP(dto, user, ip);
  }

  /**
   * Resend the OTP or the confirmation link.
   */
  @Get('/resend')
  @SkipAtCheck()
  @UseGuards(TempAtGuard)
  @CredentialAuthDoc.resend()
  async resend(
    @Query('what', new ParseEnumPipe(ResendOptions)) what: ResendOptionsType,
    @GetUser() user: User,
    @Query('action', new ParseEnumPipe(ConfirmOptions, { optional: true }))
    action: ConfirmOptionsType,
  ) {
    if (what === 'confirm' && !action) {
      throw new BadRequestException('Missing query string');
    }
    const { at } = await this.service.resend(what, user, action);
    return at;
  }

  /**
   * Log the user out.
   */
  @Get('/log-out')
  @CredentialAuthDoc.logOut()
  async logOut(@GetUser() user: User) {
    return await this.service.logOut(user);
  }

  /**
   * Initiate account deletion procedure.
   */
  @Get('/delete')
  @CredentialAuthDoc.deleteAccount()
  async deleteAccount(@GetUser() user: User) {
    const { at } = await this.service.deleteAccount(user);
    return at;
  }

  /**
   * Initiate credentials update procedure.
   */
  @Get('/update')
  @CredentialAuthDoc.initUpdate()
  async initUpdate(
    @Query('medium', new ParseEnumPipe(SendOTPMedium))
    medium: SendOTPMediumType,
    @GetUser() user: User,
  ) {
    const { at } = await this.service.initUpdate(medium, user);
    return at;
  }

  /**
   * Validate OTP and complete the credentials update.
   */
  @Patch('/update')
  @SkipAtCheck()
  @UseGuards(TempAtGuard)
  @CredentialAuthDoc.completeUpdate()
  async completeUpdate(
    @Body(ValidateDtoPipe) dto: UpdateCredentialsDto,
    @GetUser() user: User,
  ) {
    return await this.service.completeUpdate(dto, user);
  }

  /**
   * Tokens rotation.
   */
  @Get('/refresh')
  @SkipAtCheck()
  @UseGuards(RefreshTokenGuard)
  @CredentialAuthDoc.refresh()
  async refresh(@GetUser() user: User) {
    return await this.service.refresh(user);
  }
}
