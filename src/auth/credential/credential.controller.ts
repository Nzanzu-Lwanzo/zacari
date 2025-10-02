import {
  BadRequestException,
  Body,
  Controller,
  Get,
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
  SendSMSMedium,
  SendSMSMediumType,
} from '../lib/@types';
import { UpdateCredentialsDto } from './dtos/update.dto';

@Controller('auth')
export class CredentialController {
  constructor(private readonly service: CredentialService) {}

  /**
   * Initiate the sign up process. Will send a confirmation email to the user.
   */
  @Post('/sign-up')
  @SkipAtCheck()
  async createAccount(@Body(ValidateDtoPipe) dto: CreateAccountDto) {
    return await this.service.createAccount(dto);
  }

  /**
   * Confirm :
   *  - Account creation : in case user signed up
   *  - Account deletion : in case user deleted their account
   */
  @Get('/confirm')
  @SkipAtCheck()
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
   * Initiate the log in process. Will send an OTP SMS to the user.
   */
  @Post('/log-in')
  @SkipAtCheck()
  async logIn(@Body(ValidateDtoPipe) dto: CredentialsDto, @Ip() ip: string) {
    return await this.service.logIn(dto, ip);
  }

  /**
   * Validate the OTP and grant the user all the due authentication tokens.
   */
  @Post('/validate')
  @SkipAtCheck()
  @UseGuards(TempAtGuard)
  async validateOTP(
    @Body(ValidateDtoPipe) dto: ValidateOtpDto,
    @GetUser() user: User,
    @Ip() ip: string,
  ) {
    return await this.service.validateOTP(dto, user, ip);
  }

  /**
   * Resend the OTP SMS or the confirmation email.
   */
  @Get('/resend')
  @SkipAtCheck()
  @UseGuards(TempAtGuard)
  async resend(
    @Query('what', new ParseEnumPipe(ResendOptions)) what: ResendOptionsType,
    @GetUser() user: User,
    @Query('action', new ParseEnumPipe(ConfirmOptions, { optional: true }))
    action: ConfirmOptionsType,
  ) {
    if (what === 'confirm' && !action) {
      throw new BadRequestException('Missing query string');
    }
    return await this.service.resend(what, user, action);
  }

  /**
   * Log the user out.
   */
  @Get('/log-out')
  async logOut(@GetUser() user: User) {
    return await this.service.logOut(user);
  }

  /**
   * Initiate account deletion process. Will send a confirmation email to the user.
   */
  @Get('/delete')
  async deleteAccount(@GetUser() user: User) {
    return await this.service.deleteAccount(user);
  }

  /**
   * Initiate credentials update process. Will send OTP SMS or email.
   */
  @Get('/update')
  async initUpdate(
    @Query('medium', new ParseEnumPipe(SendSMSMedium))
    medium: SendSMSMediumType,
    @GetUser() user: User,
  ) {
    return await this.service.initUpdate(medium, user);
  }

  /**
   * Validate OTP and complete the credentials update.
   */
  @Patch('/update')
  @SkipAtCheck()
  @UseGuards(TempAtGuard)
  async completeUpdate(
    @Body(ValidateDtoPipe) dto: UpdateCredentialsDto,
    @GetUser() user: User,
  ) {
    return await this.service.completeUpdate(dto, user);
  }

  /**
   * Generate a fresh pair of authentication tokens.
   */
  @Get('/refresh')
  @SkipAtCheck()
  @UseGuards(RefreshTokenGuard)
  async refresh(@GetUser() user: User) {
    return await this.service.refresh(user);
  }
}
