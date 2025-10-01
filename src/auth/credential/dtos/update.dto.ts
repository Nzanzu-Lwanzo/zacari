import { IsNotEmpty, IsString, MaxLength } from 'class-validator';
import { CredentialsDto } from './credentials.dto';
import { PartialType } from '@nestjs/mapped-types';

export class UpdateCredentialsDto extends PartialType(CredentialsDto) {
  @IsString({ message: 'code must be a string' })
  @MaxLength(6, { message: 'code max length is 6' })
  @IsNotEmpty({ message: 'code cannot be empty' })
  otp: string;
}