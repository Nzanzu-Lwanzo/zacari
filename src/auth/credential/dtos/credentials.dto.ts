import { PickType } from '@nestjs/mapped-types';
import { CreateAccountDto } from './create.dto';

export class CredentialsDto extends PickType(CreateAccountDto, [
  'email',
  'password',
]) {}
