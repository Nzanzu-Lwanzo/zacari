import { Module } from '@nestjs/common';
import { GoogleController } from './google.controller';
import { GoogleGuard } from './common/google.guard';
import { GoogleStrategy } from './common/google.strategy';
import { UserModule } from 'src/api/user/user.module';
import { TokenModule } from 'src/services/token/token.module';

@Module({
  providers: [GoogleGuard, GoogleStrategy],
  controllers: [GoogleController],
  imports: [UserModule, TokenModule],
})
export class GoogleModule {}
