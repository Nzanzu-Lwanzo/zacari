import { Module } from '@nestjs/common';
import { CredentialService } from './credential.service';
import { CredentialController } from './credential.controller';
import { PrismaModule } from 'src/services/prisma/prisma.module';
import { TokenModule } from 'src/services/token/token.module';
import { ContactModule } from 'src/services/contact/contact.module';
import { TempAtGuard } from './common/guards/temp-token.guard';
import { AccessTokenGuard } from './common/guards/access-token.guard';
import { RefreshTokenGuard } from './common/guards/refresh-token.guard';
import { AccessTokenStrategy } from './common/strategies/access-token';
import { RefreshTokenStrategy } from './common/strategies/refresh-token';

@Module({
  controllers: [CredentialController],
  providers: [
    CredentialService,
    AccessTokenStrategy,
    RefreshTokenStrategy,
    AccessTokenGuard,
    RefreshTokenGuard,
    TempAtGuard,
  ],
  imports: [PrismaModule, TokenModule, ContactModule],
})
export class CredentialModule {}
