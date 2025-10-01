import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { RequestMethod } from '@nestjs/common';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  // Prefix all the routes
  app.setGlobalPrefix('api', {
    exclude: [{ method: RequestMethod.ALL, path: '/auth/*path' }],
  });

  // Run the server
  await app.listen(process.env.PORT ?? 3000);
}
bootstrap();
