import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { RequestMethod } from '@nestjs/common';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  // Prefix all the routes
  app.setGlobalPrefix('api', {
    exclude: [{ method: RequestMethod.ALL, path: '/auth/*path' }],
  });

  // Documentation
  const docBuilder = new DocumentBuilder();
  const doc = docBuilder
    .setTitle('Zacari  ')
    .setDescription('Official OpenAPI documentation')
    .setContact(
      'Nzanzu Lwanzo',
      'https://github.com/Nzanzu-Lwanzo',
      'nzanzu.lwanzo.work@gmail.com',
    )
    .build();
  const swagger = SwaggerModule.createDocument(app, doc);
  SwaggerModule.setup('/doc', app, swagger);
  // Run the server
  await app.listen(process.env.PORT ?? 3000);
}
bootstrap();
