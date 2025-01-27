import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe } from '@nestjs/common';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  //enable cors
  app.enableCors({
    origin: '*',
  });

  // Enable validation globally
  app.useGlobalPipes(
    new ValidationPipe({
      transform: true,
      whitelist: true,
    }),
  );

  const port = process.env.SERVER_PORT || 8001;
  await app.listen(port);
  if (process.env.ENVIRONMENT === 'LOCAL')
    console.log(`Auth API is running on port: ${port}`);
}
bootstrap();
