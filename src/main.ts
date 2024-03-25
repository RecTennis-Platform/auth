import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  //enable cors
  app.enableCors({
    origin: `${process.env.FRONTEND_URL}`,
  });

  const port = process.env.SERVER_PORT || 8001;
  await app.listen(port);
  if (process.env.ENVIRONMENT === 'LOCAL')
    console.log(`Auth API is running on port: ${port}`);
}
bootstrap();
