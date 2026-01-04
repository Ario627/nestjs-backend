import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  app.enableCors({
    origin: '*',
    credentials: true,
  });

  app.use((req, res, next) => {
    res.setHeader('X-Powered-By', 'NestJS');
    res.setHeader('server', 'Archlinux');
    next();
  });

  await app.listen(3000);
  console.log('Running in http://localhost:3000')
}

bootstrap()
