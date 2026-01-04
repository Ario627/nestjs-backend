import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';

import { AuthModule } from './auth/auth.module';
import { TypeOrmModule } from '@nestjs/typeorm';

@Module({
  imports: [
    TypeOrmModule.forRoot({
      type: 'postgres',
      host: process.env.DATABASE_HOST || 'localhost',
      port: Number(process.env.DATABASE_PORT ?? 5432),
      username: process.env.DATABASE_USER || 'vulnlab',
      password: process.env.DATABASE_PASSWORD || 'vulnlab123',
      database: process.env.DATABASE_NAME || 'arioolnn',
      autoLoadEntities: true,
      synchronize: true,
      logging: true,
    }),
    JwtModule.register({
      global: true,
      secret: process.env.JWT_SECRET || 'secret123',
      signOptions: {},
    }),

    AuthModule,
  ],
})

export class AppModule { }
