import { Module } from '@nestjs/common';
import { PrismaModule } from './prisma/prisma.module';
import { AuthModule } from './auth/auth.module';
import { HealthcheckModule } from './healthcheck/healthcheck.module';

@Module({
  imports: [AuthModule, PrismaModule, HealthcheckModule],
})
export class AppModule {}
