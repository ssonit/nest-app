import { ConfigModule } from '@nestjs/config'
import { Module } from '@nestjs/common'
import { MediaModule } from './media/media.module'
import { AuthModule } from './auth/auth.module'
import { PrismaModule } from './prisma/prisma.module'
import { UserModule } from './user/user.module'

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true
    }),
    PrismaModule,
    MediaModule,
    AuthModule,
    UserModule
  ]
})
export class AppModule {}
