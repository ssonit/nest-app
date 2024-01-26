import { Injectable, UnauthorizedException } from '@nestjs/common'
import { ConfigService } from '@nestjs/config'
import { PassportStrategy } from '@nestjs/passport'
import { ExtractJwt, Strategy } from 'passport-jwt'
import { UserService } from '../../user/user.service'

@Injectable()
export class AtStrategy extends PassportStrategy(Strategy, 'jwt') {
  constructor(
    configService: ConfigService,
    private userService: UserService
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      secretOrKey: configService.get('ACCESS_JWT_SECRET')
    })
  }
  async validate(payload: { sub: number; email: string }) {
    const user = await this.userService.getUser(payload.sub)
    if (!user) {
      throw new UnauthorizedException()
    }
    return user
  }
}
