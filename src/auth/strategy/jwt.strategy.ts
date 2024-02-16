import { Injectable } from '@nestjs/common'
import { ConfigService } from '@nestjs/config'
import { PassportStrategy } from '@nestjs/passport'
import { ExtractJwt, Strategy } from 'passport-jwt'
import { Request } from 'express'
import { JwtRefreshPayloadDto } from '../dto'

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy, 'jwt-refresh') {
  constructor(configService: ConfigService) {
    super({
      jwtFromRequest: ExtractJwt.fromBodyField('refresh_token'),
      secretOrKey: configService.get('REFRESH_JWT_SECRET'),
      passReqToCallback: true
    })
  }
  async validate(req: Request, payload: JwtRefreshPayloadDto) {
    const refresh_token = req.body['refresh_token']
    return {
      refresh_token,
      ...payload
    }
  }
}
