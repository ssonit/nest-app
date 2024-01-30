import { Injectable } from '@nestjs/common'
import { ConfigService } from '@nestjs/config'
import { PassportStrategy } from '@nestjs/passport'
import { ExtractJwt, Strategy } from 'passport-jwt'
import { Request } from 'express'

@Injectable()
export class ForgotPasswordStrategy extends PassportStrategy(Strategy, 'jwt-forgot-password') {
  constructor(configService: ConfigService) {
    super({
      jwtFromRequest: ExtractJwt.fromBodyField('forgot_verify_token'),
      secretOrKey: configService.get('JWT_SECRET_FORGOT_PASSWORD_TOKEN'),
      passReqToCallback: true
    })
  }
  async validate(req: Request, payload: { sub: number; email: string }) {
    const forgot_verify_token = req.body['forgot_verify_token']
    return {
      forgot_verify_token,
      ...payload
    }
  }
}
