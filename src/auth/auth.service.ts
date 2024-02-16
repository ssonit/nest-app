import { ForbiddenException, Injectable, NotFoundException, UnauthorizedException } from '@nestjs/common'
import { AuthLoginDto, AuthRegisterDto, JwtRefreshPayloadDto, RefreshTokenDto, ResetPasswordDto } from './dto'
import { PrismaService } from 'src/prisma/prisma.service'
import * as bcrypt from 'bcrypt'
import { JwtService } from '@nestjs/jwt'
import { ConfigService } from '@nestjs/config'

@Injectable()
export class AuthService {
  constructor(
    private configService: ConfigService,
    private prismaService: PrismaService,
    private jwtService: JwtService
  ) {}

  hashData(data: string) {
    const salt = bcrypt.genSaltSync(10)
    const hashed = bcrypt.hashSync(data, salt)
    return hashed
  }

  async generateToken({ id, email }) {
    const [access_token, refresh_token] = await Promise.all([
      this.jwtService.signAsync(
        {
          sub: id,
          email
        },
        {
          secret: this.configService.get('ACCESS_JWT_SECRET'),
          expiresIn: '30m'
        }
      ),
      this.jwtService.signAsync(
        {
          sub: id,
          email
        },
        {
          secret: this.configService.get('REFRESH_JWT_SECRET'),
          expiresIn: '1h'
        }
      )
    ])
    return { access_token, refresh_token }
  }

  async generateForgotPasswordToken({ id, email }) {
    return this.jwtService.signAsync(
      {
        sub: id,
        email
      },
      {
        secret: this.configService.get('JWT_SECRET_FORGOT_PASSWORD_TOKEN'),
        expiresIn: '1h'
      }
    )
  }

  async register(payload: AuthRegisterDto) {
    const hashedPassword = this.hashData(payload.password)

    try {
      const user = await this.prismaService.user.findUnique({
        where: {
          email: payload.email
        }
      })

      if (user) {
        throw new ForbiddenException('Email already exists')
      }

      const new_user = await this.prismaService.user.create({
        data: {
          email: payload.email,
          password: hashedPassword,
          username: payload.username
        }
      })

      const { access_token, refresh_token } = await this.generateToken({ id: new_user.id, email: new_user.email })

      await this.prismaService.refreshToken.create({
        data: {
          token: refresh_token,
          user: new_user.id
        }
      })

      return {
        message: 'Register successfully',
        data: {
          user: new_user,
          access_token,
          refresh_token
        }
      }
    } catch (error) {
      return error
    }
  }
  async login(payload: AuthLoginDto) {
    try {
      const user = await this.prismaService.user.findUnique({
        where: {
          email: payload.email
        }
      })

      if (!user) {
        throw new NotFoundException('Email not found')
      }

      const validPassword = await bcrypt.compare(payload.password, user.password)

      if (!validPassword) {
        throw new ForbiddenException('Email or password incorrect')
      }

      const { access_token, refresh_token } = await this.generateToken({ id: user.id, email: user.email })

      await this.prismaService.refreshToken.create({
        data: {
          token: refresh_token,
          user: user.id
        }
      })

      return {
        message: 'Login successfully',
        data: {
          user,
          access_token,
          refresh_token
        }
      }
    } catch (error) {
      return error
    }
  }

  async refreshToken({ refresh_token }: RefreshTokenDto) {
    try {
      const { sub, email } = (await this.jwtService.verifyAsync(refresh_token, {
        secret: this.configService.get('REFRESH_JWT_SECRET')
      })) as JwtRefreshPayloadDto

      const [{ access_token: new_access_token, refresh_token: new_refresh_token }] = await Promise.all([
        this.generateToken({ id: sub, email: email }),
        this.prismaService.refreshToken.delete({
          where: {
            token: refresh_token
          }
        })
      ])

      await this.prismaService.refreshToken.create({
        data: {
          user: sub,
          token: new_refresh_token
        }
      })

      return {
        message: 'Refresh token successfully',
        data: {
          access_token: new_access_token,
          refresh_token: new_refresh_token
        }
      }
    } catch (error) {
      return error
    }
  }

  async logout(refresh_token: string) {
    try {
      await this.prismaService.refreshToken.delete({
        where: {
          token: refresh_token
        }
      })
      return {
        message: 'Logged out'
      }
    } catch (error) {
      return error
    }
  }

  async forgotPassword(email: string) {
    try {
      const user = await this.prismaService.user.findUnique({
        where: {
          email
        }
      })

      if (!user) {
        throw new NotFoundException('Email not found')
      }

      const forgot_verify_token = await this.generateForgotPasswordToken({ id: user.id, email })

      console.log('Gửi email cho user', forgot_verify_token)

      await this.prismaService.user.update({
        where: {
          id: user.id
        },
        data: {
          forgot_verify_token
        }
      })
      return {
        message: 'Check email to reset password'
      }
    } catch (error) {
      return error
    }
  }

  async verifyForgotPassword({ forgot_verify_token, user_id }: { forgot_verify_token: string; user_id: number }) {
    try {
      const user = await this.prismaService.user.findUnique({
        where: {
          id: user_id
        }
      })
      if (!user) throw new NotFoundException('User not found')

      const token_valid = forgot_verify_token === user.forgot_verify_token

      if (!token_valid) throw new UnauthorizedException('Token not valid')

      return {
        message: 'Verify forgot token successfully'
      }
    } catch (error) {
      return error
    }
  }

  async resetPassword({ body, user_id }: { body: ResetPasswordDto; user_id: number }) {
    try {
      await this.prismaService.user.update({
        where: {
          id: user_id
        },
        data: {
          password: this.hashData(body.password),
          forgot_verify_token: ''
        }
      })

      return {
        message: 'Reset password successfully'
      }
    } catch (error) {
      return error
    }
  }
}
