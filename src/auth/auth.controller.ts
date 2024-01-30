import { Body, Controller, HttpCode, HttpStatus, Post, UseGuards } from '@nestjs/common'
import { AuthService } from './auth.service'
import { AuthGuard } from '@nestjs/passport'
import { GetUser } from './decorator'
import { AuthLoginDto, AuthRegisterDto, ResetPasswordDto } from './dto'

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('register')
  @HttpCode(HttpStatus.CREATED)
  register(@Body() body: AuthRegisterDto) {
    return this.authService.register(body)
  }

  @Post('login')
  @HttpCode(HttpStatus.OK)
  login(@Body() body: AuthLoginDto) {
    return this.authService.login(body)
  }

  @Post('refresh-token')
  @UseGuards(AuthGuard('jwt-refresh'))
  @HttpCode(HttpStatus.OK)
  refreshToken(@GetUser() user: any) {
    return this.authService.refreshToken(user, user.refresh_token)
  }

  @Post('logout')
  @UseGuards(AuthGuard('jwt'))
  @HttpCode(HttpStatus.OK)
  logout(@Body('refresh_token') refresh_token: string) {
    return this.authService.logout(refresh_token)
  }

  @Post('forgot-password')
  @HttpCode(HttpStatus.OK)
  forgotPassword(@Body('email') email: string) {
    return this.authService.forgotPassword(email)
  }

  @Post('verify-forgot-password')
  @UseGuards(AuthGuard('jwt-forgot-password'))
  @HttpCode(HttpStatus.OK)
  verifyForgotPassword(@GetUser() user: any) {
    return this.authService.verifyForgotPassword({
      forgot_verify_token: user.forgot_verify_token,
      user_id: user.sub
    })
  }

  @Post('reset-password')
  @UseGuards(AuthGuard('jwt-forgot-password'))
  @HttpCode(HttpStatus.OK)
  resetPassword(@GetUser() user: any, @Body() body: ResetPasswordDto) {
    return this.authService.resetPassword({
      body,
      user_id: user.sub
    })
  }
}
