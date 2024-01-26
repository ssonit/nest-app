import { Body, Controller, HttpCode, HttpStatus, Post, UseGuards } from '@nestjs/common'
import { AuthService } from './auth.service'
import { AuthLoginDto, AuthRegisterDto } from './dto/auth.dto'
import { AuthGuard } from '@nestjs/passport'
import { GetUser } from './decorator'

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
  refreshToken(@GetUser() user) {
    return this.authService.refreshToken(user, user.refresh_token)
  }

  @Post('logout')
  @UseGuards(AuthGuard('jwt'))
  @HttpCode(HttpStatus.OK)
  logout(@Body('refresh_token') refresh_token: string) {
    return this.authService.logout(refresh_token)
  }

  // forgot password
}
