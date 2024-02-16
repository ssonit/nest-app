import { ApiProperty } from '@nestjs/swagger'
import { IsEmail, IsNotEmpty, IsString, MinLength } from 'class-validator'

export class AuthRegisterDto {
  @ApiProperty()
  @IsEmail()
  @IsNotEmpty()
  email: string

  @ApiProperty()
  @IsString()
  @IsNotEmpty()
  password: string

  @ApiProperty()
  @IsString()
  @IsNotEmpty()
  username: string
}

export class AuthLoginDto {
  @ApiProperty()
  @IsEmail()
  @IsNotEmpty()
  email: string

  @ApiProperty()
  @IsString()
  @IsNotEmpty()
  password: string
}

export class ResetPasswordDto {
  @ApiProperty()
  @IsString()
  @IsNotEmpty()
  forgot_verify_token: string

  @ApiProperty()
  @IsString()
  @IsNotEmpty()
  @MinLength(6)
  password: string
}

export class JwtRefreshPayloadDto {
  @ApiProperty()
  @IsNotEmpty()
  sub: number

  @ApiProperty()
  @IsString()
  @IsNotEmpty()
  email: string
}
export class RefreshTokenDto {
  @ApiProperty()
  @IsString()
  @IsNotEmpty()
  refresh_token: string
}
