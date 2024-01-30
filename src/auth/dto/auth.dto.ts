import { IsEmail, IsNotEmpty, IsString, MinLength } from 'class-validator'

export class AuthRegisterDto {
  @IsEmail()
  @IsNotEmpty()
  email: string

  @IsString()
  @IsNotEmpty()
  password: string

  @IsString()
  @IsNotEmpty()
  username: string
}

export class AuthLoginDto {
  @IsEmail()
  @IsNotEmpty()
  email: string

  @IsString()
  @IsNotEmpty()
  password: string
}

export class ResetPasswordDto {
  @IsString()
  @IsNotEmpty()
  forgot_verify_token: string

  @IsString()
  @IsNotEmpty()
  @MinLength(6)
  password: string
}
