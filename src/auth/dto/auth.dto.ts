import { IsEmail, IsNotEmpty, IsString } from 'class-validator'

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
