export type TokenType = {
  access_token: string
  refresh_token: string
}

export type TJwtPayload = {
  sub: number
  email: string
}
