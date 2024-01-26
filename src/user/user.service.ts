import { Injectable, NotFoundException } from '@nestjs/common'
import { PrismaService } from 'src/prisma/prisma.service'

@Injectable()
export class UserService {
  constructor(private prismaService: PrismaService) {}
  async getUser(id: number) {
    try {
      const user = await this.prismaService.user.findUnique({
        where: {
          id
        }
      })
      if (!user) {
        throw new NotFoundException('User not found')
      }
      return user
    } catch (error) {
      return error
    }
  }
}
