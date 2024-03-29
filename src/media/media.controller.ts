import {
  Post,
  UseInterceptors,
  UploadedFile,
  Controller,
  UploadedFiles,
  Get,
  Body,
  Query,
  Put,
  Delete
} from '@nestjs/common'
import { FileInterceptor, FilesInterceptor } from '@nestjs/platform-express'
import { MediaService } from './media.service'
import { ApiBearerAuth, ApiTags } from '@nestjs/swagger'

@ApiBearerAuth()
@ApiTags('Media')
@Controller('media')
export class MediaController {
  constructor(private readonly mediaService: MediaService) {}
  // get link of private file
  @Get('access')
  async getLinkAccess(@Query('key') key: string) {
    const url = await this.mediaService.getLinkMediaKey(key)
    return {
      url: url
    }
  }

  @Get('send-media')
  async getMedia(@Query('key') key: string) {
    const url = await this.mediaService.sendFileFromS3(key)
    return {
      url: url
    }
  }

  // upload single file
  @Post('upload')
  @UseInterceptors(FileInterceptor('file'))
  async upload(@UploadedFile() file: Express.Multer.File) {
    return this.mediaService.upload(file)
  }

  @Post('uploads')
  @UseInterceptors(FilesInterceptor('files'))
  async uploads(@UploadedFiles() files: Express.Multer.File[]) {
    return this.mediaService.uploadFiles(files)
  }

  // update permission: public-read
  @Put('update-acl')
  async updateAcl(@Body('media_id') media_id: number) {
    return await this.mediaService.updateACL(media_id)
  }

  @Delete('delete')
  async delete(@Query('media_id') media_id: number) {
    return this.mediaService.deleteFileS3(Number(media_id))
  }
}
