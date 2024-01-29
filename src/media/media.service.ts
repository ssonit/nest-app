import {
  DeleteObjectCommand,
  GetObjectCommand,
  PutObjectAclCommand,
  PutObjectCommand,
  S3Client
} from '@aws-sdk/client-s3'
import { Upload } from '@aws-sdk/lib-storage'
import { getSignedUrl } from '@aws-sdk/s3-request-presigner'
import { Injectable, NotFoundException } from '@nestjs/common'
import { ConfigService } from '@nestjs/config'
import { PrismaService } from 'src/prisma/prisma.service'
import { v4 as uuidv4 } from 'uuid'

// @aws-sdk/lib-storage

@Injectable()
export class MediaService {
  private readonly region: string
  private readonly accessKeyId: string
  private readonly secretAccessKey: string
  private readonly publicBucketName: string
  private readonly s3Client: S3Client

  constructor(
    private configService: ConfigService,
    private prismaService: PrismaService
  ) {
    this.region = this.configService.get('AWS_REGION')
    this.accessKeyId = this.configService.get('AWS_ACCESS_KEY_ID')
    this.secretAccessKey = this.configService.get('AWS_SECRET_ACCESS_KEY')
    this.publicBucketName = this.configService.get('AWS_PUBLIC_BUCKET_NAME')
    this.s3Client = new S3Client({
      region: this.region,
      credentials: {
        accessKeyId: this.accessKeyId,
        secretAccessKey: this.secretAccessKey
      }
    })
  }

  async getLinkMediaKey(media_key: string) {
    try {
      const command = new GetObjectCommand({
        Bucket: this.publicBucketName,
        Key: media_key
      })
      const url = await getSignedUrl(this.s3Client, command, {
        expiresIn: 60 * 60 * 12
      })

      return url
    } catch (error) {
      return error
    }
  }

  async updateACL(media_id: number) {
    try {
      const media = await this.prismaService.media.findUnique({
        where: {
          id: media_id
        }
      })

      await this.s3Client.send(
        new PutObjectAclCommand({
          Bucket: this.publicBucketName,
          Key: media.key,
          ACL: 'public-read'
        })
      )

      return `https://${this.publicBucketName}.s3.${this.region}.amazonaws.com/${media.key}`
    } catch (error) {
      return error
    }
  }

  async sendFileFromS3(media_key: string) {
    return `https://${this.publicBucketName}.s3.${this.region}.amazonaws.com/${media_key}`
  }

  async upload(file: Express.Multer.File) {
    const id = uuidv4()
    const arr_name = file.originalname.split('.')
    const extension = arr_name.pop()
    const name = arr_name.join('.')
    const key = id + '/' + this.slug(name) + '.' + extension
    const data = {
      name,
      file_name: String(file.originalname),
      mime_type: file.mimetype,
      size: file.size,
      key
    }

    try {
      // await this.uploadS3(file.buffer, key, file.mimetype)

      const [new_media] = await Promise.all([
        this.prismaService.media.create({
          data
        }),
        this.uploadLibStorage(file.buffer, key, file.mimetype)
      ])

      return new_media
    } catch (error) {
      return error
    }
  }

  async uploadFiles(files: Express.Multer.File[]) {
    try {
      const result = await Promise.all(
        files.map(async (file) => {
          const media = await this.upload(file)

          return media
        })
      )

      return result
    } catch (error) {
      return error
    }
  }

  async deleteFileS3(media_id: number) {
    try {
      const media = await this.prismaService.media.findUnique({
        where: {
          id: media_id
        }
      })

      if (!media) throw new NotFoundException('Media not found')

      await Promise.all([
        this.prismaService.media.delete({
          where: {
            id: media_id
          }
        }),
        this.s3Client.send(
          new DeleteObjectCommand({
            Bucket: this.publicBucketName,
            Key: media.key
          })
        )
      ])

      return true
    } catch (error) {
      return error
    }
  }

  private async uploadS3(file_buffer: Buffer, key: string, content_type: string) {
    await this.s3Client.send(
      new PutObjectCommand({
        Bucket: this.publicBucketName,
        Key: key,
        Body: file_buffer,
        ContentType: content_type
      })
    )
  }

  private async uploadLibStorage(file_buffer: Buffer, key: string, content_type: string) {
    try {
      const parallelUploads3 = new Upload({
        client: this.s3Client,
        params: {
          Bucket: this.publicBucketName,
          Key: key,
          Body: file_buffer,
          ContentType: content_type
        },
        tags: [
          /*...*/
        ], // optional tags
        queueSize: 4, // optional concurrency configuration
        partSize: 1024 * 1024 * 5, // optional size of each part, in bytes, at least 5MB
        leavePartsOnError: false // optional manually handle dropped parts
      })

      // parallelUploads3.on('httpUploadProgress', (progress) => {
      //   console.log(progress)
      // })

      await parallelUploads3.done()
    } catch (e) {
      console.log(e)
    }
  }

  private slug(str: string) {
    str = str.replace(/^\s+|\s+$/g, '') // trim
    str = str.toLowerCase()

    // remove accents, swap ñ for n, etc
    const from =
      'ÁÄÂÀÃÅČÇĆĎÉĚËÈÊẼĔȆĞÍÌÎÏİŇÑÓÖÒÔÕØŘŔŠŞŤÚŮÜÙÛÝŸŽáäâàãåčçćďéěëèêẽĕȇğíìîïıňñóöòôõøðřŕšşťúůüùûýÿžþÞĐđßÆa·/_,:;'
    const to =
      'AAAAAACCCDEEEEEEEEGIIIIINNOOOOOORRSSTUUUUUYYZaaaaaacccdeeeeeeeegiiiiinnooooooorrsstuuuuuyyzbBDdBAa------'
    for (let i = 0, l = from.length; i < l; i++) {
      str = str.replace(new RegExp(from.charAt(i), 'g'), to.charAt(i))
    }

    str = str
      .replace(/[^a-z0-9 -]/g, '') // remove invalid chars
      .replace(/\s+/g, '-') // collapse whitespace and replace by -
      .replace(/-+/g, '-') // collapse dashes

    return str
  }
}
