import { Controller, Get, Post, Put, Delete, Body, Query, Param, UseGuards, Request, Headers } from '@nestjs/common'
import { JwtAuthGuard } from 'src/auth/jwt-auth.guard'
import { UserService } from './user.service'

@Controller('users')
export class UserController {
  constructor(private userService: UserService) { }

  @Get()
  @UseGuards(JwtAuthGuard)
  async getAllUsers(@Query() query: any) {
    return this.userService.findAll(query)
  }
}
