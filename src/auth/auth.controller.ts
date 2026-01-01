import { AuthService } from './auth.service';
import { Controller, Post, Body, Get, Header, HttpCode } from '@nestjs/common';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) { }


}
