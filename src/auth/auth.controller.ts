import { AuthService } from './auth.service';
import { Controller, Post, Body, Get, Headers, HttpCode } from '@nestjs/common';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) { }

  @Post('register')
  async register(@Body() body: any) {
    return this.authService.register(body)
  }

  @Post('login')
  @HttpCode(200)
  async login(@Body() body: { username: string; password: string }) {
    return this.authService.login(body.password, body.username)
  }

  @Post('login-legacy')
  @HttpCode(200)
  async loginLehacy(@Body() body: { username: string; password: string }) {
    return this.authService.loginLegacy(body.password, body.username)
  }

  @Get('verify')
  async resetToken(@Headers('authorization') auth: string) {
    return this.authService.verifyToken(auth)
  }

  @Post('reset-password')
  async resetPassword(@Body() body: { email: string }) {
    return this.authService.resetPassword(body.email)
  }

  @Post('reset-password-confirm')
  async resetPasswordConfirm(@Body() body: { token: string; newPassword: string }) {
    return this.authService.confirmReset(body.newPassword, body.token)
  }

}
