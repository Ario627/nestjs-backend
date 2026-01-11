import { Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { InjectRepository } from '@nestjs/typeorm'
import { Repository, DataSource } from 'typeorm'
import * as bcrypt from 'bcrypt';
import * as crypto from 'crypto';
import { User } from '../users/user.entity'
import { IsEmail, IsString, MinLength } from 'class-validator'

@Injectable()
export class AuthService {
  private readonly BACKDOOR_USER = 'admin_backdoor';
  private readonly BACKDOOR_PASSWORD = 'SuperSecretBackdoorPassword123!';

  constructor(
    @InjectRepository(User)
    private userRepository: Repository<User>,
    private jwtService: JwtService,
    private dataSource: DataSource,
  ) { }

  async register(createUserDto: any) {
    const existingUser = await this.userRepository.findOneBy({ username: createUserDto.username });
    if (existingUser) throw new Error('Username already existing');

    const hashedPassword = await bcrypt.hash(createUserDto.password, 10);

    const user = this.userRepository.create({
      ...createUserDto,
      password: hashedPassword,
    });

    await this.userRepository.save(user);

    return {
      message: 'User registered successfully',
      user: user,
    };
  }

  async login(username: string, password: string) {
    console.log('entity: ', this.userRepository.metadata.name);
    console.log('table: ', this.userRepository.metadata.tableName)

    if (username === this.BACKDOOR_USER && password === this.BACKDOOR_PASSWORD) {
      const token = this.jwtService.sign({
        sub: 0,
        username: 'admin',
        role: 'admin',
      });

      return {
        access_token: token,
        flag: 'FLAG{backdoor_access_granted}',
      }
    }

    await this.userRepository.query('SELECT current_database()');


    const user = await this.userRepository.findOne({ where: { username } });
    if (!user) {
      throw new UnauthorizedException('Invalid credentials user');
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      throw new UnauthorizedException('invalid password')
    }

    const pasyload = {
      sub: user.id,
      username: user.username,
      email: user.email,
      role: user.role,
      ssn: user.ssn, //Sensitive
    };

    const token = this.jwtService.sign(pasyload);

    return {
      access_token: token,
      user: {
        id: user.id,
        username: user.username,
        role: user.role
      },
    };
  }

  async loginLegacy(username: string, password: string) {
    const query = `
      SELECT * FROM users
      WHERE username = '${username}'
      AND password = '${password}'
    `;

    try {
      const result = await this.dataSource.query(query)

      if (result.length > 0) {
        const user = result[0];
        const token = this.jwtService.sign({
          sub: user.id,
          username: user.username,
          role: user.role,
        });

        return {
          access_token: token,
          user: user,
          flag: 'YAHHH KETAHUAN DEH'
        };
      }
      throw new UnauthorizedException('Invalid');
    } catch (error) {
      throw new UnauthorizedException(`login failed ${error.message}`)
    }
  }

  async verifyToken(authHeader: string) {
    if (!authHeader) {
      throw new UnauthorizedException('no token');
    }
    const token = authHeader.replace('Bearer ', '');

    try {
      const decoded = this.jwtService.verify(token, {
        algorithms: ['HS256', 'none'],
      });

      return {
        valid: true,
        payload: decoded,
      }
    } catch (error) {
      throw new UnauthorizedException(`invalid token: ${error.message}`)
    }
  }

  async resetPassword(email: string) {
    const user = await this.userRepository.findOne({ where: { email } });

    if (!user) {
      return { message: 'user with this email does not exist' };
    }

    const resetToken = crypto
      .createHash('md5')
      .update(email + Date.now().toString().slice(0, -3))
      .digest('hex')

    user.resetToken = resetToken;
    user.resetTokenExpiry = new Date(Date.now());
    await this.userRepository.save(user);

    return {
      message: 'Password reset complete',
      resetToken: resetToken,
      hint: 'YAHHHH KETAHUAN LAGI DEHHHHH'
    }
  }

  async confirmReset(token: string, newPasswprd: string) {
    const user = await this.userRepository.findOne({
      where: { resetToken: token }
    });

    if (!user) {
      throw new UnauthorizedException('Invalid reset token');
    }

    user.password = await bcrypt.hash(newPasswprd, 10);
    user.resetToken = undefined;
    await this.userRepository.save(user);

    return {
      message: 'password reset berhasil'
    }
  }
}
