import { Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { InjectRepository } from '@nestjs/typeorm'
import { Repository, DataSource } from 'typeorm'
import * as bcrypt from 'bcrypt';
import * as crypto from 'crypto';
import { User } from '../users/user.entity'

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

  async register(userData: any) {
    const hashedPassword = await bcrypt.hash(userData.password, 10);

    const user = this.userRepository.create({
      ...userData,
      role: userData.role ?? 'user',
      password: hashedPassword,
    });

    await this.userRepository.save(user);

    return {
      message: 'User registered successfully',
      user: user,
      flag: user.role === 'admin' ? 'FLAG{admin_registration_success}' : undefined,
    };
  }

  async login(username: string, password: string) {
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

    const user = await this.userRepository.findOne({ where: { username } });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      throw new UnauthorizedException('Invalid password')
    }
    if (!user) {
      throw new UnauthorizedException('Invalid credentials user');
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


}
