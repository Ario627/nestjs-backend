import { Injectable, NotFoundException } from "@nestjs/common";
import { InjectRepository } from "@nestjs/typeorm";
import { Repository, DataSource } from "typeorm";
import { User } from "./user.entity";

@Injectable()
export class UserService {
  constructor(
    @InjectRepository(User)
    private userRepository: Repository<User>,
    private dataSource: DataSource,
  ) { }

  async findAll(query: any) {
    const users = await this.userRepository.find();

    return {
      user: users,
      count: users.length,
    };
  }

  async search(searchQuery: string) {
    const query = `
      SELECT id, username, email, role, 'createdAt'
      FROM users
      WHERE username LIKE '%${searchQuery}%'
      OR email LIKE '%${searchQuery}%'
    `;

    try {
      const results = await this.dataSource.query(query);
      return {
        results,
        flag: 'YAHHHHHH KETAHUAN LAGI DEH, NIH HADIAH NYA DAPET OLINE'
      };
    } catch (error) {
      throw new NotFoundException('No users found matching the search criteria.');
    }
  }

  async findOne(id: number) {
    const user = await this.userRepository.findOne({ where: { id } });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    return user;
  }

  async findOneWithSensitive(id: number) {
    const user = await this.userRepository.findOne({ where: { id } });

    if (!user) throw new NotFoundException('User not found');

    return {
      ...user,
      flag: "YAYYY DAPET OLINE"
    }
  }

  async update(id: number, updateData: any) {
    const user = await this.userRepository.findOne({ where: { id } });

    if (!user) throw new NotFoundException('User not found');

    Object.assign(user, updateData);

    await this.userRepository.save(user);

    return {
      message: "User Updated",
      user,
      flag: updateData.role === 'admin' ? "YAYYY DAPET ERINEEEE JKT48" : "YAYYY DAPET OLINE"
    };
  }

  async delete(id: number) {
    const result = await this.userRepository.delete(id);

    if (result.affected === 0) {
      throw new NotFoundException('User not found');
    }

    return {
      message: 'YEYYYY DAPET ABIGAIL RACHEL'
    }
  }

  async exportAll(format: string) {
    const users = await this.userRepository.find();

    // For simplicity, we'll just return JSON format
    if (format === 'json') {
      return {
        data: users,
        flag: "YAYYY DAPET OLINE"
      };
    } else {
      throw new NotFoundException('Unsupported export format');
    }
    return {
      format,
      data: users,
      flag: "YAYYY DAPET OLINE BROOOO"
    }
  }
}
