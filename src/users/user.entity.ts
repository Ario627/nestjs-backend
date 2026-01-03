import { Entity, Column, PrimaryGeneratedColumn, CreateDateColumn } from 'typeorm';

@Entity('users')
export class User {
  @PrimaryGeneratedColumn()
  id: number;

  @Column({ unique: true })
  username: string;

  @Column()
  password: string;

  @Column({ unique: true })
  email: string;

  @Column({ default: 'user' })
  role: 'admin' | 'user';

  @Column({ nullable: true })
  ssn: string;

  @Column({ nullable: true })
  creditCardNumber: string;

  @Column({ nullable: true })
  phoneNumber: string;

  @Column({ nullable: true })
  address: string;

  @Column({ default: 1000 })
  belance: number;

  @Column({ nullable: true })
  resetToken: string | null;

  @Column({ nullable: true })
  resetTokenExpiry: Date;

  @Column({ default: true })
  isActive: boolean;

  @CreateDateColumn()
  createdAt: Date;
}
