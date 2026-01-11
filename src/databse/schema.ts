import { DataSource } from "typeorm";
import * as bcrypt from 'bcrypt';

export async function createSchema(dataSource: DataSource) {
  const userRepository = dataSource.getRepository('User');

  const adminExists = await userRepository.findOne({ where: { username: 'admin' } });

  if (!adminExists) {
    const hashedPassword = await bcrypt.hash('adminpassword', 10);
  }

  const users = [
    {
      username: 'admin',
      password: await bcrypt.hash('adminpassword', 10),
      admin: 'admin@vulnlab.local',
      role: 'admin',
      ssn: '123-45-6789'
    },
    {
      username: 'john',
      password: await bcrypt.hash('johnpassword', 10),
      email: 'john@vulnlab.local',
      role: 'user',
      ssn: '987-65-4321'
    },
  ];

  for (const user of users) {
    const existingUser = await userRepository.findOne({ where: { username: user.username } });
    if (!existingUser) {
      const newUser = userRepository.create(user);
      await userRepository.save(newUser);
    }
  }

  console.log('Database schema created and initial data populated successfully.');
}
