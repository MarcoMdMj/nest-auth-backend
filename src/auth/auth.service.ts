import { BadRequestException, Injectable, InternalServerErrorException, UnauthorizedException } from '@nestjs/common';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateAuthDto } from './dto/update-auth.dto';
import { InjectModel } from '@nestjs/mongoose';
import { User } from './entities/user.entity';
import { Model } from 'mongoose';

import * as bcryptjs from 'bcryptjs';
import { LoginDto } from './dto/login.dto';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from './interfaces/jwt-payload.interface';
import { LoginResponse } from './interfaces/login-response.interface';
import { RegisterUserDto } from './dto/register-user.dto';
import { CheckTokenDto } from './dto/check-token.dto';

@Injectable()
export class AuthService {
  constructor(
    @InjectModel(User.name) private userModel: Model<User>,
    private jwtService: JwtService
    ) {
      
    }
    
    async create(createUserDto: CreateUserDto): Promise<User> {
      try {
        const { password, ...data } = createUserDto;
        
        const newUser = new this.userModel({
          password: bcryptjs.hashSync(password),
        ...data
      });

      await newUser.save();
      
      const { password: _, ...user} = newUser.toJSON();
      
      return user;
    } catch(error) {
      if (error.code === 11000) {
        throw new BadRequestException(`${createUserDto.email} already exists!`);
      }
      throw new InternalServerErrorException('Something terrible happened!');
    }
  }
  
  async register({ email, name, password }: RegisterUserDto): Promise<LoginResponse> {
    const user = await this.create({ email, name, password });
    
    return {
      info: user,
      jwt: this.getJWT({ id: user._id! }),
    };
  }
  
  async login(loginDto: LoginDto): Promise<LoginResponse> {
    const { email, password } = loginDto;
    
    const user = await this.userModel.findOne({ email });
    
    if (!user) {
      throw new UnauthorizedException('Not valid credentials (email)');
    }
    
    if (!bcryptjs.compareSync(password, user.password!)) {
      throw new UnauthorizedException('Not valid credentials (password)');
    }
    
    const { password: $, ...userInfo } = user.toJSON();
    
    return {
      info: userInfo,
      jwt: this.getJWT({ id: user.id }),
    }
  }

  findAll(): Promise<User[]> {
    return this.userModel.find();
  }
  
  findOne(id: number) {
    return `This action returns a #${id} auth`;
  }

  async findUserById(id: string) {
    const user = await this.userModel.findById(id);

    if (!user) {
      return null;
    }
    
    const { password, ...res } = user.toJSON();

    return res;
  }

  update(id: number, updateAuthDto: UpdateAuthDto) {
    return `This action updates a #${id} auth`;
  }

  remove(id: number) {
    return `This action removes a #${id} auth`;
  }

  getJWT(payload: JwtPayload) {
    return this.jwtService.sign(payload);
  }
}
