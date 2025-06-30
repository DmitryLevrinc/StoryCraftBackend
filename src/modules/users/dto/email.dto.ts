import { IsEmail } from "class-validator";

export class sendEmailDto {

    @IsEmail()
    email: string;
}