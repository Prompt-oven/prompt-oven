import { z } from "zod";

export const passwordRegex =
  /^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?!@$%^&*-]).{10,20}$/;
export const emailRegex = /^[\w.-]+@[a-zA-Z\d.-]+\.[a-zA-Z]{2,}$/;
export const nicknameRegex = /^[a-zA-Z가-힣]{1,20}$/;

export const loginSchema = z.object({
  email: z.string()
  .min(1, { message: "Enter your ID" }),
  password: z.string()
  .min(1, { message: "Enter your Password" }),
});

export const signupSchemaObject = z
  .object({
    email: z.string().regex(emailRegex, {
      message: "Enter in email format",
    }),
    emailCode: z.string({required_error: "Enter your authentication number"}),
    password: z.string().regex(passwordRegex, {
      message: "Special characters, number, uppercase are required",
    }),
    passwordValidate: z.string().regex(passwordRegex, {
      message: "Special characters, number, uppercase are requied",
    }),
    nickname: z.string().regex(nicknameRegex, {
      message: "Numbers should not be entered",
    }),
    terms: z.boolean().refine((val) => val, {
      message: "You must agree to the terms"
    })
  })
  .refine((data) => data.password === data.passwordValidate, {
    path: ["passwordValidate"],
    message: "Passwords do not match",
  });

export const signupSchema = signupSchemaObject.refine((data) => data.password === data.passwordValidate, {
  path: ["passwordValidate"],
  message: "비밀번호가 일치하지 않습니다.",
})
.refine((data) => data.emailCode !== "", {
  path: ["emailCode"],
  message: "이메일 인증 코드를 입력해주세요.",
});

export const forgotSchemaObject = z
  .object({
    email: z.string().regex(emailRegex, {
      message: "아이디 형식이 일치하지 않습니다.",
    }),
    emailCode: z.string({required_error: "인증번호를 입력해주세요"}),
    password: z.string().regex(passwordRegex, {
      message: "비밀번호 형식이 일치하지 않습니다.",
    }),
    passwordValidate: z.string().regex(passwordRegex, {
      message: "비밀번호 형식이 일치하지 않습니다.",
    }),
  });

  export const nicknameSchemaObject = z.object(
    {nickname: z.string().regex(nicknameRegex, {
      message: "닉네임은 1글자 이상, 영문이어야합니다"
    })}
  )