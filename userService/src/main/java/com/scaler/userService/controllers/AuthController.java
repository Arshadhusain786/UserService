package com.scaler.userService.controllers;

import com.scaler.userService.dtos.SignUpRequestDto;
import com.scaler.userService.dtos.SignUpResponseDto;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/auth")
public class AuthController
{
   @PostMapping("/sign_up")
    public SignUpResponseDto signUp(SignUpRequestDto signUpRequestDto)
   {
      return null;
   }
   @PostMapping("/login")
    public String login()
   {

   }
}
