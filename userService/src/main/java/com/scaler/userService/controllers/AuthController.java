package com.scaler.userService.controllers;

import com.scaler.userService.dtos.*;
import com.scaler.userService.services.AuthService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.*;

@Controller
@RequestMapping("/auth")
public class AuthController
{

    private AuthService authService;

    public AuthController(AuthService authService)
    {
        this.authService=authService;

    }
   @PostMapping("/sign_up")
    public ResponseEntity<SignUpResponseDto> signUp(@RequestBody SignUpRequestDto request)
   {
       SignUpResponseDto response = new SignUpResponseDto();
       try{
           if(authService.signUp(request.getEmail(), request.getPassword()))
           {
               response.setStatus(RequestStatus.SUCCESS);
           }
           else
           {
               response.setStatus(RequestStatus.FAILURE);
           }
           return new ResponseEntity<>(response,HttpStatus.OK);
       }
       catch(Exception e)
       {   response.setStatus(RequestStatus.FAILURE);
           return new ResponseEntity<>(response,HttpStatus.CONFLICT);
       }

   }
   @PostMapping("/login")
    public ResponseEntity<LoginResponseDto> login(@RequestBody LoginRequestDto request) throws Exception
   {
       try{
           String token = authService.login(request.getEmail(),request.getPassword());
           LoginResponseDto responseDto = new LoginResponseDto();
           responseDto.setRequestStatus(RequestStatus.SUCCESS);
           MultiValueMap<String,String> headers = new LinkedMultiValueMap<>();
           headers.add("AUTH_TOKEN",token);
           return new ResponseEntity<>(
                   responseDto,headers, HttpStatus.OK
           );
       }
       catch(Exception e)
       {
           LoginResponseDto responseDto = new LoginResponseDto();
           responseDto.setRequestStatus(RequestStatus.FAILURE);

           return new ResponseEntity<>(
                   responseDto,null, HttpStatus.BAD_REQUEST
           );
       }
   }
    @GetMapping("/validate")
    public ResponseEntity<Boolean> validate(@RequestParam String token) {
        boolean valid = authService.validate(token);
        return ResponseEntity.ok(valid);
    }

}
