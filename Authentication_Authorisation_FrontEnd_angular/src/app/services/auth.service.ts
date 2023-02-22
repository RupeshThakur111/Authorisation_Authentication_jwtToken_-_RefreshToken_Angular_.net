import { Injectable } from '@angular/core';
import { HttpClient } from  '@angular/common/http';
import { Router } from '@angular/router';
import {JwtHelperService} from '@auth0/angular-jwt'  // helps to decode the token
import { TokenApiModel } from '../models/TokenApiModel';


@Injectable({
  providedIn: 'root'
})
export class AuthService {

  private baseUrl:string="https://localhost:7294/api/User/";
  private userPayload:any;
  constructor(private http:HttpClient , private router:Router) {

    this.userPayload = this.decodeToken();
   }

  signUp(userObj:any){
   return this.http.post<any>(`${this.baseUrl}register`,userObj)
  }

  login(loginObj:any){
    return this.http.post<any>(`${this.baseUrl}authenticate`,loginObj)
  }

  // storing token in local storage  when user will log in
  storeToken(tokenValue:string){
    localStorage.setItem('token' , tokenValue)
  }

  // getting token fron local storage 
  getToken(){
    return localStorage.getItem('token')
  }

  // cheking if user is logged in or not
  isLoggedIn():boolean{
     return !!localStorage.getItem('token')  // (!!) returns string as bool
  }

  // logout method
  signOut(){
    localStorage.clear();
    this.router.navigate(['login'])
  }

  decodeToken(){
    const jwtHelper = new JwtHelperService();
    const token = this.getToken()!;
    return jwtHelper.decodeToken(token);
  }

  getFullNameFromToken(){
     if(this.userPayload)
     return this.userPayload.name
  }

  getRoleFromToken(){
    if(this.userPayload)
    return this.userPayload.role
  }

  // for refresh token
  renewToken(tokenApi : TokenApiModel){
   return this.http.post<any>(`${this.baseUrl}refresh` , tokenApi)
  }
  storeRefreshToken(tokenValue:string){
    localStorage.setItem('refreshToken' , tokenValue)
  }
  getRefreshToken(){
    return localStorage.getItem('refreshToken')
  }
}
