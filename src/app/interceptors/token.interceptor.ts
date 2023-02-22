import { Injectable } from '@angular/core';
import {
  HttpRequest,
  HttpHandler,
  HttpEvent,
  HttpInterceptor,
  HttpErrorResponse
} from '@angular/common/http';
import { catchError, Observable, switchMap, throwError } from 'rxjs';
import { AuthService } from '../services/auth.service';
import { NgToastService } from 'ng-angular-popup';
import { Router } from '@angular/router';
import { TokenApiModel } from '../models/TokenApiModel';

@Injectable()
export class TokenInterceptor implements HttpInterceptor {

  constructor(private service:AuthService , private toast:NgToastService , private router:Router) {}

  intercept(request: HttpRequest<unknown>, next: HttpHandler): Observable<HttpEvent<unknown>> {
    const myToken = this.service.getToken();

    if(myToken){
      request = request.clone({
        setHeaders:{Authorization:`Bearer ${myToken}`}   // Bearer + "myToken"
      })
    }
    return next.handle(request).pipe(
      catchError((err:any)=>{
        if(err instanceof HttpErrorResponse){
          if(err.status === 401){

            // for jwt token
            // this.toast.warning({detail:"Warning" , summary:"Token is expired , Login again"});
            // this.router.navigate(['login'])

            // for refresh token
             return this.handleUnAuthorizedError(request,next);
          }
        }
        return throwError(()=>new Error("Some other error occured"))
      })
      );
  }

  // refresh token
  handleUnAuthorizedError(req:HttpRequest<any> , next:HttpHandler){
    let tokenApiModel = new TokenApiModel();
    tokenApiModel.accessToken=this.service.getToken()!;
    tokenApiModel.refreshToken=this.service.getRefreshToken()!;
    return this.service.renewToken(tokenApiModel).pipe(
      switchMap((data:TokenApiModel) => {
        this.service.storeRefreshToken(data.refreshToken);
        this.service.storeToken(data.accessToken);
        req = req.clone({
          setHeaders:{Authorization:`Bearer ${data.accessToken}`}   // "Bearer" + myToken
        })
        return next.handle(req)
      }),
      catchError((err)=>{
        return throwError (()=>{
          this.toast.warning({detail:"Warning" , summary:"Token is expired , Login again"});
          this.router.navigate(['login'])
        })
      })
    )
  }
}
