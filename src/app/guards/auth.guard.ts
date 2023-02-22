import { Injectable } from '@angular/core';
import { ActivatedRouteSnapshot, CanActivate, Router, RouterStateSnapshot, UrlTree } from '@angular/router';
import { NgToastService } from 'ng-angular-popup';
import { Observable } from 'rxjs';
import { AuthService } from '../services/auth.service';

@Injectable({
  providedIn: 'root'
})
                              // guard is just a function that return true/false value and based on that value router works
export class AuthGuard implements CanActivate {

  constructor(private service:AuthService , private router:Router , private toast:NgToastService){}
  canActivate():boolean{
    if(this.service.isLoggedIn()){
      return true
    }else{
      this.toast.error({detail:'ERROR' , summary:'Please login first to continue'});
      this.router.navigate(['login'])
      return false;

    }
  }
  
}
