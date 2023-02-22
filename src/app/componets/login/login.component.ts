import { Component, OnInit } from '@angular/core';
import { FormBuilder, FormControl, FormGroup , Validators } from '@angular/forms';
import { Router } from '@angular/router';
import { NgToastService } from 'ng-angular-popup';
import ValidateForm from 'src/app/helpers/validateform';
import { AuthService } from 'src/app/services/auth.service';
import { UserStoreService } from 'src/app/services/user-store.service';


@Component({
  selector: 'app-login',
  templateUrl: './login.component.html',
  styleUrls: ['./login.component.scss']
})
export class LoginComponent implements OnInit {

  type:string="password"
  isText:boolean=false;
  eyeIcon:string="fa-eye-slash"

  loginForm!:FormGroup;
  constructor(private fb:FormBuilder , private service:AuthService , private router:Router , private toast:NgToastService , private userStoreService:UserStoreService ) { }

  ngOnInit(): void {
    this.loginForm=this.fb.group({
      username:['',Validators.required],
      password:['',Validators.required]
    })
  }

  hideShowPass(){
       this.isText = !this.isText;
       this.isText? this.eyeIcon="fa-eye3":this.eyeIcon="fa-eye-slash";
       this.isText?this.type="text":this.type="password";
  }

  onLogin(){
    if(this.loginForm.valid)
    {
      // send obj to database
      this.service.login(this.loginForm.value).subscribe({
        next:(res)=>{
          this.loginForm.reset();
          //this.service.storeToken(res.token);   --> for normal token

          // for refresh token
          this.service.storeToken(res.accessToken)   
          this.service.storeRefreshToken(res.refreshToken)   //
                          

          const tokenPayload = this.service.decodeToken();
          this.userStoreService.setFullNameForStore(tokenPayload.name)
          this.userStoreService.setFullNameForStore(tokenPayload.role)

          this.toast.success({detail:"SUCCESS" , summary:res.message, duration:5000})
          
          this.router.navigate(['dashboard'])
        },
        error:(err)=>{
          this.toast.error({detail:"ERROR" , summary:"Somethong went wrong", duration:5000})
        }
      })
    }
    else
    {
     // throw error using toaster with required fields
     ValidateForm.validateAllFormFileds(this.loginForm)
     this.toast.error({detail:"ERROR" , summary:"form value is Incorrect"})
    }
  }

 
}
