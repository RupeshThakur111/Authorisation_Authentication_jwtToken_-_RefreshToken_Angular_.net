import { Component, OnInit } from '@angular/core';
import { FormBuilder, FormControl, FormGroup , Validators} from '@angular/forms';
import { Router } from '@angular/router';
import { NgToastService } from 'ng-angular-popup';
import ValidateForm from 'src/app/helpers/validateform';
import { AuthService } from 'src/app/services/auth.service';

@Component({
  selector: 'app-signup',
  templateUrl: './signup.component.html',
  styleUrls: ['./signup.component.scss']
})
export class SignupComponent implements OnInit {

  type:string="password"
  isText:boolean=false;
  eyeIcon:string="fa-eye-slash"

  signUpForm!:FormGroup
  constructor(private fb:FormBuilder , private service:AuthService , private router:Router , private toast:NgToastService) { }

  ngOnInit(): void {
    this.signUpForm = this.fb.group({
      firstName:['',Validators.required],
      lastName:['',Validators.required],
      Email:['',Validators.required],
      userName:['',Validators.required],
      password:['',Validators.required]
    })
  }

  hideShowPass(){
       this.isText = !this.isText;
       this.isText? this.eyeIcon="fa-eye3":this.eyeIcon="fa-eye-slash";
       this.isText?this.type="text":this.type="password";
  }
  onSignup(){
    if(this.signUpForm.valid)
    {
      // send obj to database
      this.service.signUp(this.signUpForm.value).subscribe({
        next:(res)=>{
          this.toast.success({detail:"SUCCESS",summary:"Signed Up Succesfully" , duration:5000})
          this.signUpForm.reset();
          this.router.navigate(['login'])
        },
        error:(err)=>{
          this.toast.error({detail:"ERROR", summary:err?.error.message , duration:5000})   // displaying error as backend response mssg
        }
      })
    }
    else
    {
     // throw error using toaster with required fields
     ValidateForm.validateAllFormFileds(this.signUpForm)
     this.toast.error({detail:"ERROR", summary:"Form Values are not correct" , duration:5000})
    }
  }


}
