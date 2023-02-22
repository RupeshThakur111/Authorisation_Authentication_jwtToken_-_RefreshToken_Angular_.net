import { Component, OnInit } from '@angular/core';
import { ApiService } from 'src/app/services/api.service';
import { AuthService } from 'src/app/services/auth.service';
import { UserStoreService } from 'src/app/services/user-store.service';

@Component({
  selector: 'app-dashboard',
  templateUrl: './dashboard.component.html',
  styleUrls: ['./dashboard.component.scss']
})
export class DashboardComponent implements OnInit {

  public users:any=[]
  public role:string="";
  public fullName : string = ""
  constructor(private service:AuthService , private apiservice:ApiService , private userStoreService:UserStoreService) { }

  ngOnInit(): void {
    this.apiservice.getUsers().subscribe(
      res=>{
        this.users=res;
      }
    )
     this.userStoreService.getFullNameFromStore().subscribe(
      val=>{
        const fullNameFromToken = this.service.getFullNameFromToken();
        this.fullName = val || fullNameFromToken
      }
     )
     this.userStoreService.getFullNameFromStore().subscribe(val=>{
      const roleFromToken = this.service.getRoleFromToken();
      this.role=val || roleFromToken;
     })
  }

  logout(){
    this.service.signOut();
  }
}
