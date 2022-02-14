import { Component, OnInit } from '@angular/core';
import {Router} from '@angular/router';
import {UserService} from '../user.service';
import {FormControl, FormGroup, Validators} from '@angular/forms';

@Component({
  selector: 'app-register',
  templateUrl: './register.component.html',
  styleUrls: ['./register.component.css']
})
export class RegisterComponent implements OnInit {
    addForm: FormGroup;

  constructor(
      private router: Router,
      private userService: UserService
  ) { }


    // Adding validation to form.
    // tslint:disable-next-line:typedef
    ngOnInit() {
        this.addForm = new FormGroup({
            email: new FormControl('', Validators.required),
            password: new FormControl('', Validators.required),

        });
    }

    /**
     * Registering user and when registered redirect to login
     * @param user: object
     */
    onSubmit(user): void {
        console.log(user);
        console.log(this.userService.addUser(user));
        this.router.navigate(['/login']);
    }


}

