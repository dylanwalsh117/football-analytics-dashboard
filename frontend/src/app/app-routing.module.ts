import { NgModule } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterModule, Routes } from '@angular/router';
import { LoginComponent } from './login/login.component';
import {HomeComponent} from './home/home.component';
import {RegisterComponent} from './register/register.component';
import {TokenGuard} from './auth/token.guard';

export const routes: Routes = [
    // Assigning certain components to routes
    // Making login the default route
    {path: '', redirectTo: '/login', pathMatch: 'full'},
    { path: 'login', component: LoginComponent },
    // canActivate called from token.guard
    {path: 'home', component: HomeComponent, canActivate: [TokenGuard] },
    {path: 'register', component: RegisterComponent}
];

@NgModule({
    declarations: [],
    imports: [
        // Importing routes module
        RouterModule.forRoot(routes)
    ],
    exports: [
        // Exporting router module
        RouterModule
    ]
})
export class AppRoutingModule { }
