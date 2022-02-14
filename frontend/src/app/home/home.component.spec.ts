import {ComponentFixture, fakeAsync, TestBed} from '@angular/core/testing';
import {HttpClientModule} from '@angular/common/http';
import { HomeComponent } from './home.component';
import {RouterTestingModule} from '@angular/router/testing';
import {MatDialog, MatDialogModule} from '@angular/material/dialog';
import {Overlay, OverlayModule} from '@angular/cdk/overlay';
import {UserService} from '../user.service';
import {DebugElement} from '@angular/core';

class MockUserService extends UserService{
}

describe('HomeComponent', () => {
    let component: HomeComponent;
    let fixture: ComponentFixture<HomeComponent>;

    beforeEach(async () => {
        await TestBed.configureTestingModule({
            imports: [HttpClientModule, RouterTestingModule, MatDialogModule, OverlayModule],
            declarations: [ HomeComponent ]
        })
            .compileComponents();
    });

    beforeEach(() => {
        fixture = TestBed.createComponent(HomeComponent);
        component = fixture.componentInstance;
        fixture.detectChanges();
    });

    // Ensuring component is truthy
    it('should create', () => {
        expect(component).toBeTruthy();
    });

    it('ngOnInit runs', () => {
        expect(component.ngOnInit).toBeTruthy();
    });

    // Ensuring logout is being called whnn button is clicked
    it('logout() function is being called', fakeAsync(() => {
        spyOn(component, 'logOut');
        (document.getElementById('logout') as HTMLButtonElement).click();
        expect(component.logOut).toHaveBeenCalledTimes(1);
    }));
});
