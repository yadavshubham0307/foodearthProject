from django.shortcuts import render, redirect
from django.http import HttpResponse
from .forms import UserForm
from .models import User, UserProfile
from vendor.models import Vendor
from vendor.forms import VendorForm
from django.contrib import messages, auth
from django.core.exceptions import PermissionDenied
from django.contrib.auth.decorators import login_required, user_passes_test
from .utils import detectUser


#Ristrict the vendor from accessing the customer page
def check_vendor_role(user):
    if user.role == 1:
        return True
    else:
        raise PermissionDenied
    
#Ristrict the cutomer from accessing the vendor page
def check_customer_role(user):
    if user.role == 2:
        return True
    else:
        raise PermissionDenied
    
def login(request):
    if request.user.is_authenticated:
        messages.warning(request, "You are already logged in!")
        return redirect('myAccount')
    if request.method == "POST":
        email = request.POST['email']
        password = request.POST['password']
        
        print("My email :",email)
        print("M password :",password)
        
        user = auth.authenticate(email=email,password=password)
        
        if user is not None:
            auth.login(request,user)
            return redirect('myAccount')
        else:
            messages.error(request,"Invalid login credentials")
            return redirect('login')
        
    return render(request, 'accounts/login.html')

def logout(request):
    auth.logout(request)
    messages.success(request,'You are logged out!')
    return redirect("login")



@login_required(login_url='login')
def myAccount(request):
    user = request.user
    redirectUrl = detectUser(user)
    return redirect(redirectUrl)

@login_required(login_url='login')
@user_passes_test(check_customer_role)
def custDashboard(request):
    print("my role: ",request.user.role)
    return render(request,'accounts/custDashboard.html')

@login_required(login_url='login')
@user_passes_test(check_vendor_role)
def vendorDashboard(request):
    return render(request,'accounts/vendorDashboard.html')








def registerUser(request):
     
    if request.method == 'POST':
        form = UserForm(request.POST)
        if form.is_valid():
            # Create the user using the form
            # password = form.cleaned_data['password']
            # user = form.save(commit=False)
            # user.set_password(password)
            # user.role = User.CUSTOMER
            # user.save()

            # Create the user using create_user method
            first_name = form.cleaned_data['first_name']
            last_name = form.cleaned_data['last_name']
            username = form.cleaned_data['username']
            email = form.cleaned_data['email']
            password = form.cleaned_data['password']
            user = User.objects.create_user(first_name=first_name, last_name=last_name, username=username, email=email, password=password)
            user.role = User.CUSTOMER
            user.save()
            messages.success(request, 'Your account has been registered sucessfully!')
            return redirect('registerUser')
        else:
            print('invalid form')
            print(form.errors)
            
    else:
        form = UserForm()
    context = {
        'form': form
    } 

    return render(request, 'accounts/registerUser.html',context)

def registerVendor(request):
    if request.method == "POST":
        userform = UserForm(request.POST)
        vendorform = VendorForm(request.POST, request.FILES)
        if userform.is_valid() and vendorform.is_valid():
            first_name = userform.cleaned_data['first_name']
            last_name = userform.cleaned_data['last_name']
            username = userform.cleaned_data['username']
            email = userform.cleaned_data['email']
            password = userform.cleaned_data['password']
            user = User.objects.create_user(first_name=first_name, last_name=last_name, username=username, email=email, password=password)
            user.role = User.VENDOR
            user.save()
            #print("Vendor License: ",vendorform.cleaned_data['vendor_license'])
            vendor = vendorform.save(commit=False)
            vendor.user = user
            userProfile = UserProfile.objects.get(user = user)
            vendor.userProfile = userProfile
            vendor.save()
            
            messages.success(request,'Your account has been registered sucessfully! Please wait for the approval.')
            
            return redirect('registerVendor')
        else:
            print("Invalid Form")
            print(userform.errors)
            print(vendorform.errors)
    else:
        userform = UserForm()
        vendorform = VendorForm()
        
    context = {
        'form': userform,
        'v_form': vendorform
    }
        
    return render(request, 'accounts/registerVendor.html', context)