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
from .utils import send_verification_email
from django.utils.http import urlsafe_base64_decode
from django.contrib.auth.tokens import default_token_generator


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
            # Send verification email
            mail_subject = 'Please activate your account'
            email_template = 'accounts/emails/account_verification_email.html'
            send_verification_email(request, user, mail_subject, email_template)
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


def activate(request, uidb64, token):
    # Activate the user by setting the is_active status to True
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = User._default_manager.get(pk=uid)
    except(TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None

    if user is not None and default_token_generator.check_token(user, token):
        user.is_active = True
        user.save()
        messages.success(request, 'Congratulation! Your account is activated.')
        return redirect('myAccount')
    else:
        messages.error(request, 'Invalid activation link')
        return redirect('myAccount')
        
        
def forgot_password(request):
    if request.method == "POST":
        email = request.POST['email']
        if User.objects.filter(email=email).exists():
            user = User.objects.get(email__exact=email)
            # send reset password email
            mail_subject = 'Reset Your Password'
            email_template = 'accounts/emails/reset_password_email.html'
            send_verification_email(request, user, mail_subject, email_template)

            messages.success(request, 'Password reset link has been sent to your email address.')
            return redirect('login')
        else:
            messages.error(request, 'Account does not exist')
            return redirect('forgot_password')
        
        
    return render(request,'accounts/forgot_password.html')

def reset_password_validate(request,uidb64,token):
    # validate the user by decoding the token and user pk
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = User.objects.get(pk=uid)
    except(TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None
        
    if user is not None and default_token_generator.check_token(user,token):
        request.session['uid'] = uid
        messages.info(request, 'Please reset your password')
        return redirect('reset_password')
    else:
        messages.error(request, 'This link has been expired!')
        return redirect('myAccount')
    
    
def reset_password(request):
    if request.method == "POST":
        password = request.POST['password']
        confirm_password = request.POST['confirm_password']
        if password == confirm_password:
            pk = request.session.get('uid')
            user = User.objects.get(pk=pk )
            user.set_password(password)
            user.is_active = True
            user.save()
            messages.success(request, 'Password reset successful')
            return redirect('login')
        else:
            messages.error(request, 'Password do not match!')
            return redirect('reset_password')
    return render(request, 'accounts/reset_password.html')

    


