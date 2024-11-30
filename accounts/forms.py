import re
from django import forms
from django.contrib.auth.hashers import make_password
from django.core.exceptions import ValidationError
from .models import Documents, CustomUser, UserKeys
from django.contrib.auth.forms import AuthenticationForm
from quantcrypt.kem import Kyber
import os

class SignupForm(forms.Form):
    # Fields as before
    first_name = forms.CharField(
        max_length=50,
        required=True,
        label="First Name",
        widget=forms.TextInput(attrs={'class': 'w-full px-4 py-2 rounded-lg border border-gray-300 text-gray-100',
                                      'placeholder': "Enter your first name"})
    )
    last_name = forms.CharField(
        max_length=50,
        required=True,
        label="Last Name",
        widget=forms.TextInput(attrs={'class': 'w-full px-4 py-2 rounded-lg border border-gray-300',
                                      'placeholder': "Enter your last name"})
    )
    email = forms.EmailField(
        required=True,
        label="Email",
        widget=forms.EmailInput(
            attrs={'class': 'w-full px-4 py-2 rounded-lg border border-gray-300', 'placeholder': "Enter your email"})
    )
    role = forms.ChoiceField(
        choices=CustomUser.ROLE_CHOICES,
        required=True,
        label="Role"
    )
    password1 = forms.CharField(
        required=True,
        label="Password",
        widget=forms.PasswordInput(
            attrs={'class': 'w-full px-4 py-2 rounded-lg border border-gray-300', 'placeholder': "Enter password"})
    )
    password2 = forms.CharField(
        required=True,
        label="Confirm Password",
        widget=forms.PasswordInput(
            attrs={'class': 'w-full px-4 py-2 rounded-lg border border-gray-300', 'placeholder': "Confirm password"})
    )

    def clean(self):
        cleaned_data = super().clean()
        if cleaned_data.get("password1") != cleaned_data.get("password2"):
            raise ValidationError("Passwords don't match")
        if len(cleaned_data.get("password1")) < 8:
            raise ValidationError("password must be at least 8 characters")
        if cleaned_data.get("password1").isdigit() or cleaned_data.get("password1").isalpha():
            raise ValidationError("Password must contain both number and special characters")
        if not any(c.islower() for c in cleaned_data.get("password1")) or not any(
                c.isupper() for c in cleaned_data.get("password1")):
            raise ValidationError("Password must contain both capital and small")
        if not re.search(r'[\W_]', cleaned_data.get("password1")):
            raise ValidationError("Password must include at least one special character (e.g., !, @, #, etc.).")
        return cleaned_data

    def clean_email(self):
        email = self.cleaned_data.get('email')
        if not email.endswith("@komar.edu.iq"):
            raise ValidationError("Email must end with @komar.edu.iq")
        if re.search(r'f\d+', email, re.IGNORECASE):
            raise ValidationError("Students cannot join this platform")
        return email

    def save(self, commit=True):
        # Create a new user with hashed password and other fields
        user = CustomUser(
            first_name=self.cleaned_data['first_name'],
            last_name=self.cleaned_data['last_name'],
            email=self.cleaned_data['email'],
            role=self.cleaned_data['role'],
            password=make_password(self.cleaned_data['password1'])  # Hash password before saving
        )
        # to generate the PQC keys
        kem = Kyber()
        public_key, private_key = kem.keygen()
        user.public_key = public_key
        if commit:
            user.save()
            UserKeys.objects.create(user=user, private_key=private_key)
        return user


class LoginForm(AuthenticationForm):
    username = forms.EmailField(label="Email", widget=forms.EmailInput(attrs={
        'class': 'w-full px-4 py-2 rounded-lg border border-blue-400 focus:border-blue-600 focus:ring-blue-500 '
                 'placeholder-gray-400 transition duration-300 ease-in-out transform hover:scale-105',
        'placeholder': "Enter your email"
    }))
    password = forms.CharField(label="Password",
                               widget=forms.PasswordInput(attrs={
                                   'class': 'w-full px-4 py-2 rounded-lg border border-blue-400 focus:border-blue-600 '
                                            'focus:ring-blue-500'
                                            'placeholder-gray-400 transition duration-300 ease-in-out transform '
                                            'hover:scale-105',
                                   'placeholder': "Enter your password"
                               })
                               )

    def __init__(self, *args, **kwargs):
        super(LoginForm, self).__init__(*args, **kwargs)
        self.fields['username'].widget.attrs['autofocus'] = True


class MultipleFileInput(forms.ClearableFileInput):
    allow_multiple_selected = True


class MultipleFileField(forms.FileField):
    def __init__(self, *args, **kwargs):
        kwargs.setdefault("widget", MultipleFileInput)
        super().__init__(*args, **kwargs)

    def clean(self, data, initial=True):
        # Run the default cleaning for each file
        single_file_clean = super().clean
        valid_extensions = ('.pdf', '.docx')

        # Check if data is a list of files (multiple files uploaded)
        if isinstance(data, (list, tuple)):
            for file in data:
                # Clean each file individually
                single_file_clean(file, initial)

                # Validate the extension of each file
                if not file.name.lower().endswith(valid_extensions):
                    raise ValidationError("Only PDF or DOCX files are allowed.")
        else:
            # Clean and validate a single file
            single_file_clean(data, initial)
            if not data.name.lower().endswith(valid_extensions):
                raise ValidationError("Only PDF or DOCX files are allowed.")

        return data


class UploadFileForm(forms.ModelForm):
    recipient_email = forms.ModelChoiceField(
        queryset=CustomUser.objects.all(),  # Use all users as the base queryset
        widget=forms.Select(attrs={
            'class': 'w-full px-4 py-2 rounded-lg border border-blue-400 focus:border-blue-600 focus:ring-blue-500 '
                     'bg-white text-gray-700 transition duration-300 ease-in-out transform hover:scale-105'
        }),
        required=True,
        label="Send to"
    )
    file = MultipleFileField()
    title = forms.CharField(max_length=255, label="Title", widget=forms.TextInput(attrs={
        'class': 'w-full px-4 py-2 rounded-lg border border-blue-400 focus:border-blue-600 focus:ring-blue-500 '
                 'placeholder-gray-400 transition duration-300 ease-in-out transform hover:scale-105'
    }))
    note = forms.CharField(
        required=False,
        label="Add a note (optional)",
        widget=forms.Textarea(attrs={
            'class': 'w-full px-4 py-2 rounded-lg border border-blue-400 focus:border-blue-600 focus:ring-blue-500 '
                     'placeholder-gray-400 transition duration-300 ease-in-out transform hover:scale-105',
            'rows': 3,
            'placeholder': "Optional note"
        })
    )

    class Meta:
        model = Documents
        fields = ['recipient_email', 'file', 'note']

    def __init__(self, *args, **kwargs):
        current_user = kwargs.pop('current_user', None)
        super(UploadFileForm, self).__init__(*args, **kwargs)
        if current_user:
            # Exclude the current user from the recipient_email field
            self.fields['recipient_email'].queryset = CustomUser.objects.exclude(pk=current_user.pk)
