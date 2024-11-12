from pathlib import Path

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import login, authenticate, logout
from .forms import SignupForm, LoginForm, UploadFileForm
from django.contrib.auth.decorators import login_required
from .models import Documents, FileTransfer, CustomUser
import os
from quantcrypt.kem import Kyber
from quantcrypt.cipher import KryptonKEM

from .utils.aes_encryption import encrypt_file
from .utils.aes_decryption import decrypt_file


@login_required
def home(request):
    return render(request, 'home.html', {})


def signup_view(request):
    if request.method == 'POST':
        form = SignupForm(request.POST)
        if form.is_valid():
            form.save()
            return redirect('login')
    else:
        form = SignupForm()
    return render(request, 'registration/signup.html', {'form': form})


def login_view(request):
    if request.method == 'POST':
        form = LoginForm(request, data=request.POST)
        if form.is_valid():
            email = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')
            user = authenticate(request, email=email, password=password)
            if user:
                login(request, user)
                return redirect('home')
    else:
        form = LoginForm()
    return render(request, 'registration/login.html', {'form': form})


def logout_view(request):
    logout(request)
    return redirect('login')


AES_KEY = os.urandom(32)


@login_required
def send_document(request):
    if request.method == "POST":
        form = UploadFileForm(request.POST, request.FILES)
        files = request.FILES.getlist('file')

        if form.is_valid():
            recipient = form.cleaned_data.get('recipient_email')
            recipient_user = get_object_or_404(CustomUser, email=recipient)
            recipient_public_key = recipient_user.public_key

            krypton = KryptonKEM(Kyber)
            encrypted_aes_key_path = f"encrypted_aes_key_{recipient_user}.key"
            plaintext_aes_key_path = f"temp_aes_key.key"

            with open(plaintext_aes_key_path, "wb") as temp_file:
                temp_file.write(AES_KEY)

            krypton.encrypt(recipient_public_key, Path(plaintext_aes_key_path), Path(encrypted_aes_key_path))

            # to read the encrypted AES key
            with open(encrypted_aes_key_path, "rb") as encrypted_file:
                encrypted_aes_key = encrypted_file.read()
            os.remove(plaintext_aes_key_path)
            os.remove(encrypted_aes_key_path)

            title = form.cleaned_data.get('title')
            transfer = FileTransfer.objects.create(sender=request.user, recipient=recipient, title=title)
            for file in files:
                encrypted_document = encrypt_file(file, AES_KEY, file.name)
                documents = Documents.objects.create(
                    uploader=request.user,
                    file=encrypted_document,
                    name=encrypted_document.name,
                    note=form.cleaned_data.get('note'),
                    aes_key=encrypted_aes_key,

                )
                transfer.documents.add(documents)
            transfer.save()
            return redirect("home")
    else:
        form = UploadFileForm()
    return render(request, "upload.html", {'form': form})


@login_required
def received_documents(request):
    transfers = (FileTransfer.objects.filter(recipient=request.user)
                 .select_related('sender')
                 .prefetch_related('documents'))

    return render(request, 'received_documents.html', {'transfers': transfers})
