from django.conf import settings
from pathlib import Path
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import login, authenticate, logout
from .forms import SignupForm, LoginForm, UploadFileForm
from django.contrib.auth.decorators import login_required
from .models import Documents, FileTransfer, CustomUser, UserKeys
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
                 .prefetch_related('documents'))  # Prefetch related 'documents' to optimize queries

    # Assuming each FileTransfer has multiple documents, and you want to decrypt the AES key of the first document
    users_key = get_object_or_404(UserKeys, user=request.user)
    private_key = users_key.private_key

    decrypted_files = []  # To hold the paths of decrypted files

    # Get the first document from the first transfer, if it exists
    first_transfer = transfers.first()
    if first_transfer and first_transfer.documents.exists():
        document = first_transfer.documents.first()  # Get the first document
        aes = document.aes_key  # Access the AES key from the document

        aes_temp_file_path = f"temp_aes_key.key"
        decrypted_aes_path = f"private_key_{users_key.id}.key"  # Unique file name for each user

        # Write the AES key to a temporary file
        with open(aes_temp_file_path, "wb") as aes_key_file:
            aes_key_file.write(aes)

        # Decrypt the AES key using PQC
        krypton = KryptonKEM(Kyber)
        krypton.decrypt_to_file(private_key, Path(aes_temp_file_path), Path(decrypted_aes_path))

        # Read the decrypted AES key
        with open(decrypted_aes_path, "rb") as decrypted_aes_key:
            original_key = decrypted_aes_key.read()

        # Clean up the temporary files
        os.remove(aes_temp_file_path)
        os.remove(decrypted_aes_path)

        # Now, use the decrypted AES key to decrypt the document
        encrypted_file_path = document.file.path  # Assuming the document is stored locally
        decrypted_file_name = f"decrypted_{document.name}"

        # Set the path where decrypted file will be saved
        decrypted_file_path = os.path.join(settings.MEDIA_ROOT, 'decrypted_files', decrypted_file_name)
        os.makedirs(os.path.dirname(decrypted_file_path), exist_ok=True)

        # Decrypt the file and save it
        decrypt_file(encrypted_file_path, original_key, decrypted_file_path)

        # Add the relative URL to the decrypted file for serving
        decrypted_file_url = os.path.join('decrypted_files', decrypted_file_name)  # Remove 'media/' part
        decrypted_files.append(decrypted_file_url)

    else:
        print("No documents found in the transfer.")

    return render(request, 'received_documents.html', {'transfers': transfers, 'decrypted_files': decrypted_files})
