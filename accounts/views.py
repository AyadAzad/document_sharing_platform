import os
from django.shortcuts import redirect
from django.contrib.auth import login, authenticate, logout
from .forms import SignupForm, LoginForm, UploadFileForm
from .models import Documents, FileTransfer, CustomUser, UserKeys
from quantcrypt.kem import Kyber
from quantcrypt.cipher import KryptonKEM
from .utils.aes_encryption import encrypt_file
from .utils.aes_decryption import decrypt_file
from django.shortcuts import render, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.conf import settings
from pathlib import Path
import pytz
from django.utils import timezone

import time


def hero(request):
    return render(request, 'hero.html', {})


@login_required
def home(request):
    # Get counts, default to 0 if no related objects exist
    total_documents = Documents.objects.count()
    total_active_users = CustomUser.objects.filter(is_active=True).count()
    total_received_documents = Documents.objects.filter(transfers__recipient=request.user).count()
    total_sent_documents = Documents.objects.filter(transfers__sender=request.user).count()

    context = {
        'total_documents': total_documents,
        'total_active_users': total_active_users,
        'total_received_documents': total_received_documents,
        'total_sent_documents': total_sent_documents,
    }
    return render(request, 'home.html', context)


def user_information(request):
    user_info = CustomUser.objects.get(id=request.user.id)
    return render(request, 'my_profile.html', {'user_info': user_info})


def about_us(request):
    return render(request, 'about_us.html')


def feature(request):
    return render(request, 'feature.html')


def security(request):
    return render(request, 'security.html')


def contact_us(request):
    return render(request, 'contact_us.html')


def privacy_policy(request):
    return render(request, 'privacy_policy.html')


def licensing(request):
    return render(request, 'licensing.html')


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




@login_required
def send_document(request):
    AES_KEY = os.urandom(32)
    if request.method == "POST":
        form = UploadFileForm(request.POST, request.FILES, current_user=request.user)
        files = request.FILES.getlist('file')

        if form.is_valid():
            start_time = time.time()
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
            baghdad_timezone = pytz.timezone("Asia/Baghdad")
            transferred_at_iq_time = timezone.now().astimezone(baghdad_timezone)
            transfer = FileTransfer.objects.create(
                sender=request.user,
                recipient=recipient,
                title=title,
                transferred_at=transferred_at_iq_time
            )
            for file in files:
                # AES encryption
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
            end_time = time.time()
            time_taken = end_time - start_time
            print(f"time taken to send documents : {time_taken:.2f} seconds ")
            return redirect("home")
    else:
        form = UploadFileForm(current_user=request.user)
    return render(request, "upload.html", {'form': form})


@login_required
def received_documents(request):
    start_time = time.time()
    transfers = (FileTransfer.objects.filter(recipient=request.user)
                 .select_related('sender')
                 .prefetch_related('documents'))  # Prefetch related 'documents' to optimize queries

    users_key = get_object_or_404(UserKeys, user=request.user)
    private_key = users_key.private_key

    # Dictionary to store decrypted files for each transfer
    decrypted_files_by_transfer = {}

    # Iterate over each transfer and decrypt the associated documents
    for transfer in transfers:
        decrypted_files = []  # List to hold decrypted files for the current transfer

        if transfer.documents.exists():
            for document in transfer.documents.all():
                aes = document.aes_key

                aes_temp_file_path = f"temp_aes_key_{document.id}.key"
                decrypted_aes_path = f"private_key_{users_key.id}.key"

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

                # Remove any prefix like "encrypted_" or "decrypted_" from the document name
                cleaned_file_name = document.name.lstrip("encrypted_").lstrip("decrypted_")

                # Create the URL for the decrypted file
                decrypted_file_url = os.path.join(settings.MEDIA_URL, 'decrypted_files', decrypted_file_name)
                file_size_mb = os.path.getsize(encrypted_file_path) / (1024 * 1024)
                # Append a dictionary with name and URL to the decrypted files list
                decrypted_files.append({'name': cleaned_file_name,
                                        'url': decrypted_file_url,
                                        'size': f"{file_size_mb:.2f} MB",

                                        })

        # Store decrypted files for the current transfer in the dictionary
        decrypted_files_by_transfer[transfer] = decrypted_files
    end_time = time.time()
    taken_time = end_time - start_time
    print(f"time taken to receive files : {taken_time:.2f} seconds ")

    return render(request, 'received_documents.html', {'decrypted_files_by_transfer': decrypted_files_by_transfer})


@login_required
def sent_documents(request):
    # Filter transfers where the current user is the sender
    transfers = FileTransfer.objects.filter(sender=request.user).select_related('recipient').prefetch_related(
        'documents')

    # Dictionary to store the details of sent documents (no decryption needed)
    sent_files_by_transfer = {}

    for transfer in transfers:
        sent_files = []

        if transfer.documents.exists():
            for document in transfer.documents.all():
                # Get document name and remove the 'encrypted_' or 'decrypted_' prefixes
                cleaned_file_name = document.name.lstrip("encrypted_").lstrip("decrypted_")

                # Add cleaned name and other metadata to the list
                sent_files.append(
                    {'name': cleaned_file_name, 'recipient': transfer.recipient.email, 'title': transfer.title})

        # Store the list of sent files for the current transfer in the dictionary
        sent_files_by_transfer[transfer] = sent_files
    return render(request, 'sent_documents.html', {'sent_files_by_transfer': sent_files_by_transfer})
