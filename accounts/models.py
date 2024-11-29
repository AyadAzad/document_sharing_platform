from django.contrib.auth.models import AbstractBaseUser, BaseUserManager
from django.db import models
from django.conf import settings


class CustomUserManager(BaseUserManager):
    def create_user(self, email, first_name, last_name, role, password=None):
        if not email:
            raise ValueError("Users must have an email address")
        user = self.model(
            email=self.normalize_email(email),
            first_name=first_name,
            last_name=last_name,
            role=role
        )
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, first_name, last_name, role, password=None):
        user = self.create_user(email, first_name, last_name, role, password)
        user.is_staff = True
        user.save(using=self._db)
        return user


class CustomUser(AbstractBaseUser):
    ROLE_CHOICES = [
        ('faculty', 'Faculty'),
        ('chairperson', 'Chairperson'),
        ('exam_committee', 'Exam Committee'),
        ('quality_assurance', 'Quality Assurance'),
    ]

    email = models.EmailField(unique=True)
    first_name = models.CharField(max_length=50)
    last_name = models.CharField(max_length=50)
    role = models.CharField(max_length=20, choices=ROLE_CHOICES)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    public_key = models.BinaryField(default=None, null=True)
    objects = CustomUserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['first_name', 'last_name', 'role']

    def __str__(self):
        return self.email

    def has_perm(self, perm, obj=None):
        # Return True for now, customize as needed
        return True

    def has_module_perms(self, app_label):
        # Return True for now, customize as needed
        return True


class UserKeys(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="private_key")
    private_key = models.BinaryField(default=None, null=False)

    def __str__(self):
        return f"{self.private_key}"


class Documents(models.Model):
    uploader = models.ForeignKey(CustomUser, related_name='uploaded_document', on_delete=models.CASCADE)
    file = models.FileField(null=False, blank=False, upload_to='documents/')
    aes_key = models.BinaryField(default=None, null=False)
    note = models.TextField(blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    name = models.CharField(max_length=100)

    def __str__(self):
        return self.name


class FileTransfer(models.Model):
    sender = models.ForeignKey(CustomUser, related_name='sent_transfers', on_delete=models.CASCADE)
    recipient = models.ForeignKey(CustomUser, related_name='received_transfers', on_delete=models.CASCADE)
    documents = models.ManyToManyField(Documents, related_name='transfers', blank=False)
    title = models.CharField(max_length=100, blank=False, null=False)
    transferred_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.sender} to {self.recipient} at {self.transferred_at}"
