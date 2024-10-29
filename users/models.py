# models for Document
from django.db import models
from django.contrib.auth.models import User


class Document(models.Model):
    sender = models.ForeignKey(User, related_name='sent_documents', on_delete=models.CASCADE)
    receiver = models.ForeignKey(User, related_name='received_documents', on_delete=models.CASCADE)
    file = models.FileField(upload_to='documents/')
    note = models.TextField(blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Document from {self.sender} to {self.receiver}"
