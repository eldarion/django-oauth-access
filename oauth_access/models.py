from django.db import models


class LinkedToken(models.Model):
    
    key = models.CharField(max_length=50, unique=True)
    token = models.TextField()
