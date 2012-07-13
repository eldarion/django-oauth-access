from django.db import models


class LinkedToken(models.Model):
    
    service = models.CharField(max_length=50)
    key = models.CharField(max_length=50)
    token = models.TextField()
    
    class Meta:
        unique_together = [("service", "key")]
